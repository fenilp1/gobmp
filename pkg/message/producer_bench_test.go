package message

import (
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// pipelineUpdate builds a BGP UPDATE (RFC 4271 §4.3) with the Withdrawn
// Routes and NLRI fields given, ORIGIN, AS_PATH and, with NLRI, NEXT_HOP.
func pipelineUpdate(tb testing.TB, withdrawn, nlri []byte) *bgp.Update {
	tb.Helper()
	attrs := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // AS_PATH AS_SEQUENCE 65000
	}
	if len(nlri) != 0 {
		attrs = append(attrs, 0x40, 0x03, 0x04, 192, 0, 2, 1) // NEXT_HOP
	}
	b := []byte{byte(len(withdrawn) >> 8), byte(len(withdrawn))}
	b = append(b, withdrawn...)
	b = append(b, byte(len(attrs)>>8), byte(len(attrs)))
	b = append(b, attrs...)
	b = append(b, nlri...)
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(b, true)
	if err != nil {
		tb.Fatalf("UnmarshalBGPUpdateWithAS4Hint() error: %v", err)
	}
	return update
}

// pipelinePrefixes returns n /24 IPv4 NLRI starting at 10.base.0.0/24.
func pipelinePrefixes(base, n int) []byte {
	b := make([]byte, 0, 4*n)
	for i := 0; i < n; i++ {
		v := base<<16 + i<<8
		b = append(b, 24, 10, byte(v>>16), byte(v>>8))
	}
	return b
}

// pipelinePeerUp returns a Peer Up message for ph.
func pipelinePeerUp(ph *bmp.PerPeerHeader) bmp.Message {
	local := make([]byte, 16)
	copy(local[10:], []byte{0xff, 0xff, 192, 168, 1, 1})
	return bmp.Message{
		PeerHeader: ph,
		Payload: &bmp.PeerUpMessage{
			LocalAddress: local,
			LocalPort:    179,
			RemotePort:   45678,
			SentOpen:     &bgp.OpenMessage{Version: 4, MyAS: 65000, HoldTime: 90, BGPID: []byte{10, 0, 0, 1}},
			ReceivedOpen: &bgp.OpenMessage{Version: 4, MyAS: 65001, HoldTime: 90, BGPID: []byte{10, 0, 0, 2}},
		},
		SpeakerIP: "10.2.1.3",
	}
}

// countingPublisher counts the messages published and closes done once it
// has counted want.
type countingPublisher struct {
	n    atomic.Int64
	want int64
	done chan struct{}
}

func (c *countingPublisher) PublishMessage(int, []byte, []byte) error {
	if c.n.Add(1) == c.want {
		close(c.done)
	}
	return nil
}

func (c *countingPublisher) Stop() {}

// BenchmarkProducerRouteMonitor feeds b.N Route Monitoring messages of
// prefixes IPv4 prefixes each, after a Peer Up, through Producer and waits
// until all they produce is published.
func BenchmarkProducerRouteMonitor(b *testing.B) {
	for _, prefixes := range []int{1, 64} {
		b.Run(fmt.Sprintf("prefixes=%d", prefixes), func(b *testing.B) {
			ph := globalHeader("192.0.2.1", "10.0.0.1")
			rm := bmp.Message{
				PeerHeader: ph,
				Payload:    &bmp.RouteMonitor{Update: pipelineUpdate(b, nil, pipelinePrefixes(1, prefixes))},
				SpeakerIP:  "10.2.1.3",
			}
			pub := &countingPublisher{want: 1 + int64(b.N)*int64(prefixes), done: make(chan struct{})}
			p := NewProducer(pub, true).(*producer)
			queue := make(chan bmp.Message)
			stop := make(chan struct{})
			returned := make(chan struct{})
			b.ReportAllocs()
			b.ResetTimer()
			go func() {
				p.Producer(queue, stop)
				close(returned)
			}()
			queue <- pipelinePeerUp(ph)
			for i := 0; i < b.N; i++ {
				queue <- rm
			}
			<-pub.done
			b.StopTimer()
			close(stop)
			<-returned
		})
	}
}
