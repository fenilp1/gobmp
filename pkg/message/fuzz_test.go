package message

import (
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/internal/fuzzseed"
	"github.com/sbezverk/gobmp/pkg/parser"
)

// FuzzParseAndProduce runs a BMP message through the real parser and hands
// everything it emits (Route Monitoring, Stats, Peer Up/Down, RAW) to the
// producer with a no-op publisher. produce is called directly so that a
// producer panic fails the fuzzer; parser panics are covered by
// parser.FuzzParsingWorker.
func FuzzParseAndProduce(f *testing.F) {
	fuzzseed.Quiet(f)
	msgs := fuzzseed.BMPMessages()
	for _, m := range msgs {
		f.Add(m, false)
	}
	f.Add(msgs[0], true)
	f.Fuzz(func(t *testing.T, b []byte, raw bool) {
		queue := make(chan []byte)
		// Every BMP message is at least a common header long, so this never blocks.
		out := make(chan bmp.Message, len(b)/bmp.CommonHeaderLength+1)
		stop := make(chan struct{})
		done := make(chan struct{})
		prs := parser.NewParser(queue, out, stop, &parser.Config{EnableRawMode: raw, SpeakerIP: "192.0.2.9"})
		go func() {
			prs.Start()
			close(done)
		}()
		queue <- b
		queue <- nil // accepted only once b has been parsed
		close(stop)
		<-done
		close(out)

		p := NewProducer(&mockPublisher{}, false).(*producer)
		_ = p.SetConfig(&Config{AdminID: "fuzz"})
		p.speakerReadyOnce.Do(func() { close(p.speakerReady) })
		for msg := range out {
			p.produce(msg)
		}
	})
}

// fuzzAddPath marks every NLRI type as ADD-PATH capable.
var fuzzAddPath = func() map[int]bool {
	m := make(map[int]bool)
	for i := 0; i < 256; i++ {
		m[i] = true
	}
	return m
}()

// fuzzPeerHeader builds a per-peer header with the peer type and flags taken
// from ctl, or nil if that combination is invalid.
func fuzzPeerHeader(ctl byte) *bmp.PerPeerHeader {
	b := append([]byte(nil), fuzzseed.PerPeerHeader...)
	b[0] = ctl & 0x03
	b[1] = ctl & 0xf0
	ph, err := bmp.UnmarshalPerPeerHeader(b)
	if err != nil {
		return nil
	}
	return ph
}

// FuzzProduceRouteMonitor decodes a BGP UPDATE as a BMP Route Monitoring
// payload and runs it through the producer with a no-op publisher. It calls
// produceRouteMonitorMessage directly so a panic is not recovered.
// ctl bits: 0-1 peer type (bit 0 also selects splitAF), 2 AS4 hint,
// 3 ADD-PATH, 4-7 per-peer header flags.
func FuzzProduceRouteMonitor(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, u := range fuzzseed.UpdateBodies() {
		m := fuzzseed.Message(2, u)
		f.Add(m, byte(0x04))
		f.Add(m, byte(0x08))
	}
	f.Fuzz(func(t *testing.T, b []byte, ctl byte) {
		ph := fuzzPeerHeader(ctl)
		if ph == nil {
			return
		}
		rm, err := bmp.UnmarshalBMPRouteMonitorMessageWithAS4Hint(b, ctl&0x04 != 0)
		if err != nil {
			return
		}
		p := NewProducer(&mockPublisher{}, ctl&0x01 != 0).(*producer)
		if ctl&0x08 != 0 {
			p.tableProperties[ph.GetTableKey()] = PerTableProperties{addPathCapable: fuzzAddPath}
		}
		p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: rm})
	})
}

// FuzzProducePeerUp decodes a BMP Peer Up body and builds the PeerStateChange
// message from it, as the inline PeerUp path does.
func FuzzProducePeerUp(f *testing.F) {
	fuzzseed.Quiet(f)
	for _, o := range fuzzseed.OpenBodies() {
		f.Add(fuzzseed.PeerUpBody(o), byte(0))
	}
	f.Fuzz(func(t *testing.T, b []byte, ctl byte) {
		ph := fuzzPeerHeader(ctl)
		if ph == nil {
			return
		}
		pu, err := bmp.UnmarshalPeerUpMessage(b, ph.IsRemotePeerIPv6())
		if err != nil {
			return
		}
		msg := bmp.Message{PeerHeader: ph, Payload: pu}
		p := NewProducer(&mockPublisher{}, false).(*producer)
		m, err := p.producePeerMessage(peerUP, msg, bmp.IdentityFromPeerUp(msg))
		if err != nil {
			return
		}
		if _, err := json.Marshal(m); err != nil {
			t.Fatalf("marshal PeerStateChange: %v", err)
		}
	})
}
