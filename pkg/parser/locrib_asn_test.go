package parser

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// buildRouteMonitorMsg returns a BMP Route Monitoring message with a per-peer
// header of the given peer type and flags, carrying an UPDATE with the given
// AS_PATH and AS4_PATH (none if nil) values and NLRI 192.168.1.0/24.
func buildRouteMonitorMsg(peerType bmp.PeerType, flags byte, asPath, as4Path []byte) []byte {
	attrs := []byte{0x40, 0x01, 0x01, 0x00} // ORIGIN IGP
	attrs = append(append(attrs, 0x40, 0x02, byte(len(asPath))), asPath...)
	attrs = append(attrs, 0x40, 0x03, 0x04, 10, 0, 0, 1) // NEXT_HOP
	if as4Path != nil {
		attrs = append(append(attrs, 0xC0, 0x11, byte(len(as4Path))), as4Path...)
	}
	body := binary.BigEndian.AppendUint16([]byte{0, 0}, uint16(len(attrs)))
	body = append(append(body, attrs...), 0x18, 192, 168, 1)
	update := bytes.Repeat([]byte{0xFF}, 16)
	update = binary.BigEndian.AppendUint16(update, uint16(19+len(body)))
	update = append(append(update, 2), body...)

	pph := make([]byte, bmp.PerPeerHeaderLength)
	pph[0] = byte(peerType)
	pph[1] = flags
	msgLen := bmp.CommonHeaderLength + bmp.PerPeerHeaderLength + len(update)
	b := []byte{3}
	b = binary.BigEndian.AppendUint32(b, uint32(msgLen))
	b = append(b, bmp.RouteMonitorMsg)
	return append(append(b, pph...), update...)
}

// parseASPath runs msg through the parser and returns the decoded AS path,
// or nil if the message was rejected.
func parseASPath(t *testing.T, msg []byte) []uint32 {
	t.Helper()
	producerQueue := make(chan bmp.Message, 1)
	p := &parser{producerQueue: producerQueue, config: &Config{}}
	p.parsingWorker(msg)
	msgs := collectMessages(producerQueue)
	if len(msgs) == 0 {
		return nil
	}
	rm, ok := msgs[0].Payload.(*bmp.RouteMonitor)
	if !ok {
		t.Fatalf("payload type = %T, want *bmp.RouteMonitor", msgs[0].Payload)
	}
	return rm.Update.BaseAttributes.ASPath
}

// Loc-RIB Route Monitoring MUST use 4-byte ASNs (RFC 9069 Section 5.4.1), but
// FRR up to 10.5 sends the source peer's 2-octet AS_PATH with AS4_PATH.
func TestParsingWorkerLocRIBASPathWidth(t *testing.T) {
	tests := []struct {
		name    string
		asPath  []byte
		as4Path []byte
		want    []uint32 // nil: the message is rejected
	}{
		{
			// At 2 octets: AS_SEQUENCE [100, 23456] AS_SET [300].
			name:    "AS_PATH that also parses at 2 octets is 4-octet",
			asPath:  []byte{0x02, 0x02, 0x00, 0x64, 0x5B, 0xA0, 0x01, 0x01, 0x01, 0x2C},
			as4Path: []byte{0x02, 0x01, 0x00, 0x01, 0x11, 0x70}, // [70000]
			want:    []uint32{0x00645BA0, 0x0101012C},
		},
		{
			name:    "2-octet AS_PATH merged with AS4_PATH",
			asPath:  []byte{0x02, 0x02, 0xFD, 0xE9, 0x5B, 0xA0}, // [65001, AS_TRANS]
			as4Path: []byte{0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // [4200000001]
			want:    []uint32{65001, 4200000001},
		},
		{
			name:   "2-octet AS_PATH without AS4_PATH",
			asPath: []byte{0x02, 0x02, 0xFD, 0xE9, 0x0D, 0x1C}, // [65001, 3356]
			want:   []uint32{65001, 3356},
		},
		{
			name:   "AS_PATH that parses at neither width is rejected",
			asPath: []byte{0x02, 0x03, 0xFD, 0xE9, 0x0D, 0x1C},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseASPath(t, buildRouteMonitorMsg(bmp.PeerType3, 0, tt.asPath, tt.as4Path))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ASPath = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRateLimitedWarning(t *testing.T) {
	now := time.Unix(1000, 0)
	w := &rateLimitedWarning{}
	var logged []bool
	for _, step := range []time.Duration{0, time.Second, 30 * time.Second, 30 * time.Second, time.Second} {
		now = now.Add(step)
		logged = append(logged, w.warningfAt(now, "test warning"))
	}
	if want := []bool{true, false, false, true, false}; !reflect.DeepEqual(logged, want) {
		t.Errorf("logged = %v, want %v", logged, want)
	}
}

// Each parser, one per BMP connection, rate-limits its own warnings.
func TestParserFallbackWarningPerConnection(t *testing.T) {
	msg := buildRouteMonitorMsg(bmp.PeerType3, 0, []byte{0x02, 0x02, 0xFD, 0xE9, 0x0D, 0x1C}, nil) // 2-octet [65001, 3356]
	newParser := func(speakerIP string) *parser {
		return &parser{producerQueue: make(chan bmp.Message, 2), config: &Config{SpeakerIP: speakerIP}}
	}
	one, two := newParser("192.0.2.1"), newParser("192.0.2.2")
	one.parsingWorker(msg)
	one.parsingWorker(msg)
	two.parsingWorker(msg)
	for _, tt := range []struct {
		name       string
		p          *parser
		suppressed int
	}{{"first connection", one, 1}, {"second connection", two, 0}} {
		if tt.p.locRIB2OctetWarning.last.IsZero() || tt.p.locRIB2OctetWarning.suppressed != tt.suppressed {
			t.Errorf("%s: logged %v, suppressed %d; want logged, suppressed %d", tt.name,
				!tt.p.locRIB2OctetWarning.last.IsZero(), tt.p.locRIB2OctetWarning.suppressed, tt.suppressed)
		}
	}
}
