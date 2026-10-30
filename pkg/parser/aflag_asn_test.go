package parser

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// FRR up to 10.5 sends the 2-octet AS_PATH and AS4_PATH of a 2-octet peer
// with the per-peer header A flag 0, which means a 4-byte AS_PATH (RFC 7854
// Section 4.2).
func TestParsingWorkerAFlagASPathWidth(t *testing.T) {
	as2Trans := []byte{0x02, 0x02, 0xFD, 0xE9, 0x5B, 0xA0}              // 2-octet [65001, AS_TRANS]
	as2 := []byte{0x02, 0x02, 0xFD, 0xE9, 0x0D, 0x1C}                   // 2-octet [65001, 3356]
	as4 := []byte{0x02, 0x02, 0, 0, 0xFD, 0xE9, 0xFA, 0x56, 0xEA, 0x01} // 4-octet [65001, 4200000001]
	as4Only := []byte{0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}               // 4-octet [4200000001], not 2-octet
	as4Path := []byte{0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}               // AS4_PATH [4200000001]
	tests := []struct {
		name    string
		flags   byte
		asPath  []byte
		as4Path []byte
		want    []uint32 // nil: the message is rejected
	}{
		{"A=0, 2-octet AS_PATH merged with AS4_PATH", 0x00, as2Trans, as4Path, []uint32{65001, 4200000001}},
		{"A=0, 2-octet AS_PATH", 0x00, as2, nil, []uint32{65001, 3356}},
		{"A=0 post-policy Adj-RIB-Out, 2-octet AS_PATH", 0x50, as2, nil, []uint32{65001, 3356}},
		{"A=0, 4-octet AS_PATH", 0x00, as4, nil, []uint32{65001, 4200000001}},
		{"A=1, 2-octet AS_PATH merged with AS4_PATH", 0x20, as2Trans, as4Path, []uint32{65001, 4200000001}},
		// The A flag 1 is not overridden.
		{"A=1, 4-octet AS_PATH rejected", 0x20, as4Only, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseASPath(t, buildRouteMonitorMsg(bmp.PeerType0, tt.flags, tt.asPath, tt.as4Path))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ASPath = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParserAFlagFallbackWarning(t *testing.T) {
	p := &parser{producerQueue: make(chan bmp.Message, 1), config: &Config{SpeakerIP: "192.0.2.1"}}
	p.parsingWorker(buildRouteMonitorMsg(bmp.PeerType0, 0x00, []byte{0x02, 0x02, 0xFD, 0xE9, 0x0D, 0x1C}, nil))
	if p.aFlag2OctetWarning.last.IsZero() || !p.locRIB2OctetWarning.last.IsZero() {
		t.Errorf("A flag warning logged %v, Loc-RIB warning logged %v; want true, false",
			!p.aFlag2OctetWarning.last.IsZero(), !p.locRIB2OctetWarning.last.IsZero())
	}
}
