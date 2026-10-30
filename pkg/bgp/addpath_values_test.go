package bgp

import (
	"reflect"
	"testing"
)

// TestAddPathSendReceiveValues checks RFC 7911 §4: Send/Receive values other
// than 1 (receive), 2 (send) and 3 (both) are ignored, so the AFI/SAFI counts
// as not listed, while valid values give the same AddPathCapability as before.
func TestAddPathSendReceiveValues(t *testing.T) {
	key := NLRIMessageType(1, 4)
	for sr := 0; sr <= 7; sr++ {
		o := &OpenMessage{Capabilities: Capability{
			69: []*CapabilityData{{Value: []byte{0x00, 0x01, 0x04, byte(sr)}}},
		}}
		valid := sr >= 1 && sr <= 3
		got, ok := o.AddPathSendReceive()[key]
		if ok != valid || (valid && got != uint8(sr)) {
			t.Errorf("Send/Receive %d: AddPathSendReceive = %d (listed %t), want listed %t", sr, got, ok, valid)
		}
		capable, ok := o.AddPathCapability()[key]
		if ok != valid || capable != (sr == 3) {
			t.Errorf("Send/Receive %d: AddPathCapability = %t (listed %t), want %t (listed %t)", sr, capable, ok, sr == 3, valid)
		}
	}
	// An ignored tuple does not override an earlier valid one.
	o := &OpenMessage{Capabilities: Capability{
		69: []*CapabilityData{{Value: []byte{0x00, 0x01, 0x04, 0x03, 0x00, 0x01, 0x04, 0x07}}},
	}}
	if got := o.AddPathSendReceive()[key]; got != 3 {
		t.Errorf("AddPathSendReceive = %d after an ignored tuple, want 3", got)
	}
}

// TestMultiprotocolFamilies checks the address families an OPEN lists in its
// Multiprotocol Extensions capabilities, IPv4 unicast alone when it has none
// (RFC 4760 §8).
func TestMultiprotocolFamilies(t *testing.T) {
	tests := []struct {
		name string
		caps Capability
		want map[int]bool
	}{
		{name: "none", caps: Capability{}, want: map[int]bool{NLRIMessageType(1, 1): true}},
		{name: "IPv6 unicast and VPNv4", caps: Capability{1: {{Value: []byte{0, 2, 0, 1}}, {Value: []byte{0, 1, 0, 128}}}},
			want: map[int]bool{NLRIMessageType(2, 1): true, NLRIMessageType(1, 128): true}},
		{name: "malformed only", caps: Capability{1: {{Value: []byte{0, 2, 0}}}}, want: map[int]bool{}},
	}
	for _, tt := range tests {
		got := (&OpenMessage{Capabilities: tt.caps}).MultiprotocolFamilies()
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: MultiprotocolFamilies() = %v, want %v", tt.name, got, tt.want)
		}
	}
}
