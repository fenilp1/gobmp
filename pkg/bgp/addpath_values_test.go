package bgp

import "testing"

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
