package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
)

// TestPathIDStates checks the ADD-PATH state derived from a Peer Up: Path
// IDs flow from Send to Receive (RFC 7911 §5), a table may hold received or
// sent routes, and a Loc-RIB uses Path IDs whenever the capability is present
// (RFC 9069 §5.2).
func TestPathIDStates(t *testing.T) {
	open := func(ap byte) *bgp.OpenMessage {
		o := &bgp.OpenMessage{Capabilities: bgp.Capability{}}
		if ap != 0 {
			o.Capabilities[69] = []*bgp.CapabilityData{{Value: []byte{0x00, 0x01, 0x04, ap}}}
		}
		return o
	}
	tests := []struct {
		sent, recv byte
		locRIB     bool
		want       base.PathIDState
		listed     bool
	}{
		// Not listed; producer.pathIDState reads that as absent.
		{sent: 0, recv: 0},
		{sent: 3, recv: 3, want: base.PathIDPresent, listed: true},
		{sent: 3, recv: 0, want: base.PathIDAbsent, listed: true},
		{sent: 1, recv: 1, want: base.PathIDAbsent, listed: true},
		{sent: 1, recv: 2, want: base.PathIDUnknown, listed: true},
		{sent: 2, recv: 3, want: base.PathIDUnknown, listed: true},
		{sent: 2, recv: 1, want: base.PathIDUnknown, listed: true},
		{sent: 1, recv: 1, locRIB: true, want: base.PathIDPresent, listed: true},
		// RFC 7911 §4: values other than 1-3 are ignored, as if not listed.
		{sent: 7, recv: 7},
		{sent: 7, recv: 7, locRIB: true},
		{sent: 5, recv: 6},
		{sent: 6, recv: 5},
		{sent: 4, recv: 4},
		{sent: 7, recv: 3, want: base.PathIDAbsent, listed: true},
	}
	for _, tt := range tests {
		m := pathIDStates(open(tt.sent), open(tt.recv), tt.locRIB)
		got, ok := m[16] // AFI 1 SAFI 4
		if ok != tt.listed || got != tt.want {
			t.Errorf("sent %d, received %d, Loc-RIB %t: state %d (listed %t), want %d (listed %t)",
				tt.sent, tt.recv, tt.locRIB, got, ok, tt.want, tt.listed)
		}
	}
}
