package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestSessionPathIDs checks the ADD-PATH state derived from a Peer Up for
// each RIB. Path IDs flow from a speaker that advertised Send to one that
// advertised Receive (RFC 7911 §5); the sent OPEN is the monitored router's
// and the received OPEN the peer's (RFC 7854 §4.10). Adj-RIB-In holds routes
// from the peer to the router, Adj-RIB-Out (O flag) routes from the router to
// the peer (RFC 8671 §4), and a Loc-RIB uses Path IDs whenever the capability
// is present (RFC 9069 §5.2).
func TestSessionPathIDs(t *testing.T) {
	open := func(ap byte) *bgp.OpenMessage {
		o := &bgp.OpenMessage{Capabilities: bgp.Capability{}}
		if ap != 0 {
			o.Capabilities[69] = []*bgp.CapabilityData{{Value: []byte{0x00, 0x01, 0x04, ap}}}
		}
		return o
	}
	const (
		in = iota
		out
		locRIB
	)
	header := func(t *testing.T, rib int) *bmp.PerPeerHeader {
		switch rib {
		case out:
			return makePeerHeader(t, bmp.PeerType0, 0x10) // O flag
		case locRIB:
			return makePeerHeader(t, bmp.PeerType3, 0x00)
		}
		return makePeerHeader(t, bmp.PeerType0, 0x00)
	}
	P, A := base.PathIDPresent, base.PathIDAbsent
	tests := []struct {
		sent, recv byte
		// Expected state for Adj-RIB-In, Adj-RIB-Out and Loc-RIB.
		want [3]base.PathIDState
	}{
		{sent: 0, recv: 0, want: [3]base.PathIDState{A, A, A}},
		{sent: 3, recv: 3, want: [3]base.PathIDState{P, P, P}},
		{sent: 3, recv: 0, want: [3]base.PathIDState{A, A, P}},
		{sent: 0, recv: 3, want: [3]base.PathIDState{A, A, P}},
		{sent: 1, recv: 1, want: [3]base.PathIDState{A, A, P}},
		{sent: 2, recv: 2, want: [3]base.PathIDState{A, A, P}},
		// Router Receive, peer Send: Path IDs on received routes only.
		{sent: 1, recv: 2, want: [3]base.PathIDState{P, A, P}},
		// Router Send, peer Receive: Path IDs on sent routes only.
		{sent: 2, recv: 1, want: [3]base.PathIDState{A, P, P}},
		{sent: 2, recv: 3, want: [3]base.PathIDState{A, P, P}},
		{sent: 3, recv: 2, want: [3]base.PathIDState{P, A, P}},
		{sent: 1, recv: 3, want: [3]base.PathIDState{P, A, P}},
		{sent: 3, recv: 1, want: [3]base.PathIDState{A, P, P}},
		// RFC 7911 §4: values other than 1-3 are ignored, as if not listed.
		{sent: 7, recv: 7, want: [3]base.PathIDState{A, A, A}},
		{sent: 5, recv: 6, want: [3]base.PathIDState{A, A, A}},
		{sent: 4, recv: 4, want: [3]base.PathIDState{A, A, A}},
		{sent: 7, recv: 3, want: [3]base.PathIDState{A, A, P}},
	}
	for _, tt := range tests {
		s := newSessionState(&bmp.PeerUpMessage{SentOpen: open(tt.sent), ReceivedOpen: open(tt.recv)})
		for rib, name := range []string{"Adj-RIB-In", "Adj-RIB-Out", "Loc-RIB"} {
			if got := s.pathIDs(header(t, rib), bgp.NLRIMessageType(1, 4)); got != tt.want[rib] {
				t.Errorf("sent %d, received %d, %s: state %d, want %d", tt.sent, tt.recv, name, got, tt.want[rib])
			}
		}
	}
}
