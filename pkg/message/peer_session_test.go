package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// sessionTest drives one producer through Peer Up, Route Monitoring and Peer
// Down messages.
type sessionTest struct {
	t   *testing.T
	pub *recordingPublisher
	p   *producer
}

func newSessionTest(t *testing.T) *sessionTest {
	pub := &recordingPublisher{}
	return &sessionTest{t: t, pub: pub, p: NewProducer(pub, false).(*producer)}
}

// peerUp sends a Peer Up for ph whose sent (monitored router's) and received
// (peer's) OPENs carry the capabilities given.
func (s *sessionTest) peerUp(ph *bmp.PerPeerHeader, sent, recv bgp.Capability) {
	s.t.Helper()
	peerUp := buildPeerUpMessage(s.t, "192.168.1.1")
	peerUp.SentOpen.Capabilities = sent
	peerUp.ReceivedOpen.Capabilities = recv
	s.p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
}

func (s *sessionTest) peerDown(ph *bmp.PerPeerHeader) {
	s.p.producingWorker(bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}, SpeakerIP: "10.2.1.3"})
}

// routes sends a Route Monitoring of update for ph and returns the
// UnicastPrefix and L3VPNPrefix messages it publishes.
func (s *sessionTest) routes(ph *bmp.PerPeerHeader, update *bgp.Update) []UnicastPrefix {
	s.t.Helper()
	n := len(s.pub.msgs)
	s.p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}})
	var got []UnicastPrefix
	for _, m := range s.pub.msgs[n:] {
		if m.msgType != bmp.UnicastPrefixMsg && m.msgType != bmp.L3VPNMsg {
			continue
		}
		var u UnicastPrefix
		if err := json.Unmarshal(m.payload, &u); err != nil {
			s.t.Fatalf("json.Unmarshal() error: %v", err)
		}
		got = append(got, u)
	}
	return got
}

// wantRoute checks that routes is one route for prefix/length with Path ID
// pathID and, when labels is not nil, those labels.
func wantRoute(t *testing.T, what string, routes []UnicastPrefix, prefix string, length int32, pathID int32, labels []uint32) {
	t.Helper()
	if len(routes) != 1 {
		t.Errorf("%s: published %d routes, want 1: %+v", what, len(routes), routes)
		return
	}
	u := routes[0]
	if u.Prefix != prefix || u.PrefixLen != length || u.PathID != pathID {
		t.Errorf("%s: published %s/%d path %d, want %s/%d path %d", what, u.Prefix, u.PrefixLen, u.PathID, prefix, length, pathID)
	}
	if labels != nil && !reflect.DeepEqual(u.Labels, labels) {
		t.Errorf("%s: labels %v, want %v", what, u.Labels, labels)
	}
}

func wantNoRoute(t *testing.T, what string, routes []UnicastPrefix) {
	t.Helper()
	if len(routes) != 0 {
		t.Errorf("%s: published %+v, want nothing", what, routes)
	}
}

func catBytes(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

var (
	sessionV4NH = []byte{192, 0, 2, 1}
	sessionV6NH = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	// A Path ID that makes the NLRI malformed when read without Path IDs: its
	// last octet reads as a 255-bit prefix length.
	sessionPathID = []byte{0x00, 0x00, 0x00, 0xff}
	sessionV4     = []byte{0x18, 0x0a, 0x01, 0x02} // 10.1.2.0/24
)

// TestTwoSessionsToOneNeighbour checks that two sessions to one neighbour BGP
// ID, here over IPv4 and IPv6 transport, keep their own ADD-PATH (RFC 7911
// §3) and Multiple Labels (RFC 8277 §2.1) state, and that the Peer Down of
// one leaves the other's (RFC 7854 §4.2, §4.9).
func TestTwoSessionsToOneNeighbour(t *testing.T) {
	s := newSessionTest(t)
	ph4 := globalHeader("192.0.2.1", "10.0.0.1")
	ph6 := globalHeader("2001:db8::1", "10.0.0.1")

	// IPv4 session: ADD-PATH for SAFI 1 and 4, Multiple Labels for SAFI 4.
	v4Caps := addPathTestCaps(3, [2]byte{1, 1}, [2]byte{1, 4})
	v4Caps[8] = []*bgp.CapabilityData{{Value: []byte{0x00, 0x01, 0x04, 0x02}}}
	s.peerUp(ph4, v4Caps, v4Caps)
	// IPv6 session: neither.
	s.peerUp(ph6, bgp.Capability{}, bgp.Capability{})

	// 10.1.2.0/24 with a Path ID: read without Path IDs it is 0.0.0.0/0
	// three times, 24.0.0.0/7 and 1.2.0.0/10.
	v4PathID := catBytes([]byte{0, 0, 0, 7}, sessionV4)
	// Label 1000 S=0 then 0x0a0001: with the Multiple Labels Capability two
	// labels and 1.0.0.0/8, without it one label and 10.0.1.1/32.
	v4LabelLike := []byte{0x38, 0x00, 0x3e, 0x80, 0x0a, 0x00, 0x01, 0x01}
	v6LabelLike := catBytes([]byte{0x58, 0x00, 0x3e, 0x80}, []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00})
	checkV4 := func(when string) {
		t.Helper()
		wantRoute(t, when+": IPv4 SAFI 1", s.routes(ph4, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, v4PathID))), "10.1.2.0", 24, 7, nil)
		wantRoute(t, when+": IPv4 NLRI field", s.routes(ph4, plainTestUpdate(t, nil, v4PathID)), "10.1.2.0", 24, 7, nil)
		wantRoute(t, when+": IPv4 SAFI 4", s.routes(ph4, testUpdate(t, luTestAttr(0x0e, 1, sessionV4NH, catBytes([]byte{0, 0, 0, 7}, v4LabelLike)))), "1.0.0.0", 8, 7, []uint32{1000, 40960})
	}
	checkV4("both up")
	wantRoute(t, "IPv6 SAFI 1", s.routes(ph6, testUpdate(t, mpTestAttr(0x0e, 2, 1, sessionV6NH, []byte{0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}))), "2001:db8:1::", 64, 0, nil)
	wantRoute(t, "IPv6 SAFI 4", s.routes(ph6, testUpdate(t, luTestAttr(0x0e, 2, sessionV6NH, v6LabelLike))), "2001:db8:1::", 64, 0, []uint32{1000})

	s.peerDown(ph6)
	if ids, ml := s.p.nlriState(ph6, bgp.NLRIMessageType(2, 1)); ids != base.PathIDUnknown || ml != base.MultiLabelUnknown {
		t.Errorf("IPv6 session after its Peer Down: state %d, %d, want unknown", ids, ml)
	}
	checkV4("IPv6 session down")

	s.peerDown(ph4)
	if ids, _ := s.p.nlriState(ph4, bgp.NLRIMessageType(1, 1)); ids != base.PathIDUnknown {
		t.Errorf("IPv4 session after its Peer Down: state %d, want unknown", ids)
	}
}

// TestPathIDDirection checks that Path IDs are expected only on routes from
// a speaker that advertised ADD-PATH Send to one that advertised Receive
// (RFC 7911 §5). The Peer Up sent OPEN is the monitored router's and the
// received OPEN the peer's (RFC 7854 §4.10); Adj-RIB-In holds routes from the
// peer and Adj-RIB-Out (O flag) routes to it (RFC 8671 §4). A Loc-RIB uses
// Path IDs whenever the capability is present (RFC 9069 §5.2). The expected
// setting is tried first, so a field with Path IDs is read right in one
// direction only; a field encoded the other way is read by the retry.
func TestPathIDDirection(t *testing.T) {
	adjIn := globalHeader("192.0.2.1", "10.0.0.1")
	adjOut := globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x10) // O flag
	locRIB := makePeerHeader(t, bmp.PeerType3, 0x00)
	if adjIn.SessionKey() != adjOut.SessionKey() {
		t.Fatalf("Adj-RIB-In and Adj-RIB-Out session keys %q and %q differ", adjIn.SessionKey(), adjOut.SessionKey())
	}

	withID := catBytes(sessionPathID, sessionV4)
	tests := []struct {
		name        string
		peerUp      *bmp.PerPeerHeader
		sent, recv  byte // ADD-PATH Send/Receive for AFI 1 SAFI 1, 0 for none
		ph          *bmp.PerPeerHeader
		wantPathIDs bool
	}{
		{name: "router Send, peer Receive: Adj-RIB-Out", peerUp: adjIn, sent: 2, recv: 1, ph: adjOut, wantPathIDs: true},
		{name: "router Send, peer Receive: Adj-RIB-In", peerUp: adjIn, sent: 2, recv: 1, ph: adjIn},
		{name: "router Receive, peer Send: Adj-RIB-In", peerUp: adjIn, sent: 1, recv: 2, ph: adjIn, wantPathIDs: true},
		{name: "router Receive, peer Send: Adj-RIB-Out", peerUp: adjIn, sent: 1, recv: 2, ph: adjOut},
		{name: "Loc-RIB, Receive only", peerUp: locRIB, sent: 1, recv: 1, ph: locRIB, wantPathIDs: true},
		{name: "Loc-RIB, no ADD-PATH", peerUp: locRIB, ph: locRIB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, field := range []string{"MP_REACH_NLRI", "NLRI field"} {
				update := func(nlri []byte) *bgp.Update {
					if field == "NLRI field" {
						return plainTestUpdate(t, nil, nlri)
					}
					return testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, nlri))
				}
				s := newSessionTest(t)
				var none [][2]byte
				sentAS, recvAS := none, none
				if tt.sent != 0 {
					sentAS = [][2]byte{{1, 1}}
				}
				if tt.recv != 0 {
					recvAS = [][2]byte{{1, 1}}
				}
				s.peerUp(tt.peerUp, addPathTestCaps(tt.sent, sentAS...), addPathTestCaps(tt.recv, recvAS...))
				if tt.wantPathIDs {
					wantRoute(t, field+" with Path ID", s.routes(tt.ph, update(withID)), "10.1.2.0", 24, 0xff, nil)
				}
				wantRoute(t, field+" without Path ID", s.routes(tt.ph, update(sessionV4)), "10.1.2.0", 24, 0, nil)
			}
		})
	}
}

// TestMalformedNLRIPathIDRetry checks the retry with the Path ID flag
// flipped, whether the Peer Up says ADD-PATH is off or no Peer Up was seen:
// it reads a field encoded with Path IDs, while a field malformed both ways
// is dropped (RFC 7606 §5.3).
func TestMalformedNLRIPathIDRetry(t *testing.T) {
	// Without Path IDs: 0.62.129.48/32, 0.0.0.0/0, then a 62-bit prefix.
	// With Path IDs: Path ID 0x20003e81 and a 48-bit prefix. Both readings
	// are malformed for IPv4 (RFC 4271 §4.3).
	repro := []byte{0x20, 0x00, 0x3e, 0x81, 0x30, 0x00, 0x3e, 0x81, 0x0a, 0x00, 0x00}
	// The same for VPN-IPv4: with Path IDs, Path ID 0x20003e81, label 1000,
	// RD 100:1 and 10.0.0.0/24; without, a 32-bit Length too short for the
	// label and RD.
	vpnRepro := []byte{0x20, 0x00, 0x3e, 0x81, 0x70, 0x00, 0x3e, 0x81, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 0x0a, 0x00, 0x00}
	// 10.1.2.0/24 with Path ID 255, malformed only without Path IDs.
	withID := catBytes(sessionPathID, sessionV4)
	tests := []struct {
		name   string
		update func(t *testing.T) *bgp.Update
		// Path ID of the one route published, 0 for none.
		pathID int32
	}{
		{name: "SAFI 1", update: func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, repro)) }},
		{name: "SAFI 1 withdraw", update: func(t *testing.T) *bgp.Update { return testUpdate(t, mpTestAttr(0x0f, 1, 1, nil, repro)) }},
		{name: "NLRI field", update: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, repro) }},
		{name: "SAFI 1 Path ID", update: func(t *testing.T) *bgp.Update {
			return testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, withID))
		}, pathID: 0xff},
		{name: "NLRI field Path ID", update: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, withID) }, pathID: 0xff},
		{name: "L3VPN", update: func(t *testing.T) *bgp.Update {
			return testUpdate(t, mpTestAttr(0x0e, 1, 128, sessionV4NH, vpnRepro), testRT)
		}, pathID: 0x20003e81},
	}
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	for _, tt := range tests {
		for _, peerUp := range []bool{true, false} {
			name := tt.name + ", no Peer Up"
			if peerUp {
				name = tt.name + ", ADD-PATH off"
			}
			t.Run(name, func(t *testing.T) {
				s := newSessionTest(t)
				if peerUp {
					s.peerUp(ph, bgp.Capability{}, bgp.Capability{})
				}
				routes := s.routes(ph, tt.update(t))
				if tt.pathID == 0 {
					wantNoRoute(t, tt.name, routes)
				} else if len(routes) != 1 || routes[0].PathID != tt.pathID {
					t.Errorf("published %+v, want one route with Path ID %#x", routes, tt.pathID)
				}
			})
		}
	}
}

// TestLocRIBEmulatedPeers checks that a Loc-RIB conveyed by one emulated
// peer per address family, which share the per-peer header (RFC 9069
// §6.1.1), keeps the ADD-PATH state of each Peer Up and the Information TLVs
// of all as an ordered set (RFC 9069 §5.2.1). A Peer Down cannot tell which
// emulated peer it ends, so the state lasts until the last one's.
func TestLocRIBEmulatedPeers(t *testing.T) {
	s := newSessionTest(t)
	ph := makePeerHeader(t, bmp.PeerType3, 0x00)
	peerUp := func(afi byte, names ...string) {
		t.Helper()
		peerUp := buildPeerUpMessage(t, "192.168.1.1")
		// Each OPEN lists its address family (RFC 9069 §6.1.1).
		peerUp.SentOpen.Capabilities = withMP(addPathTestCaps(1, [2]byte{afi, 1}), [2]byte{afi, 1})
		peerUp.ReceivedOpen.Capabilities = withMP(addPathTestCaps(1, [2]byte{afi, 1}), [2]byte{afi, 1})
		for _, n := range names {
			peerUp.Information = append(peerUp.Information, bmp.InformationalTLV{InformationType: bmp.PeerUpTLVVRFTableName, Information: []byte(n)})
		}
		s.p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
	}
	peerUp(1, "global", "view-A")
	peerUp(2, "global", "view-B")
	for _, nlriType := range []int{bgp.NLRIMessageType(1, 1), bgp.NLRIMessageType(2, 1)} {
		if ids, _ := s.p.nlriState(ph, nlriType); ids != base.PathIDExpectPresent {
			t.Errorf("NLRI type %d: state %d, want present", nlriType, ids)
		}
	}
	if tn := s.p.GetTableName(ph); tn != "globalview-Aview-B" {
		t.Errorf("GetTableName() = %q, want the ordered set globalview-Aview-B", tn)
	}

	// IPv4 routes with Path IDs; read without them they would be five
	// bogus routes.
	v4PathID := catBytes([]byte{0, 0, 0, 7}, sessionV4)
	s.peerDown(ph)
	wantRoute(t, "IPv4 after one Peer Down", s.routes(ph, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, v4PathID))), "10.1.2.0", 24, 7, nil)
	if tn := s.p.GetTableName(ph); tn != "globalview-Aview-B" {
		t.Errorf("GetTableName() after one Peer Down = %q, want globalview-Aview-B", tn)
	}
	s.peerDown(ph)
	if ids, _ := s.p.nlriState(ph, bgp.NLRIMessageType(1, 1)); ids != base.PathIDUnknown {
		t.Errorf("after the last Peer Down: state %d, want unknown", ids)
	}
}

// TestOneWayAddPath checks a session with ADD-PATH negotiated in one
// direction only: the peer advertised Send and the router Receive, so the
// routes the peer sends, in the router's Adj-RIB-In, carry Path IDs (RFC 7911
// §5). Read without them, Path ID 7 and 10.0.1.0/24 parse as five routes
// (0.0.0.0/0 three times, then a /7 and a /10), which is what was published
// when the Path ID setting required Send/Receive in both OPENs.
func TestOneWayAddPath(t *testing.T) {
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	nlri := []byte{0x00, 0x00, 0x00, 0x07, 0x18, 0x0a, 0x00, 0x01} // Path ID 7, 10.0.1.0/24
	for _, field := range []string{"MP_REACH_NLRI", "NLRI field"} {
		s := newSessionTest(t)
		s.peerUp(ph, addPathTestCaps(1, [2]byte{1, 1}), addPathTestCaps(2, [2]byte{1, 1}))
		update := plainTestUpdate(t, nil, nlri)
		if field == "MP_REACH_NLRI" {
			update = testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, nlri))
		}
		wantRoute(t, field, s.routes(ph, update), "10.0.1.0", 24, 7, nil)
	}
}

// withMP adds a Multiprotocol Extensions capability (code 1, RFC 4760 §8)
// for each AFI/SAFI pair in afiSAFI to c and returns c.
func withMP(c bgp.Capability, afiSAFI ...[2]byte) bgp.Capability {
	for _, as := range afiSAFI {
		c[1] = append(c[1], &bgp.CapabilityData{Value: []byte{0x00, as[0], 0x00, as[1]}})
	}
	return c
}

// TestLocRIBBounce checks that a Loc-RIB emulated peer bounced with new
// capabilities (RFC 9069 §6.1.3) gets them for the address families its
// OPEN lists (RFC 9069 §6.1.1), while the others keep their state. An OPEN
// with no Multiprotocol capability lists IPv4 unicast only (RFC 4760 §8).
func TestLocRIBBounce(t *testing.T) {
	v4, v6 := [2]byte{1, 1}, [2]byte{2, 1}
	for _, explicitMP := range []bool{true, false} {
		name := "explicit Multiprotocol capability"
		if !explicitMP {
			name = "no Multiprotocol capability"
		}
		t.Run(name, func(t *testing.T) {
			s := newSessionTest(t)
			ph := makePeerHeader(t, bmp.PeerType3, 0x00)
			caps := func(ap byte, as [2]byte) bgp.Capability {
				c := bgp.Capability{}
				if ap != 0 {
					c = addPathTestCaps(ap, as)
				}
				if explicitMP || as != v4 {
					c = withMP(c, as)
				}
				return c
			}
			s.peerUp(ph, caps(3, v4), caps(3, v4)) // A: IPv4 with ADD-PATH
			s.peerUp(ph, caps(3, v6), caps(3, v6)) // B: IPv6 with ADD-PATH
			s.peerDown(ph)
			s.peerUp(ph, caps(0, v4), caps(0, v4)) // A': IPv4 without ADD-PATH
			wantRoute(t, "IPv4 after the bounce", s.routes(ph, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, sessionV4))), "10.1.2.0", 24, 0, nil)
			if ids, _ := s.p.nlriState(ph, bgp.NLRIMessageType(2, 1)); ids != base.PathIDExpectPresent {
				t.Errorf("IPv6 state %d, want present: A' does not list IPv6", ids)
			}
		})
	}
}

// TestLocRIBDuplicatePeerUp checks that a repeated Peer Up, counted as one
// more emulated peer, does not keep stale ADD-PATH state once the emulated
// peer comes back without ADD-PATH.
func TestLocRIBDuplicatePeerUp(t *testing.T) {
	s := newSessionTest(t)
	ph := makePeerHeader(t, bmp.PeerType3, 0x00)
	s.peerUp(ph, addPathTestCaps(3, [2]byte{1, 1}), addPathTestCaps(3, [2]byte{1, 1}))
	s.peerUp(ph, addPathTestCaps(3, [2]byte{1, 1}), addPathTestCaps(3, [2]byte{1, 1}))
	s.peerDown(ph)
	s.peerUp(ph, bgp.Capability{}, bgp.Capability{})
	wantRoute(t, "IPv4 without ADD-PATH", s.routes(ph, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, sessionV4))), "10.1.2.0", 24, 0, nil)
}
