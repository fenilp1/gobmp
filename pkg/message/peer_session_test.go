package message

import (
	"encoding/json"
	"errors"
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
		wantRoute(t, when+": IPv4 SAFI 1", s.routes(ph4, ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, v4PathID))), "10.1.2.0", 24, 7, nil)
		wantRoute(t, when+": IPv4 NLRI field", s.routes(ph4, plainTestUpdate(t, nil, v4PathID)), "10.1.2.0", 24, 7, nil)
		wantRoute(t, when+": IPv4 SAFI 4", s.routes(ph4, ctTestUpdate(t, luTestAttr(0x0e, 1, sessionV4NH, catBytes([]byte{0, 0, 0, 7}, v4LabelLike)))), "1.0.0.0", 8, 7, []uint32{1000, 40960})
	}
	checkV4("both up")
	wantRoute(t, "IPv6 SAFI 1", s.routes(ph6, ctTestUpdate(t, mpTestAttr(0x0e, 2, 1, sessionV6NH, []byte{0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}))), "2001:db8:1::", 64, 0, nil)
	wantRoute(t, "IPv6 SAFI 4", s.routes(ph6, ctTestUpdate(t, luTestAttr(0x0e, 2, sessionV6NH, v6LabelLike))), "2001:db8:1::", 64, 0, []uint32{1000})

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
// Path IDs whenever the capability is present (RFC 9069 §5.2). These views
// fix the encoding (pre-policy Adj-RIB-In, post-policy Adj-RIB-Out, RFC 8671
// §5.1), so NLRI are parsed once, without the Path ID flip.
func TestPathIDDirection(t *testing.T) {
	adjIn := globalHeader("192.0.2.1", "10.0.0.1")
	adjOut := globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x50) // O and L flags
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
					return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, nlri))
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
					wantNoRoute(t, field+" without Path ID", s.routes(tt.ph, update(sessionV4)))
				} else {
					wantRoute(t, field+" without Path ID", s.routes(tt.ph, update(sessionV4)), "10.1.2.0", 24, 0, nil)
					wantNoRoute(t, field+" with Path ID", s.routes(tt.ph, update(withID)))
				}
			}
		})
	}
}

// TestMalformedNLRIWithKnownPathIDState checks that a malformed NLRI field
// that reads as a route only if Path IDs are assumed is dropped once the
// Peer Up says ADD-PATH is off (RFC 7606 §5.3). While no Peer Up was seen
// the Path ID flip is still tried, and its result kept only if valid.
func TestMalformedNLRIWithKnownPathIDState(t *testing.T) {
	// Without Path IDs: 0.62.129.48/32, 0.0.0.0/0, then a 62-bit prefix.
	// With Path IDs: Path ID 0x20003e81 and a 48-bit prefix. Both readings
	// are malformed for IPv4 (RFC 4271 §4.3).
	repro := []byte{0x20, 0x00, 0x3e, 0x81, 0x30, 0x00, 0x3e, 0x81, 0x0a, 0x00, 0x00}
	// 10.1.2.0/24 with Path ID 255, malformed only without Path IDs.
	withID := catBytes(sessionPathID, sessionV4)
	// The same for VPN-IPv4: with Path IDs, Path ID 0x20003e81, label 1000,
	// RD 100:1 and 10.0.0.0/24; without, a 32-bit Length too short for the
	// label and RD.
	vpnRepro := []byte{0x20, 0x00, 0x3e, 0x81, 0x70, 0x00, 0x3e, 0x81, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 0x0a, 0x00, 0x00}
	tests := []struct {
		name   string
		update func(t *testing.T) *bgp.Update
		// Path ID of the one route published with no Peer Up, 0 for none.
		noPeerUpPathID int32
	}{
		{name: "SAFI 1", update: func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, repro)) }},
		{name: "SAFI 1 withdraw", update: func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0f, 1, 1, nil, repro)) }},
		{name: "NLRI field", update: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, repro) }},
		{name: "SAFI 1 Path ID", update: func(t *testing.T) *bgp.Update {
			return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, withID))
		}, noPeerUpPathID: 0xff},
		{name: "NLRI field Path ID", update: func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, withID) }, noPeerUpPathID: 0xff},
		{name: "L3VPN", update: func(t *testing.T) *bgp.Update {
			return ctTestUpdate(t, mpTestAttr(0x0e, 1, 128, sessionV4NH, vpnRepro), ctTestRT)
		}, noPeerUpPathID: 0x20003e81},
	}
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	for _, tt := range tests {
		t.Run(tt.name+", ADD-PATH known off", func(t *testing.T) {
			s := newSessionTest(t)
			s.peerUp(ph, bgp.Capability{}, bgp.Capability{})
			wantNoRoute(t, tt.name, s.routes(ph, tt.update(t)))
		})
		t.Run(tt.name+", no Peer Up", func(t *testing.T) {
			s := newSessionTest(t)
			routes := s.routes(ph, tt.update(t))
			if tt.noPeerUpPathID == 0 {
				wantNoRoute(t, tt.name, routes)
			} else if len(routes) != 1 || routes[0].PathID != tt.noPeerUpPathID {
				t.Errorf("published %+v, want one route with Path ID %#x", routes, tt.noPeerUpPathID)
			}
		})
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
		peerUp.SentOpen.Capabilities = addPathTestCaps(1, [2]byte{afi, 1})
		peerUp.ReceivedOpen.Capabilities = addPathTestCaps(1, [2]byte{afi, 1})
		for _, n := range names {
			peerUp.Information = append(peerUp.Information, bmp.InformationalTLV{InformationType: bmp.PeerUpTLVVRFTableName, Information: []byte(n)})
		}
		s.p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
	}
	peerUp(1, "global", "view-A")
	peerUp(2, "global", "view-B")
	for _, nlriType := range []int{bgp.NLRIMessageType(1, 1), bgp.NLRIMessageType(2, 1)} {
		if ids, _ := s.p.nlriState(ph, nlriType); ids != base.PathIDPresent {
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
	wantRoute(t, "IPv4 after one Peer Down", s.routes(ph, ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, v4PathID))), "10.1.2.0", 24, 7, nil)
	if tn := s.p.GetTableName(ph); tn != "globalview-Aview-B" {
		t.Errorf("GetTableName() after one Peer Down = %q, want globalview-Aview-B", tn)
	}
	s.peerDown(ph)
	if ids, _ := s.p.nlriState(ph, bgp.NLRIMessageType(1, 1)); ids != base.PathIDUnknown {
		t.Errorf("after the last Peer Down: state %d, want unknown", ids)
	}
}

// TestPathIDExpectedViews checks post-policy Adj-RIB-In and pre-policy
// Adj-RIB-Out, whose ADD-PATH encoding no RFC fixes: NLRI are decoded with
// the setting the capabilities suggest and, if that fails, with the other.
func TestPathIDExpectedViews(t *testing.T) {
	withID := catBytes(sessionPathID, sessionV4)
	tests := []struct {
		name       string
		flags      byte
		sent, recv byte
		nlri       []byte
		pathID     int32
	}{
		// The reviewer's repro: ADD-PATH both ways, post-policy Adj-RIB-In,
		// NLRI without Path IDs.
		{name: "Adj-RIB-In post-policy, expected Path IDs absent", flags: 0x40, sent: 3, recv: 3, nlri: sessionV4},
		{name: "Adj-RIB-In post-policy, expected Path IDs present", flags: 0x40, sent: 3, recv: 3, nlri: withID, pathID: 0xff},
		{name: "Adj-RIB-In post-policy, unexpected Path IDs", flags: 0x40, nlri: withID, pathID: 0xff},
		{name: "Adj-RIB-Out pre-policy, expected Path IDs absent", flags: 0x10, sent: 2, recv: 1, nlri: sessionV4},
		{name: "Adj-RIB-Out pre-policy, unexpected Path IDs", flags: 0x10, sent: 1, recv: 2, nlri: withID, pathID: 0xff},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSessionTest(t)
			ph := globalHeaderFlags("192.0.2.1", "10.0.0.1", tt.flags)
			var sentAS, recvAS [][2]byte
			if tt.sent != 0 {
				sentAS = [][2]byte{{1, 1}}
			}
			if tt.recv != 0 {
				recvAS = [][2]byte{{1, 1}}
			}
			s.peerUp(ph, addPathTestCaps(tt.sent, sentAS...), addPathTestCaps(tt.recv, recvAS...))
			wantRoute(t, "MP_REACH_NLRI", s.routes(ph, ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, tt.nlri))), "10.1.2.0", 24, tt.pathID, nil)
			wantRoute(t, "NLRI field", s.routes(ph, plainTestUpdate(t, nil, tt.nlri)), "10.1.2.0", 24, tt.pathID, nil)
		})
	}
	// The flip is rate limited per session and AFI/SAFI.
	s := newSessionTest(t)
	ph := globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x40)
	s.peerUp(ph, addPathTestCaps(3, [2]byte{1, 1}), addPathTestCaps(3, [2]byte{1, 1}))
	for i := 0; i < 3; i++ {
		s.routes(ph, ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, sessionV4)))
	}
	if len(s.p.pathIDWarned) != 1 {
		t.Errorf("warnings recorded for %d session AFI/SAFIs, want 1", len(s.p.pathIDWarned))
	}
	s.peerDown(ph)
	if len(s.p.pathIDWarned) != 0 {
		t.Errorf("warnings recorded after Peer Down for %d session AFI/SAFIs, want 0", len(s.p.pathIDWarned))
	}
}

// TestRouteMonitorSessionSnapshot checks that a Route Monitoring message is
// decoded with the session state at its place in the stream, not that of a
// Peer Down and Peer Up the dispatcher handled before its worker ran.
func TestRouteMonitorSessionSnapshot(t *testing.T) {
	s := newSessionTest(t)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	s.peerUp(ph, addPathTestCaps(3, [2]byte{1, 1}), addPathTestCaps(3, [2]byte{1, 1}))
	msg := bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, catBytes([]byte{0, 0, 0, 7}, sessionV4)))}}
	// As the Producer dispatch loop does before starting the worker.
	s.p.attachIdentitySnapshot(&msg)
	s.p.attachSessionSnapshot(&msg)
	s.peerDown(ph)
	s.peerUp(ph, bgp.Capability{}, bgp.Capability{})

	n := len(s.pub.msgs)
	s.p.producingWorker(msg)
	var got []UnicastPrefix
	for _, m := range s.pub.msgs[n:] {
		var u UnicastPrefix
		if err := json.Unmarshal(m.payload, &u); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}
		got = append(got, u)
	}
	wantRoute(t, "Route Monitoring dispatched before the Peer Down", got, "10.1.2.0", 24, 7, nil)
	if ph.Session != nil {
		t.Error("the snapshot was attached to the shared per-peer header")
	}
}

// TestDecodeErrorContext checks that a dropped NLRI field is logged with its
// session: router, peer, RIB view and AFI/SAFI.
func TestDecodeErrorContext(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x50)
	err := p.checkDecoded(ph, 1, 1, nil, errors.New("not enough bytes"))
	want := "router 10.0.0.1 peer 192.0.2.1 distinguisher 0:0 Adj-RIB-Out post-policy AFI/SAFI 1/1: not enough bytes"
	if err == nil || err.Error() != want {
		t.Errorf("checkDecoded() = %v, want %s", err, want)
	}
	ph = makePeerHeader(t, bmp.PeerType3, 0x00)
	err = p.checkDecoded(ph, 2, 1, nil, errors.New("x"))
	want = "router 10.0.0.1 peer BGP ID 10.0.0.1 distinguisher 0:0 Loc-RIB AFI/SAFI 2/1: x"
	if err == nil || err.Error() != want {
		t.Errorf("checkDecoded() = %v, want %s", err, want)
	}
}
