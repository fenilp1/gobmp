package message

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestPathIDExpectedViews checks every RIB view: NLRI are decoded with the
// Path ID setting the capabilities call for and, if that fails, with the
// other, as some routers encode a view, notably post-policy Adj-RIB-In and
// pre-policy Adj-RIB-Out whose encoding no RFC fixes, other than their OPEN
// messages say. A retry is warned about, rate limited per session and
// AFI/SAFI.
func TestPathIDExpectedViews(t *testing.T) {
	withID := catBytes(sessionPathID, sessionV4)
	tests := []struct {
		name       string
		peerType   bmp.PeerType
		flags      byte
		sent, recv byte
		nlri       []byte
		pathID     int32
		flipped    bool
	}{
		{name: "Adj-RIB-In pre-policy, expected Path IDs", sent: 3, recv: 3, nlri: withID, pathID: 0xff},
		{name: "Adj-RIB-In pre-policy, unexpected Path IDs absent", sent: 3, recv: 3, nlri: sessionV4, flipped: true},
		{name: "Adj-RIB-In post-policy, unexpected Path IDs absent", flags: 0x40, sent: 3, recv: 3, nlri: sessionV4, flipped: true},
		{name: "Adj-RIB-In post-policy, unexpected Path IDs", flags: 0x40, nlri: withID, pathID: 0xff, flipped: true},
		{name: "Adj-RIB-Out pre-policy, unexpected Path IDs absent", flags: 0x10, sent: 2, recv: 1, nlri: sessionV4, flipped: true},
		{name: "Adj-RIB-Out pre-policy, expected Path IDs absent", flags: 0x10, sent: 1, recv: 2, nlri: sessionV4},
		{name: "Adj-RIB-Out pre-policy, unexpected Path IDs", flags: 0x10, sent: 1, recv: 2, nlri: withID, pathID: 0xff, flipped: true},
		{name: "Adj-RIB-Out post-policy, expected Path IDs", flags: 0x50, sent: 2, recv: 1, nlri: withID, pathID: 0xff},
		{name: "Loc-RIB, unexpected Path IDs absent", peerType: bmp.PeerType3, sent: 1, recv: 1, nlri: sessionV4, flipped: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newSessionTest(t)
			ph := globalHeaderFlags("192.0.2.1", "10.0.0.1", tt.flags)
			if tt.peerType == bmp.PeerType3 {
				ph = makePeerHeader(t, bmp.PeerType3, tt.flags)
			}
			var sentAS, recvAS [][2]byte
			if tt.sent != 0 {
				sentAS = [][2]byte{{1, 1}}
			}
			if tt.recv != 0 {
				recvAS = [][2]byte{{1, 1}}
			}
			s.peerUp(ph, addPathTestCaps(tt.sent, sentAS...), addPathTestCaps(tt.recv, recvAS...))
			wantRoute(t, "MP_REACH_NLRI", s.routes(ph, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, tt.nlri))), "10.1.2.0", 24, tt.pathID, nil)
			wantRoute(t, "NLRI field", s.routes(ph, plainTestUpdate(t, nil, tt.nlri)), "10.1.2.0", 24, tt.pathID, nil)
			if warned := len(s.p.pathIDWarned) != 0; warned != tt.flipped {
				t.Errorf("Path ID retry warned %t, want %t", warned, tt.flipped)
			}
		})
	}
	// The warning is rate limited per session and AFI/SAFI, and forgotten
	// at the session's Peer Down.
	s := newSessionTest(t)
	ph := globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x40)
	s.peerUp(ph, addPathTestCaps(3, [2]byte{1, 1}), addPathTestCaps(3, [2]byte{1, 1}))
	for i := 0; i < 3; i++ {
		s.routes(ph, testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, sessionV4)))
	}
	if len(s.p.pathIDWarned) != 1 {
		t.Errorf("warnings recorded for %d session AFI/SAFIs, want 1", len(s.p.pathIDWarned))
	}
	s.peerDown(ph)
	if len(s.p.pathIDWarned) != 0 {
		t.Errorf("warnings recorded after Peer Down for %d session AFI/SAFIs, want 0", len(s.p.pathIDWarned))
	}
}

// TestRouteMonitorDecodedInStreamOrder checks that a Route Monitoring message
// is decoded with the session state at its place in the stream: the producer
// handles a connection's messages one at a time, so a Peer Down and a Peer Up
// without ADD-PATH that follow it do not change how it is decoded.
func TestRouteMonitorDecodedInStreamOrder(t *testing.T) {
	pub := &recordingPublisher{}
	p := NewProducer(pub, false).(*producer)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	peerUp := func(caps bgp.Capability) bmp.Message {
		m := buildPeerUpMessage(t, "192.168.1.1")
		m.SentOpen.Capabilities = caps
		m.ReceivedOpen.Capabilities = caps
		return bmp.Message{PeerHeader: ph, Payload: m, SpeakerIP: "10.2.1.3"}
	}
	route := func(nlri []byte) bmp.Message {
		update := testUpdate(t, mpTestAttr(0x0e, 1, 1, sessionV4NH, nlri))
		return bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}, SpeakerIP: "10.2.1.3"}
	}
	queue := make(chan bmp.Message, 5)
	queue <- peerUp(addPathTestCaps(3, [2]byte{1, 1}))
	queue <- route(catBytes([]byte{0, 0, 0, 7}, sessionV4))
	queue <- bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}, SpeakerIP: "10.2.1.3"}
	queue <- peerUp(bgp.Capability{})
	queue <- route(sessionV4)
	close(queue)
	p.Producer(queue, nil)

	var got []UnicastPrefix
	for _, m := range pub.msgs {
		if m.msgType != bmp.UnicastPrefixMsg {
			continue
		}
		var u UnicastPrefix
		if err := json.Unmarshal(m.payload, &u); err != nil {
			t.Fatalf("json.Unmarshal() error: %v", err)
		}
		got = append(got, u)
	}
	if len(got) != 2 {
		t.Fatalf("published %d routes, want 2: %+v", len(got), got)
	}
	wantRoute(t, "Route Monitoring before the Peer Down", got[:1], "10.1.2.0", 24, 7, nil)
	wantRoute(t, "Route Monitoring after the new Peer Up", got[1:], "10.1.2.0", 24, 0, nil)
}

// TestDecodeErrorContext checks that a dropped NLRI field is logged with its
// session: router, peer, RIB view and AFI/SAFI.
func TestDecodeErrorContext(t *testing.T) {
	p := NewProducer(&recordingPublisher{}, false).(*producer)
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
