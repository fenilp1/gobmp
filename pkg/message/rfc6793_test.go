package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

const (
	testPeerAS  = 65000      // Peer AS set by makePeerHeader
	testLocalAS = 4200000100 // monitored router's AS in the Sent OPEN
)

// sentOpenAS returns a Sent OPEN for a NEW speaker of AS as: My AS is
// AS_TRANS and the 4-octet AS Number Capability carries the AS.
func sentOpenAS(as uint32) *bgp.OpenMessage {
	return &bgp.OpenMessage{
		Version:  4,
		MyAS:     23456,
		HoldTime: 90,
		BGPID:    []byte{10, 0, 0, 1},
		Capabilities: bgp.Capability{
			65: {{Value: binary.BigEndian.AppendUint32(nil, as)}},
		},
	}
}

// updateMsg encodes a BGP UPDATE that withdraws 10.0.0.0/8 and announces
// 192.168.1.0/24 with the given path attributes.
func updateMsg(attrs []byte) []byte {
	withdrawn := []byte{0x08, 10}
	body := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	body = append(body, withdrawn...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(attrs)))
	body = append(append(body, attrs...), 0x18, 192, 168, 1)
	msg := bytes.Repeat([]byte{0xFF}, 16)
	msg = binary.BigEndian.AppendUint16(msg, uint16(19+len(body)))
	return append(append(msg, 2), body...)
}

// withPath returns ORIGIN, the given AS_PATH value and NEXT_HOP, followed by
// the extra attributes.
func withPath(asPath []byte, extra ...[]byte) []byte {
	attrs := []byte{0x40, 0x01, 0x01, 0x00}
	attrs = append(append(attrs, 0x40, 0x02, byte(len(asPath))), asPath...)
	attrs = append(attrs, 0x40, 0x03, 0x04, 10, 0, 0, 1)
	for _, e := range extra {
		attrs = append(attrs, e...)
	}
	return attrs
}

type publishedRoute struct {
	Action   string `json:"action"`
	Prefix   string `json:"prefix"`
	OriginAS uint32 `json:"origin_as"`
	BaseAttr struct {
		ASPath      []uint32            `json:"as_path"`
		ASPathCount int32               `json:"as_path_count"`
		AS4Path     []uint32            `json:"as4_path"`
		Segments    []bgp.ASPathSegment `json:"as_path_segments"`
	} `json:"base_attrs"`
}

// produceRoutes feeds a Peer Up with sentOpen (none if nil) and a Route
// Monitoring message carrying updateMsg(attrs) through the producer, decoding
// the UPDATE as the parser does, and returns the published unicast prefixes
// by prefix.
func produceRoutes(t *testing.T, sentOpen *bgp.OpenMessage, peerType bmp.PeerType, flags byte, attrs []byte) map[string]publishedRoute {
	t.Helper()
	return produceRoutesPeerAS(t, sentOpen, peerType, flags, testPeerAS, attrs)
}

// produceRoutesPeerAS is produceRoutes with the per-peer header Peer AS set
// to peerAS.
func produceRoutesPeerAS(t *testing.T, sentOpen *bgp.OpenMessage, peerType bmp.PeerType, flags byte, peerAS uint32, attrs []byte) map[string]publishedRoute {
	t.Helper()
	header := func(flags byte) *bmp.PerPeerHeader {
		ph := makePeerHeader(t, peerType, flags)
		ph.PeerAS = peerAS
		return ph
	}
	rec := &recordingPublisher{}
	p := NewProducer(rec, false).(*producer)
	if sentOpen != nil {
		peerUp := buildPeerUpMessage(t, "192.0.2.10")
		peerUp.SentOpen = sentOpen
		p.producingWorker(bmp.Message{PeerHeader: header(0), Payload: peerUp, SpeakerIP: "10.1.1.3"})
	} else {
		close(p.speakerReady)
	}
	ph := header(flags)
	as4, err := ph.Is4ByteASN()
	if err != nil {
		as4 = true // Loc-RIB (RFC 9069 Section 5.4.1)
	}
	rm, err := bmp.UnmarshalBMPRouteMonitorMessageWithAS4Hint(updateMsg(attrs), as4)
	if err != nil {
		t.Fatalf("UnmarshalBMPRouteMonitorMessageWithAS4Hint: %v", err)
	}
	rec.msgs = nil
	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: rm, SpeakerIP: "10.1.1.3"})
	routes := make(map[string]publishedRoute)
	for _, m := range rec.msgs {
		if m.msgType != bmp.UnicastPrefixMsg {
			continue
		}
		var r publishedRoute
		if err := json.Unmarshal(m.payload, &r); err != nil {
			t.Fatalf("json.Unmarshal: %v", err)
		}
		routes[r.Prefix] = r
	}
	return routes
}

// TestOriginAS_TwoOctetSession decodes UPDATEs with AS4_PATH from a peer
// whose per-peer header sets the A flag (flags 0x20: 2-octet AS_PATH, RFC
// 7854 Section 4.2) or, after a BMP speaker reformatted AS_PATH, does not.
func TestOriginAS_TwoOctetSession(t *testing.T) {
	tests := []struct {
		name     string
		flags    byte
		attrs    []byte
		asPath   []uint32
		segments []bgp.ASPathSegment
		origin   uint32
		as4Path  []uint32
	}{
		{
			// RFC 6793 Section 4.2.3: AS_TRANS is replaced from AS4_PATH.
			name:  "AS4_PATH merged",
			flags: 0x20,
			attrs: withPath(
				[]byte{0x02, 0x03, 0xFD, 0xE9, 0x0D, 0x1C, 0x5B, 0xA0},                               // AS_SEQUENCE [65001, 3356, AS_TRANS]
				[]byte{0xC0, 0x11, 0x0A, 0x02, 0x02, 0x00, 0x00, 0x0D, 0x1C, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_SEQUENCE [3356, 4200000001]
			),
			asPath:   []uint32{65001, 3356, 4200000001},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{65001, 3356, 4200000001}}},
			origin:   4200000001,
			as4Path:  []uint32{3356, 4200000001},
		},
		{
			// RFC 6793 Section 6: confederation segments are discarded from
			// AS4_PATH and from as4_path.
			name:  "AS4_PATH with confed segment merged",
			flags: 0x20,
			attrs: withPath(
				[]byte{0x02, 0x02, 0xFD, 0xE9, 0x5B, 0xA0},                                                 // AS_SEQUENCE [65001, AS_TRANS]
				[]byte{0xC0, 0x11, 0x0C, 0x03, 0x01, 0, 0, 0xFE, 0x4C, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_CONFED_SEQUENCE [65100] AS_SEQUENCE [4200000001]
			),
			asPath:   []uint32{65001, 4200000001},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{65001, 4200000001}}},
			origin:   4200000001,
			as4Path:  []uint32{4200000001},
		},
		{
			// RFC 7854 Section 4.2: A flag 0, but the BMP speaker reformatted
			// a 2-octet AS_PATH and still sent AS4_PATH.
			name:  "4-byte AS_PATH with AS_TRANS and AS4_PATH merged",
			flags: 0x00,
			attrs: withPath(
				[]byte{0x02, 0x02, 0, 0, 0xFD, 0xE9, 0, 0, 0x5B, 0xA0},       // AS_SEQUENCE [65001, AS_TRANS]
				[]byte{0xC0, 0x11, 0x06, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_SEQUENCE [4200000001]
			),
			asPath:   []uint32{65001, 4200000001},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{65001, 4200000001}}},
			origin:   4200000001,
			as4Path:  []uint32{4200000001},
		},
		{
			// AS4_PATH would replace 100, not the AS_TRANS before it.
			name:  "4-byte AS_PATH with AS_TRANS only in the kept part: AS4_PATH ignored",
			flags: 0x00,
			attrs: withPath(
				[]byte{0x02, 0x02, 0, 0, 0x5B, 0xA0, 0, 0, 0, 100},           // AS_SEQUENCE [AS_TRANS, 100]
				[]byte{0xC0, 0x11, 0x06, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_SEQUENCE [4200000001]
			),
			asPath:   []uint32{23456, 100},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{23456, 100}}},
			origin:   100,
			as4Path:  []uint32{4200000001},
		},
		{
			name:  "4-byte AS_PATH without AS_TRANS: AS4_PATH ignored",
			flags: 0x00,
			attrs: withPath(
				[]byte{0x02, 0x02, 0, 0, 0xFD, 0xE9, 0, 0, 0x0D, 0x1C},       // AS_SEQUENCE [65001, 3356]
				[]byte{0xC0, 0x11, 0x06, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_SEQUENCE [4200000001]
			),
			asPath:   []uint32{65001, 3356},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{65001, 3356}}},
			origin:   3356,
			as4Path:  []uint32{4200000001},
		},
		{
			name:  "AGGREGATOR AS_TRANS: AS4_PATH merged",
			flags: 0x20,
			attrs: withPath(
				[]byte{0x02, 0x02, 0xFD, 0xE9, 0x5B, 0xA0},                    // AS_SEQUENCE [65001, AS_TRANS]
				[]byte{0xC0, 0x07, 0x06, 0x5B, 0xA0, 10, 0, 0, 9},             // AGGREGATOR AS_TRANS 10.0.0.9
				[]byte{0xC0, 0x11, 0x06, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01},  // AS4_PATH AS_SEQUENCE [4200000001]
				[]byte{0xC0, 0x12, 0x08, 0xFA, 0x56, 0xEA, 0x01, 10, 0, 0, 9}, // AS4_AGGREGATOR 4200000001 10.0.0.9
			),
			asPath:   []uint32{65001, 4200000001},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{65001, 4200000001}}},
			origin:   4200000001,
			as4Path:  []uint32{4200000001},
		},
		{
			// RFC 6793 Section 4.2.3: AS4_PATH counts more AS numbers than
			// AS_PATH and is ignored.
			name:  "AS4_PATH longer than AS_PATH: ignored",
			flags: 0x20,
			attrs: withPath(
				[]byte{0x02, 0x01, 0x5B, 0xA0}, // AS_SEQUENCE [AS_TRANS]
				[]byte{0xC0, 0x11, 0x0A, 0x02, 0x02, 0x00, 0x01, 0x11, 0x70, 0x00, 0x01, 0x38, 0x80}, // AS4_PATH AS_SEQUENCE [70000, 80000]
			),
			asPath:   []uint32{23456},
			segments: []bgp.ASPathSegment{{Type: 2, ASNs: []uint32{23456}}},
			origin:   23456,
			as4Path:  []uint32{70000, 80000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := produceRoutes(t, sentOpenAS(testLocalAS), bmp.PeerType0, tt.flags, tt.attrs)
			got := routes["192.168.1.0"]
			if got.Action != "add" || got.OriginAS != tt.origin || got.BaseAttr.ASPathCount != int32(len(tt.asPath)) ||
				!reflect.DeepEqual(got.BaseAttr.ASPath, tt.asPath) || !reflect.DeepEqual(got.BaseAttr.Segments, tt.segments) ||
				!reflect.DeepEqual(got.BaseAttr.AS4Path, tt.as4Path) {
				t.Errorf("announced route = %+v, want as_path %v, as_path_count %d, segments %v, origin_as %d, as4_path %v",
					got, tt.asPath, len(tt.asPath), tt.segments, tt.origin, tt.as4Path)
			}
			if w := routes["10.0.0.0"]; w.Action != "del" || w.OriginAS != 0 {
				t.Errorf("withdrawn route = %+v, want action del and no origin_as", w)
			}
		})
	}
}

// TestOriginAS_RIBViews checks the origin of an AS_PATH that is empty, ends
// in a confederation segment or ends in an AS_SET for each RIB view (RFC
// 6811 Section 2), and that withdrawn routes carry no origin.
func TestOriginAS_RIBViews(t *testing.T) {
	empty := withPath(nil)
	confed := withPath([]byte{0x02, 0x01, 0, 0, 0, 100, 0x03, 0x01, 0, 0, 0xFD, 0xE9})         // AS_SEQUENCE [100] AS_CONFED_SEQUENCE [65001]
	asSet := withPath([]byte{0x02, 0x01, 0, 0, 0, 100, 0x01, 0x02, 0, 0, 0, 200, 0, 0, 1, 44}) // AS_SEQUENCE [100] AS_SET [200, 300]
	seq := withPath([]byte{0x02, 0x02, 0, 0, 0, 100, 0, 0, 0, 200})                            // AS_SEQUENCE [100, 200]
	locRIBOpen := sentOpenAS(64999)                                                            // Loc-RIB uses Peer AS, not the fabricated OPEN
	tests := []struct {
		name     string
		sentOpen *bgp.OpenMessage
		peerType bmp.PeerType
		flags    byte
		attrs    []byte
		want     uint32
	}{
		{"Adj-RIB-In, AS_SEQUENCE", sentOpenAS(testLocalAS), bmp.PeerType0, 0x00, seq, 200},
		{"Adj-RIB-In, empty", sentOpenAS(testLocalAS), bmp.PeerType0, 0x00, empty, testLocalAS},
		{"Adj-RIB-In, confed", sentOpenAS(testLocalAS), bmp.PeerType0, 0x00, confed, testLocalAS},
		{"Adj-RIB-In, AS_SET", sentOpenAS(testLocalAS), bmp.PeerType0, 0x00, asSet, 0},
		{"Adj-RIB-In post-policy, confed", sentOpenAS(testLocalAS), bmp.PeerType0, 0x40, confed, testLocalAS},
		{"Adj-RIB-Out, empty", sentOpenAS(testLocalAS), bmp.PeerType0, 0x10, empty, testLocalAS},
		{"Adj-RIB-Out, confed", sentOpenAS(testLocalAS), bmp.PeerType0, 0x10, confed, testLocalAS},
		{"Adj-RIB-Out, AS_SET", sentOpenAS(testLocalAS), bmp.PeerType0, 0x10, asSet, 0},
		// Pre-policy Adj-RIB-Out to an eBGP peer: the path as learned, before
		// the router prepends its AS.
		{"Adj-RIB-Out pre-policy, AS_SEQUENCE", sentOpenAS(testLocalAS), bmp.PeerType0, 0x10, seq, 200},
		{"Adj-RIB-Out post-policy, AS_SEQUENCE", sentOpenAS(testLocalAS), bmp.PeerType0, 0x50, seq, 200},
		{"Loc-RIB, empty", locRIBOpen, bmp.PeerType3, 0x00, empty, testPeerAS},
		{"Loc-RIB, confed", locRIBOpen, bmp.PeerType3, 0x00, confed, testPeerAS},
		{"Loc-RIB, AS_SET", locRIBOpen, bmp.PeerType3, 0x00, asSet, 0},
		// An OLD router: My AS is its AS.
		{"Adj-RIB-In, confed, 2-octet router", &bgp.OpenMessage{MyAS: 64700}, bmp.PeerType0, 0x00, confed, 64700},
		// Without a Peer Up, Peer AS stands in only for an empty AS_PATH on
		// Adj-RIB-In, which an internal peer sends (RFC 4271 Section 5.1.2).
		{"no Peer Up, Adj-RIB-In, empty", nil, bmp.PeerType0, 0x00, empty, testPeerAS},
		{"no Peer Up, Adj-RIB-In, confed", nil, bmp.PeerType0, 0x00, confed, 0},
		{"no Peer Up, Adj-RIB-Out, empty", nil, bmp.PeerType0, 0x10, empty, 0},
		{"no Peer Up, Loc-RIB, confed", nil, bmp.PeerType3, 0x00, confed, testPeerAS},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := produceRoutes(t, tt.sentOpen, tt.peerType, tt.flags, tt.attrs)
			if got := routes["192.168.1.0"]; got.Action != "add" || got.OriginAS != tt.want {
				t.Errorf("announced route action %q origin_as %d, want add, %d", got.Action, got.OriginAS, tt.want)
			}
			if got := routes["10.0.0.0"]; got.Action != "del" || got.OriginAS != 0 {
				t.Errorf("withdrawn route action %q origin_as %d, want del, none", got.Action, got.OriginAS)
			}
		})
	}
}

// TestOriginAS_MPReach checks origin_as from the MP_REACH_NLRI producer on a
// 2-octet session.
func TestOriginAS_MPReach(t *testing.T) {
	mpReach := []byte{0x80, 0x0E, 0x1A, 0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 32, 0x20, 0x01, 0x0d, 0xb8} // 2001:db8::/32
	attrs := withPath(
		[]byte{0x02, 0x02, 0xFD, 0xE9, 0x5B, 0xA0},                   // AS_SEQUENCE [65001, AS_TRANS]
		[]byte{0xC0, 0x11, 0x06, 0x02, 0x01, 0xFA, 0x56, 0xEA, 0x01}, // AS4_PATH AS_SEQUENCE [4200000001]
		mpReach,
	)
	routes := produceRoutes(t, sentOpenAS(testLocalAS), bmp.PeerType0, 0x20, attrs)
	if got := routes["2001:db8::"]; got.Action != "add" || got.OriginAS != 4200000001 {
		t.Errorf("2001:db8::/32 action %q origin_as %d, want add, 4200000001", got.Action, got.OriginAS)
	}
}

// RFC 9069 Section 5.1 sets Loc-RIB Peer AS to the router's AS; if a sender
// leaves it 0, the fabricated Sent OPEN (RFC 9069 Section 5.2) gives it.
func TestOriginAS_LocRIBPeerASZero(t *testing.T) {
	tests := []struct {
		name     string
		sentOpen *bgp.OpenMessage
		want     uint32
	}{
		{"Sent OPEN", sentOpenAS(64999), 64999},
		{"no Peer Up", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes := produceRoutesPeerAS(t, tt.sentOpen, bmp.PeerType3, 0, 0, withPath(nil))
			if got := routes["192.168.1.0"]; got.Action != "add" || got.OriginAS != tt.want {
				t.Errorf("announced route action %q origin_as %d, want add, %d", got.Action, got.OriginAS, tt.want)
			}
		})
	}
}
