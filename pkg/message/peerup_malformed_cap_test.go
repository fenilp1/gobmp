package message

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

var bgpMarker = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// testPeerUpBody encodes a BMP Peer Up body (after the per-peer header) with
// open as both the sent and the received OPEN.
func testPeerUpBody(open []byte) []byte {
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2, 0, 179, 0x9c, 0x40}
	b = append(append(b, bgpMarker...), open...)
	return append(append(b, bgpMarker...), open...)
}

// testAttr encodes a BGP path attribute using the extended length format.
func testAttr(flags, typ byte, v []byte) []byte {
	b := []byte{flags | 0x10, typ, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	return append(b, v...)
}

// testUpdate encodes a BGP UPDATE carrying attrs and no withdrawn routes.
func testUpdate(attrs []byte) []byte {
	b := append([]byte(nil), bgpMarker...)
	b = binary.BigEndian.AppendUint16(b, uint16(19+4+len(attrs)))
	b = append(b, 2, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(attrs)))
	return append(b, attrs...)
}

// A PeerUp whose OPENs carry a malformed 4-octet AS capability (RFC 6793 §3)
// must still be published, fall back to My AS, and set up the per-table
// ADD-PATH state so that later routes decode with their Path IDs.
func TestPeerUpWithMalformedCap65KeepsAddPath(t *testing.T) {
	for name, cap65 := range map[string][]byte{
		"length 2": {0x02, 0x04, 0x41, 0x02, 0xfd, 0xe8},
		"length 5": {0x02, 0x07, 0x41, 0x05, 0x00, 0x00, 0xfd, 0xe8, 0x00},
	} {
		t.Run(name, func(t *testing.T) {
			opt := append(append([]byte(nil), cap65...),
				0x02, 0x06, 0x45, 0x04, 0x00, 0x02, 0x01, 0x03) // ADD-PATH IPv6 unicast, send/receive
			open := append([]byte{0, byte(29 + len(opt)), 1, 4, 0xfd, 0xe8, 0, 0xb4, 192, 0, 2, 1, byte(len(opt))}, opt...)
			pu, err := bmp.UnmarshalPeerUpMessage(testPeerUpBody(open), false)
			if err != nil {
				t.Fatalf("UnmarshalPeerUpMessage: %v", err)
			}
			pub := &recordingPublisher{}
			p := NewProducer(pub, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0)
			p.producingWorker(bmp.Message{PeerHeader: ph, Payload: pu})

			if len(pub.msgs) != 1 || pub.msgs[0].msgType != bmp.PeerStateChangeMsg {
				t.Fatalf("PeerUp not published: %d messages", len(pub.msgs))
			}
			var psc PeerStateChange
			if err := json.Unmarshal(pub.msgs[0].payload, &psc); err != nil {
				t.Fatal(err)
			}
			if psc.LocalASN != 65000 {
				t.Errorf("LocalASN = %d, want My AS 65000", psc.LocalASN)
			}
			select {
			case <-p.speakerReady:
			default:
				t.Fatal("speakerReady not closed")
			}

			// MP_REACH_NLRI IPv6 unicast with Path ID 7 for 2001:db8::/32.
			reach := []byte{0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0,
				0, 0, 0, 7, 32, 0x20, 0x01, 0x0d, 0xb8}
			attrs := append([]byte{0x40, 1, 1, 0, 0x40, 2, 0}, testAttr(0x80, 14, reach)...)
			rm, err := bmp.UnmarshalBMPRouteMonitorMessage(testUpdate(attrs))
			if err != nil {
				t.Fatalf("UnmarshalBMPRouteMonitorMessage: %v", err)
			}
			p.producingWorker(bmp.Message{PeerHeader: ph, Payload: rm})
			if len(pub.msgs) != 2 || pub.msgs[1].msgType != bmp.UnicastPrefixMsg {
				t.Fatalf("route not published: %d messages", len(pub.msgs))
			}
			var up UnicastPrefix
			if err := json.Unmarshal(pub.msgs[1].payload, &up); err != nil {
				t.Fatal(err)
			}
			if up.PathID != 7 || up.Prefix != "2001:db8::" || up.PrefixLen != 32 {
				t.Errorf("route = path_id %d prefix %s/%d, want 7 2001:db8::/32", up.PathID, up.Prefix, up.PrefixLen)
			}
		})
	}
}

// Malformed Multiprotocol (RFC 4760 §8) and BGP Role (RFC 9234 §4.1)
// capabilities are published raw in adv_cap/recv_cap, next to a valid Role,
// and the PeerUp and its ADD-PATH state are kept. Rejecting the OPEN used to
// drop the PeerUp, which also left speakerReady open so every later Route
// Monitoring message was dropped.
func TestPeerUpWithMalformedCap1And9KeepsThemVisible(t *testing.T) {
	opt := []byte{
		0x02, 0x05, 0x01, 0x03, 0x00, 0x01, 0x00, // MP, length 3
		0x02, 0x07, 0x09, 0x02, 0x00, 0x00, 0x09, 0x01, 0x03, // malformed Role, then Role Customer
		0x02, 0x06, 0x45, 0x04, 0x00, 0x02, 0x01, 0x03, // ADD-PATH IPv6 unicast, send/receive
	}
	open := append([]byte{0, byte(29 + len(opt)), 1, 4, 0xfd, 0xe8, 0, 0xb4, 192, 0, 2, 1, byte(len(opt))}, opt...)
	pu, err := bmp.UnmarshalPeerUpMessage(testPeerUpBody(open), false)
	if err != nil {
		t.Fatalf("UnmarshalPeerUpMessage: %v", err)
	}
	if _, ok := pu.ReceivedOpen.BGPRoleCapability(); ok {
		t.Error("BGPRoleCapability reported a Role for a malformed plus valid Role")
	}
	pub := &recordingPublisher{}
	p := NewProducer(pub, false).(*producer)
	ph := makePeerHeader(t, bmp.PeerType0, 0)
	p.producingWorker(bmp.Message{PeerHeader: ph, Payload: pu})

	if len(pub.msgs) != 1 || pub.msgs[0].msgType != bmp.PeerStateChangeMsg {
		t.Fatalf("PeerUp not published: %d messages", len(pub.msgs))
	}
	var psc struct {
		Adv map[string][]bgp.CapabilityData `json:"adv_cap"`
		Rcv map[string][]bgp.CapabilityData `json:"recv_cap"`
	}
	if err := json.Unmarshal(pub.msgs[0].payload, &psc); err != nil {
		t.Fatal(err)
	}
	for name, caps := range map[string]map[string][]bgp.CapabilityData{"adv_cap": psc.Adv, "recv_cap": psc.Rcv} {
		if mp := caps["1"]; len(mp) != 1 || !bytes.Equal(mp[0].Value, []byte{0x00, 0x01, 0x00}) {
			t.Errorf("%s: Multiprotocol = %+v, want raw 000100", name, mp)
		}
		if role := caps["9"]; len(role) != 2 || !bytes.Equal(role[0].Value, []byte{0, 0}) || !bytes.Equal(role[1].Value, []byte{3}) {
			t.Errorf("%s: Role = %+v, want raw 0000 then 03", name, role)
		}
	}
	if !p.GetAddPathCapability(ph.GetTableKey())[bgp.NLRIMessageType(2, 1)] {
		t.Error("ADD-PATH state lost")
	}
}
