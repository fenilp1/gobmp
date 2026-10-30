package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// BGP Classful Transport (RFC 9832) end-to-end tests: a BGP UPDATE built from
// wire bytes is run through the route monitor path and the published JSON is
// checked.

var (
	// RFC 8277 §2.2 NLRI: Length 120, Label 1000 (S=1), RD 100:1, 10.0.0.1/32.
	ctTestNLRI = []byte{
		0x78,
		0x00, 0x3e, 0x81,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x01,
	}
	// RFC 8277 §2.4 withdrawal of the same route, Compatibility 0x800000.
	ctTestWithdrawn = []byte{
		0x78,
		0x80, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x01,
	}
	// RFC 9832 §4.3 Transport Class RTs.
	ctTestTCRT100   = []byte{0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	ctTestNTTCRT200 = []byte{0x4a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8}
	ctTestRT        = []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01} // rt=100:1
)

// ctTestUpdate builds a BGP UPDATE (RFC 4271 §4.3) whose path attributes are
// ORIGIN, AS_PATH, EXTENDED COMMUNITIES (when extComms is not empty) and attr.
func ctTestUpdate(t *testing.T, attr []byte, extComms ...[]byte) *bgp.Update {
	t.Helper()
	attrs := []byte{
		0x40, 0x01, 0x01, 0x00, // ORIGIN IGP
		0x40, 0x02, 0x06, 0x02, 0x01, 0x00, 0x00, 0xfd, 0xe8, // AS_PATH AS_SEQUENCE 65000
	}
	if len(extComms) != 0 {
		var ec []byte
		for _, c := range extComms {
			ec = append(ec, c...)
		}
		attrs = append(attrs, 0xc0, 0x10, byte(len(ec)))
		attrs = append(attrs, ec...)
	}
	attrs = append(attrs, attr...)
	b := []byte{0x00, 0x00, byte(len(attrs) >> 8), byte(len(attrs))}
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(append(b, attrs...), true)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdateWithAS4Hint() error: %v", err)
	}
	return update
}

// ctTestReach returns an MP_REACH_NLRI path attribute (RFC 4760 §3).
func ctTestReach(afi byte, nh []byte, nlri []byte) []byte {
	v := []byte{0x00, afi, bgp.SAFIClassfulTransport, byte(len(nh))}
	v = append(v, nh...)
	v = append(v, 0x00)
	v = append(v, nlri...)
	return append([]byte{0x80, 0x0e, byte(len(v))}, v...)
}

// ctTestUnreach returns an MP_UNREACH_NLRI path attribute (RFC 4760 §4).
func ctTestUnreach(afi byte, withdrawn []byte) []byte {
	v := append([]byte{0x00, afi, bgp.SAFIClassfulTransport}, withdrawn...)
	return append([]byte{0x80, 0x0f, byte(len(v))}, v...)
}

func publishCT(t *testing.T, splitAF bool, update *bgp.Update) []recordedMsg {
	t.Helper()
	pub := &recordingPublisher{}
	p := NewProducer(pub, splitAF).(*producer)
	p.produceRouteMonitorMessage(bmp.Message{
		PeerHeader: minimalPeerHeader(),
		Payload:    &bmp.RouteMonitor{Update: update},
	})
	return pub.msgs
}

func decodeCT(t *testing.T, m recordedMsg) (ClassfulTransportPrefix, map[string]any) {
	t.Helper()
	var msg ClassfulTransportPrefix
	if err := json.Unmarshal(m.payload, &msg); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(m.payload, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	return msg, raw
}

func TestProcessMPUpdateClassfulTransportTopics(t *testing.T) {
	v6NLRI := []byte{
		0xd8,             // Length 216
		0x00, 0x7d, 0x01, // Label 2000, S=1
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // 2001:db8::5/128
	}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	tests := []struct {
		name     string
		splitAF  bool
		attr     []byte
		wantType int
		prefix   string
	}{
		{name: "combined IPv4", attr: ctTestReach(1, []byte{192, 0, 2, 1}, ctTestNLRI), wantType: bmp.ClassfulTransportMsg, prefix: "10.0.0.1"},
		{name: "combined IPv6", attr: ctTestReach(2, v6NH, v6NLRI), wantType: bmp.ClassfulTransportMsg, prefix: "2001:db8::5"},
		{name: "split IPv4", splitAF: true, attr: ctTestReach(1, []byte{192, 0, 2, 1}, ctTestNLRI), wantType: bmp.ClassfulTransportV4Msg, prefix: "10.0.0.1"},
		{name: "split IPv6", splitAF: true, attr: ctTestReach(2, v6NH, v6NLRI), wantType: bmp.ClassfulTransportV6Msg, prefix: "2001:db8::5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishCT(t, tt.splitAF, ctTestUpdate(t, tt.attr, ctTestTCRT100))
			if len(msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(msgs))
			}
			if msgs[0].msgType != tt.wantType {
				t.Errorf("message type = %d, want %d", msgs[0].msgType, tt.wantType)
			}
			msg, _ := decodeCT(t, msgs[0])
			if msg.Prefix != tt.prefix || msg.Action != "add" {
				t.Errorf("prefix = %s, action = %s, want %s, add", msg.Prefix, msg.Action, tt.prefix)
			}
		})
	}
}

func TestProcessMPUpdateClassfulTransportAnnounceWithdraw(t *testing.T) {
	added := publishCT(t, false, ctTestUpdate(t, ctTestReach(1, []byte{192, 0, 2, 1}, ctTestNLRI), ctTestRT, ctTestNTTCRT200, ctTestTCRT100))
	if len(added) != 1 {
		t.Fatalf("published %d messages, want 1", len(added))
	}
	add, raw := decodeCT(t, added[0])
	if add.Action != "add" || add.Prefix != "10.0.0.1" || add.PrefixLen != 32 || !add.IsIPv4 {
		t.Errorf("route = %s %s/%d IPv4=%t, want add 10.0.0.1/32 IPv4", add.Action, add.Prefix, add.PrefixLen, add.IsIPv4)
	}
	if add.VPNRD != "100:1" || !reflect.DeepEqual(add.Labels, []uint32{1000}) {
		t.Errorf("RD = %s, labels = %v, want 100:1, [1000]", add.VPNRD, add.Labels)
	}
	if add.Nexthop != "192.0.2.1" || !add.IsNexthopIPv4 {
		t.Errorf("next hop = %s IPv4=%t, want 192.0.2.1 IPv4", add.Nexthop, add.IsNexthopIPv4)
	}
	// RFC 9832 §7.14: with both versions present only the transitive one is used.
	if ids, ok := raw["transport_class_ids"].([]any); !ok || !reflect.DeepEqual(ids, []any{float64(100)}) {
		t.Errorf("transport_class_ids = %v, want [100]", raw["transport_class_ids"])
	}
	wantECs := []string{"rt=100:1", "nt-transport-target=0:200", "transport-target=0:100"}
	if add.BaseAttributes == nil || !reflect.DeepEqual(add.BaseAttributes.ExtCommunityList, wantECs) {
		t.Errorf("ext communities = %v, want %v", add.BaseAttributes, wantECs)
	}
	if add.Hash == "" {
		t.Error("hash is empty")
	}

	withdrawn := publishCT(t, false, ctTestUpdate(t, ctTestUnreach(1, ctTestWithdrawn)))
	if len(withdrawn) != 1 {
		t.Fatalf("published %d messages, want 1", len(withdrawn))
	}
	del, raw := decodeCT(t, withdrawn[0])
	if del.Action != "del" || del.Prefix != "10.0.0.1" || del.PrefixLen != 32 || del.VPNRD != "100:1" {
		t.Errorf("route = %s %s/%d RD %s, want del 10.0.0.1/32 RD 100:1", del.Action, del.Prefix, del.PrefixLen, del.VPNRD)
	}
	if len(del.Labels) != 0 {
		t.Errorf("withdraw labels = %v, want none (RFC 8277 §2.4)", del.Labels)
	}
	if _, ok := raw["transport_class_ids"]; ok {
		t.Errorf("withdraw transport_class_ids = %v, want omitted", raw["transport_class_ids"])
	}
	if del.Hash != add.Hash {
		t.Errorf("withdraw hash = %s, want announcement hash %s", del.Hash, add.Hash)
	}
}

// RFC 9832 §4.3: a received non-transitive Transport Class RT is equivalent
// to the transitive one.
func TestProcessMPUpdateClassfulTransportNonTransitiveRT(t *testing.T) {
	msgs := publishCT(t, false, ctTestUpdate(t, ctTestReach(1, []byte{192, 0, 2, 1}, ctTestNLRI), ctTestNTTCRT200))
	if len(msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(msgs))
	}
	if msg, _ := decodeCT(t, msgs[0]); !reflect.DeepEqual(msg.TransportClassIDs, []uint32{200}) {
		t.Errorf("TransportClassIDs = %v, want [200]", msg.TransportClassIDs)
	}
}

func TestProcessMPUpdateClassfulTransportEndOfRIB(t *testing.T) {
	// RFC 4724 §2: End-of-RIB is an UPDATE whose only attribute is an empty
	// MP_UNREACH_NLRI; with other attributes it is not a marker.
	if msgs := publishCT(t, true, ctTestUpdate(t, ctTestUnreach(2, nil))); len(msgs) != 0 {
		t.Fatalf("published %d messages for an empty MP_UNREACH with other attributes, want 0", len(msgs))
	}
	attr := ctTestUnreach(2, nil)
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(append([]byte{0x00, 0x00, 0x00, byte(len(attr))}, attr...), true)
	if err != nil {
		t.Fatalf("UnmarshalBGPUpdateWithAS4Hint() error: %v", err)
	}
	msgs := publishCT(t, true, update)
	if len(msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(msgs))
	}
	if msgs[0].msgType != bmp.ClassfulTransportV6Msg {
		t.Errorf("message type = %d, want %d", msgs[0].msgType, bmp.ClassfulTransportV6Msg)
	}
	if msg, _ := decodeCT(t, msgs[0]); !msg.IsEOR || msg.Action != "del" || msg.IsIPv4 {
		t.Errorf("EoR = %t, action = %s, IPv4 = %t, want true, del, false", msg.IsEOR, msg.Action, msg.IsIPv4)
	}
}

// A malformed NLRI is logged and dropped without publishing or panicking.
func TestProcessMPUpdateClassfulTransportMalformed(t *testing.T) {
	if msgs := publishCT(t, false, ctTestUpdate(t, ctTestReach(1, []byte{192, 0, 2, 1}, ctTestNLRI[:10]))); len(msgs) != 0 {
		t.Fatalf("published %d messages for a truncated NLRI, want 0", len(msgs))
	}
	if msgs := publishCT(t, false, ctTestUpdate(t, ctTestReach(1, make([]byte, 8), ctTestNLRI))); len(msgs) != 0 {
		t.Fatalf("published %d messages for an invalid next hop length, want 0", len(msgs))
	}
}
