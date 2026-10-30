package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestRIBViewPublishedJSONGolden pins the JSON published for valid input in
// Adj-RIB-Out (RFC 8671), Loc-RIB (RFC 9069) and with ADD-PATH negotiated in
// one direction only (RFC 7911 §5). The expectations were captured after the
// per-session state change: most match the output before it, but "Loc-RIB,
// ADD-PATH receive only" and "router Send, peer Receive: Adj-RIB-Out
// post-policy with Path IDs" are fixes, as before it those NLRI were read
// without Path IDs and published five bogus routes each.
func TestRIBViewPublishedJSONGolden(t *testing.T) {
	v4NH := []byte{192, 0, 2, 1}
	withID := []byte{0x00, 0x00, 0x00, 0x07, 0x18, 0x0a, 0x01, 0x02} // Path ID 7, 10.1.2.0/24
	plain := []byte{0x18, 0x0a, 0x01, 0x02}                          // 10.1.2.0/24
	vpn := []byte{0x00, 0x00, 0x00, 0x07, 0x70, 0x05, 0xdc, 0x31, 0, 0, 0, 0x64, 0, 0, 0, 0x01, 10, 1, 2}
	safi1 := [2]byte{1, 1}
	tests := []struct {
		name       string
		ph         func(t *testing.T) *bmp.PerPeerHeader
		sent, recv byte // ADD-PATH Send/Receive in the sent and received OPENs
		as         [2]byte
		tableName  string // Peer Up VRF/Table Name TLV, if any
		update     func(t *testing.T) *bgp.Update
		wantType   int
		want       []string
	}{
		{
			name: "Adj-RIB-Out pre-policy, ADD-PATH both",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x10) },
			sent: 3, recv: 3, as: safi1,
			update:   func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, withID)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"3bf98b6982f616aa576ef35d954683bc","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"685b67d472a35e9c60ca2f5b4c83010a","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":true,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name: "Adj-RIB-Out post-policy, ADD-PATH both",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x50) },
			sent: 3, recv: 3, as: safi1,
			update:   func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, withID)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"3bf98b6982f616aa576ef35d954683bc","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"685b67d472a35e9c60ca2f5b4c83010a","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":true,"is_adj_rib_out":true,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name: "Adj-RIB-In post-policy, ADD-PATH both",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x40) },
			sent: 3, recv: 3, as: safi1,
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, withID) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"3bf98b6982f616aa576ef35d954683bc","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"8cb57e2a9c62e1d3c1ba4fec098235b0","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"nexthop":"192.0.2.1","is_atomic_agg":false},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":true,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name: "Loc-RIB, ADD-PATH receive only",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return makePeerHeader(t, bmp.PeerType3, 0x00) },
			sent: 1, recv: 1, as: safi1,
			tableName: "global",
			update:    func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, withID)) },
			wantType:  bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"1ae2a56352ad8584a69e689a32134bfd","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"685b67d472a35e9c60ca2f5b4c83010a","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"819d10ff9f291f8d9a679abcb6499063","remote_bgp_id":"10.0.0.1","peer_ip":"0.0.0.0","peer_type":3,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":true,"is_loc_rib_filtered":false,"table_name":"global"}`,
			},
		},
		{
			name:      "Loc-RIB filtered, no ADD-PATH, NLRI field",
			ph:        func(t *testing.T) *bmp.PerPeerHeader { return makePeerHeader(t, bmp.PeerType3, 0x80) },
			tableName: "VRF-A",
			update:    func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, plain) },
			wantType:  bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"b9f2a8da81f49d2d97f0781cc1a3b1e0","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"8cb57e2a9c62e1d3c1ba4fec098235b0","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"nexthop":"192.0.2.1","is_atomic_agg":false},"peer_hash":"819d10ff9f291f8d9a679abcb6499063","remote_bgp_id":"10.0.0.1","peer_ip":"0.0.0.0","peer_type":3,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":true,"is_loc_rib_filtered":true,"table_name":"VRF-A"}`,
			},
		},
		{
			name: "router Send, peer Receive: Adj-RIB-Out post-policy with Path IDs",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeaderFlags("192.0.2.1", "10.0.0.1", 0x50) },
			sent: 2, recv: 1, as: safi1,
			update:   func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 1, v4NH, withID)) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"3bf98b6982f616aa576ef35d954683bc","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"685b67d472a35e9c60ca2f5b4c83010a","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":true,"is_adj_rib_out":true,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name: "router Send, peer Receive: Adj-RIB-In pre-policy without",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeader("192.0.2.1", "10.0.0.1") },
			sent: 2, recv: 1, as: safi1,
			update:   func(t *testing.T) *bgp.Update { return plainTestUpdate(t, nil, plain) },
			wantType: bmp.UnicastPrefixMsg,
			want: []string{
				`{"action":"add","hash":"ecb8f4650bc00a6960427a6926029265","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"8cb57e2a9c62e1d3c1ba4fec098235b0","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"nexthop":"192.0.2.1","is_atomic_agg":false},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
		{
			name: "router Receive, peer Send: Adj-RIB-In pre-policy VPNv4 with Path IDs",
			ph:   func(t *testing.T) *bmp.PerPeerHeader { return globalHeader("192.0.2.1", "10.0.0.1") },
			sent: 1, recv: 2, as: [2]byte{1, 128},
			update:   func(t *testing.T) *bgp.Update { return ctTestUpdate(t, mpTestAttr(0x0e, 1, 128, v4NH, vpn), ctTestRT) },
			wantType: bmp.L3VPNMsg,
			want: []string{
				`{"action":"add","hash":"c4e5994bf442c01ed55e19404e49b38e","router_hash":"abc123","router_ip":"10.0.0.1","base_attrs":{"base_attr_hash":"7e5a33b159a7dcc50c487cec2f0448e2","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false,"ext_community_list":["rt=100:1"]},"peer_hash":"79c56ab0db70cf69163c11ad4f16def2","remote_bgp_id":"10.0.0.1","peer_ip":"192.0.2.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"path_id":7,"labels":[24003],"vpn_rd":"100:1","vpn_rd_type":0,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{}
			p := NewProducer(pub, false).(*producer)
			ph := tt.ph(t)
			var sentAS, recvAS [][2]byte
			if tt.sent != 0 {
				sentAS = [][2]byte{tt.as}
			}
			if tt.recv != 0 {
				recvAS = [][2]byte{tt.as}
			}
			peerUp := buildPeerUpMessage(t, "192.168.1.1")
			peerUp.SentOpen.Capabilities = addPathTestCaps(tt.sent, sentAS...)
			peerUp.ReceivedOpen.Capabilities = addPathTestCaps(tt.recv, recvAS...)
			if tt.tableName != "" {
				peerUp.Information = []bmp.InformationalTLV{{InformationType: bmp.PeerUpTLVVRFTableName, Information: []byte(tt.tableName)}}
			}
			p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
			n := len(pub.msgs)
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: tt.update(t)}})
			msgs := pub.msgs[n:]
			if len(msgs) != len(tt.want) {
				t.Fatalf("published %d messages, want %d", len(msgs), len(tt.want))
			}
			for i, m := range msgs {
				if m.msgType != tt.wantType {
					t.Errorf("message %d type = %d, want %d", i, m.msgType, tt.wantType)
				}
				if got := string(m.payload); got != tt.want[i] {
					t.Errorf("message %d published JSON:\n%s\nwant:\n%s", i, got, tt.want[i])
				}
			}
		})
	}
}
