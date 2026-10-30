package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// luTestAttr returns an MP_REACH_NLRI (code 14) or MP_UNREACH_NLRI (code 15)
// path attribute for AFI 1/2 SAFI 4. The next hop is only used for 14.
func luTestAttr(code byte, afi byte, nh []byte, nlri []byte) []byte {
	v := []byte{0x00, afi, 4}
	if code == 0x0e {
		v = append(v, byte(len(nh)))
		v = append(v, nh...)
		v = append(v, 0x00) // Reserved
	}
	v = append(v, nlri...)
	return append([]byte{0x80, code, byte(len(v))}, v...)
}

// TestLabeledUnicastPublishedJSONGolden pins the JSON published for valid
// labeled unicast input, so decoder conformance fixes are shown not to change
// consumer output.
func TestLabeledUnicastPublishedJSONGolden(t *testing.T) {
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	tests := []struct {
		name string
		attr []byte
		want string
	}{
		{
			name: "IPv4 announce",
			attr: luTestAttr(0x0e, 1, []byte{192, 0, 2, 1}, []byte{
				0x30,             // Length 48 = 24 label + 24 prefix
				0x05, 0xdc, 0x31, // Label 24003, S=1
				0x0a, 0x01, 0x02, // 10.1.2.0/24
			}),
			want: `{"action":"add","hash":"5380439caa078f2bea3eaec10c7c5c2a","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"dbc02de9afbdb1d5ef11938acad0ffa7","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"labels":[24003],"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "IPv4 withdraw",
			attr: luTestAttr(0x0f, 1, nil, []byte{
				0x30,             // Length 48
				0x80, 0x00, 0x00, // Compatibility
				0x0a, 0x01, 0x02, // 10.1.2.0/24
			}),
			want: `{"action":"del","hash":"bb239fe17b30ba78ab7d6ac4eec7f5e1","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"3b0e37da66a0647b0dc2c48985f9a435","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"is_nexthop_ipv4":true,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "IPv4 two labels",
			attr: luTestAttr(0x0e, 1, []byte{192, 0, 2, 1}, []byte{
				0x50,             // Length 80 = 48 labels + 32 prefix
				0x00, 0x06, 0x40, // Label 100, S=0
				0x00, 0x0c, 0x81, // Label 200, S=1
				0x0a, 0x00, 0x00, 0x01, // 10.0.0.1/32
			}),
			want: `{"action":"add","hash":"bdd5487583ca3f32735cf1ea6c6f204b","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"ea32f651313de4bc903256b79531b3cd","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.0.0.1","prefix_len":32,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"labels":[100,200],"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "IPv6 announce",
			attr: luTestAttr(0x0e, 2, v6NH, []byte{
				0x58,             // Length 88 = 24 label + 64 prefix
				0x00, 0x7d, 0x01, // Label 2000, S=1
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
			}),
			want: `{"action":"add","hash":"031b2d286aee87ea6a7986ae142e7394","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"c20ed4266b8ebfb8e3e226f5ba8535c5","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"nexthop":"2001:db8::1","is_nexthop_ipv4":false,"labels":[2000],"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "IPv6 withdraw",
			attr: luTestAttr(0x0f, 2, nil, []byte{
				0x58,             // Length 88
				0x80, 0x00, 0x00, // Compatibility
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
			}),
			want: `{"action":"del","hash":"ba1c3c731087ea4b4a5461ed2eed9c19","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"9e058c7089718b90f8b20a34ae2c6443","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"is_nexthop_ipv4":false,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishUpdate(t, false, testUpdate(t, tt.attr))
			if len(msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(msgs))
			}
			if msgs[0].msgType != bmp.UnicastPrefixMsg {
				t.Errorf("message type = %d, want %d", msgs[0].msgType, bmp.UnicastPrefixMsg)
			}
			if got := string(msgs[0].payload); got != tt.want {
				t.Errorf("published JSON:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
