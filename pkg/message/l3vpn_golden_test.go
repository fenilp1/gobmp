package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// l3vpnTestAttr returns an MP_REACH_NLRI (code 14) or MP_UNREACH_NLRI (code
// 15) path attribute for AFI 1/2 SAFI 128. The next hop is only used for 14.
func l3vpnTestAttr(code byte, afi byte, nh []byte, nlri []byte) []byte {
	v := []byte{0x00, afi, 128}
	if code == 0x0e {
		v = append(v, byte(len(nh)))
		v = append(v, nh...)
		v = append(v, 0x00) // Reserved
	}
	v = append(v, nlri...)
	return append([]byte{0x80, code, byte(len(v))}, v...)
}

// TestL3VPNPublishedJSONGolden pins the JSON published for valid L3VPN input,
// so decoder conformance fixes are shown not to change consumer output.
func TestL3VPNPublishedJSONGolden(t *testing.T) {
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	tests := []struct {
		name string
		attr []byte
		want string
	}{
		{
			name: "VPNv4 announce",
			attr: l3vpnTestAttr(0x0e, 1, []byte{192, 0, 2, 1}, []byte{
				0x70,             // Length 112 = 24 label + 64 RD + 24 prefix
				0x05, 0xdc, 0x31, // Label 24003, S=1
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
				0x0a, 0x01, 0x02, // 10.1.2.0/24
			}),
			want: `{"action":"add","hash":"3c6f27782b43269ccce071e01f9ca3da","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"82b4f6d21a3d278fa768728c13ebc0d3","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false,"ext_community_list":["rt=100:1"]},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"nexthop":"192.0.2.1","is_nexthop_ipv4":true,"labels":[24003],"vpn_rd":"100:1","vpn_rd_type":0,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "VPNv4 withdraw",
			attr: l3vpnTestAttr(0x0f, 1, nil, []byte{
				0x70,             // Length 112
				0x80, 0x00, 0x00, // Compatibility
				0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
				0x0a, 0x01, 0x02, // 10.1.2.0/24
			}),
			want: `{"action":"del","hash":"5382b7b29e5937af8f06f20a599877f4","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"e22082053ccb97a395706120958caa24","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false,"ext_community_list":["rt=100:1"]},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"10.1.2.0","prefix_len":24,"is_ipv4":true,"origin_as":65000,"is_nexthop_ipv4":true,"vpn_rd":"100:1","vpn_rd_type":0,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
		{
			name: "VPNv6 announce",
			attr: l3vpnTestAttr(0x0e, 2, v6NH, []byte{
				0x98,             // Length 152 = 24 label + 64 RD + 64 prefix
				0x00, 0x7d, 0x01, // Label 2000, S=1
				0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x07, // RD 192.0.2.1:7
				0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00, // 2001:db8:1::/64
			}),
			want: `{"action":"add","hash":"47c7d2438afe13be57a55f387e8cf812","router_ip":"10.1.1.1","base_attrs":{"base_attr_hash":"42fdbc6a68f50490e8d8bfd4ad5e574b","origin":"igp","as_path":[65000],"as_path_count":1,"as_path_segments":[{"type":2,"asns":[65000]}],"is_atomic_agg":false,"ext_community_list":["rt=100:1"]},"peer_hash":"ef9f1cc86e4617df24d4675e2b55bbe2","remote_bgp_id":"10.0.0.1","peer_ip":"10.0.0.1","peer_type":0,"peer_asn":65000,"timestamp":"1970-01-01T00:00:00Z","prefix":"2001:db8:1::","prefix_len":64,"is_ipv4":false,"origin_as":65000,"nexthop":"2001:db8::1","is_nexthop_ipv4":false,"labels":[2000],"vpn_rd":"192.0.2.1:7","vpn_rd_type":1,"is_adj_rib_in_post_policy":false,"is_adj_rib_out_post_policy":false,"is_adj_rib_out":false,"is_loc_rib":false,"is_loc_rib_filtered":false}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishCT(t, false, ctTestUpdate(t, tt.attr, ctTestRT))
			if len(msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(msgs))
			}
			if msgs[0].msgType != bmp.L3VPNMsg {
				t.Errorf("message type = %d, want %d", msgs[0].msgType, bmp.L3VPNMsg)
			}
			if got := string(msgs[0].payload); got != tt.want {
				t.Errorf("published JSON:\n%s\nwant:\n%s", got, tt.want)
			}
		})
	}
}
