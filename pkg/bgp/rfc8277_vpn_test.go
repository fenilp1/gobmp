package bgp

import (
	"fmt"
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
)

// RFC 8277 conformance of the L3VPN (SAFI 128) NLRI decoder.

var vpnTestRD = []byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01} // RD 100:1

func vpnTestNLRI(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

// decodeVPN decodes nlri as MP_REACH_NLRI (withdraw false) or MP_UNREACH_NLRI
// (withdraw true) of AFI afi SAFI 128 through GetNLRIL3VPN.
func decodeVPN(t *testing.T, afi uint16, withdraw bool, ml base.MultiLabel, nlri []byte) (*base.MPNLRI, error) {
	t.Helper()
	var mp MPNLRI
	if withdraw {
		mp = &MPUnReachNLRI{AddressFamilyID: afi, SubAddressFamilyID: 128, WithdrawnRoutes: nlri}
	} else {
		mp = &MPReachNLRI{
			AddressFamilyID:      afi,
			SubAddressFamilyID:   128,
			NextHopAddressLength: 4,
			NextHopAddress:       []byte{192, 0, 2, 1},
			NLRI:                 nlri,
			MultiLabel:           ml,
		}
	}
	return mp.GetNLRIL3VPN()
}

func TestVPNNLRIRFC8277Conformance(t *testing.T) {
	v4Prefix := []byte{0x0a, 0x00, 0x00, 0x01} // 10.0.0.1
	tests := []struct {
		name     string
		afi      uint16
		withdraw bool
		ml       base.MultiLabel
		nlri     []byte
		labels   []uint32 // expected labels; nil for none
		cidr     string   // expected prefix, if set
		rd       string   // expected RD; 100:1 if empty
		fail     bool
	}{
		{
			// RFC 8277 §2.4: the Compatibility field MUST be ignored, so a
			// value other than 0x800000/0x000000 is skipped, not parsed.
			name:     "withdraw with label-like compatibility S=0",
			afi:      1,
			withdraw: true,
			nlri:     vpnTestNLRI([]byte{0x78, 0x00, 0x06, 0x40}, vpnTestRD, v4Prefix),
		},
		{
			name:     "withdraw with label-like compatibility S=1",
			afi:      1,
			withdraw: true,
			nlri:     vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x81}, vpnTestRD, v4Prefix),
		},
		{
			// The compatibility marker only exists on the withdraw path: a
			// first label of 0x80000 with S=0 is a label in an announcement.
			name:   "announce first label 0x800000 with multiple labels",
			afi:    1,
			ml:     base.MultiLabelConfirmed,
			nlri:   vpnTestNLRI([]byte{0x90, 0x80, 0x00, 0x00, 0x00, 0x3e, 0x81}, vpnTestRD, v4Prefix),
			labels: []uint32{0x80000, 1000},
		},
		{
			name:   "announce two labels with multiple labels",
			afi:    1,
			ml:     base.MultiLabelConfirmed,
			nlri:   vpnTestNLRI([]byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, vpnTestRD, v4Prefix),
			labels: []uint32{100, 200},
		},
		{
			// RFC 8277 §2.2: without the capability exactly one label is
			// present and the S bit MUST be ignored.
			name:   "announce S=0, capability unknown",
			afi:    1,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x80}, vpnTestRD, v4Prefix),
			labels: []uint32{1000},
		},
		{
			name:   "announce S=0, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x80}, vpnTestRD, v4Prefix),
			labels: []uint32{1000},
		},
		{
			// RD 256:1: the S bit walk would read 00 00 01 as a second label
			// and parse a valid looking RD 0:17432576 and 1.0.0.0/8, so a
			// known absent capability decodes one label first.
			name:   "announce S=0 with label-like type 0 RD, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x80}, []byte{0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01}, v4Prefix),
			labels: []uint32{1000},
			rd:     "256:1",
		},
		{
			name:   "announce S=0 with label-like type 1 RD, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x80}, []byte{0x00, 0x01, 0x0b, 0x00, 0x01, 0x01, 0x00, 0x05}, v4Prefix),
			labels: []uint32{1000},
			rd:     "11.0.1.1:5",
		},
		{
			// The single label parse is invalid (56-bit IPv4 prefix), so the
			// S bit walk is used.
			name:   "announce two labels, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, vpnTestRD, v4Prefix),
			labels: []uint32{100, 200},
		},
		{
			// Labels are read by the S bit first when the capability state is
			// unknown, so a collector without it still decodes a label stack.
			name:   "announce two labels, capability unknown",
			afi:    1,
			nlri:   vpnTestNLRI([]byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, vpnTestRD, v4Prefix),
			labels: []uint32{100, 200},
		},
		{
			// Labels 100 and 3 (Implicit NULL), 2001:db8:1::/64: the single
			// label reading would take the second label as part of the RD.
			name:   "announce IPv6 two labels, capability unknown",
			afi:    2,
			nlri:   vpnTestNLRI([]byte{0xb0, 0x00, 0x06, 0x40, 0x00, 0x00, 0x31}, vpnTestRD, []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}),
			labels: []uint32{100, 3},
			cidr:   "2001:db8:1::/64",
		},
		{
			// With the capability known absent the strict single label
			// reading is valid here and wins (RFC 8277 §2.2): a sender
			// binding two labels without the capability is not compliant.
			name:   "announce IPv6 two labels, capability absent",
			afi:    2,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0xb0, 0x00, 0x06, 0x40, 0x00, 0x00, 0x31}, vpnTestRD, []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00}),
			labels: []uint32{100},
			rd:     "12544:25600",
			cidr:   "0:120:10d:b800:100::/88",
		},
		{
			// A confirmed capability never falls back to a single label.
			name: "announce S=0 single label with multiple labels",
			afi:  1,
			ml:   base.MultiLabelConfirmed,
			nlri: vpnTestNLRI([]byte{0x78, 0x00, 0x3e, 0x80}, vpnTestRD, v4Prefix),
			fail: true,
		},
		{
			// RFC 8277 §2.2: on an announcement 0x000000 and 0x800000 are
			// labels (0 and 524288), not a compatibility marker.
			name:   "announce label 0x000000",
			afi:    1,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x00, 0x00}, vpnTestRD, v4Prefix),
			labels: []uint32{0},
		},
		{
			name:   "announce label 0x800000",
			afi:    1,
			nlri:   vpnTestNLRI([]byte{0x78, 0x80, 0x00, 0x00}, vpnTestRD, v4Prefix),
			labels: []uint32{0x80000},
		},
		{
			name:   "announce label 0x000000, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x78, 0x00, 0x00, 0x00}, vpnTestRD, v4Prefix),
			labels: []uint32{0},
		},
		{
			name:   "announce label 0x800000, capability absent",
			afi:    1,
			ml:     base.MultiLabelAbsent,
			nlri:   vpnTestNLRI([]byte{0x78, 0x80, 0x00, 0x00}, vpnTestRD, v4Prefix),
			labels: []uint32{0x80000},
		},
		{
			// RFC 8277 §2.2, RFC 7606 §3(j): an AFI 1 prefix longer than 32
			// bits is malformed, not capped.
			name: "announce IPv4 prefix of 64 bits",
			afi:  1,
			nlri: vpnTestNLRI([]byte{0x98, 0x00, 0x3e, 0x81}, vpnTestRD, v4Prefix, []byte{0x09, 0x09, 0x09, 0x09}),
			fail: true,
		},
		{
			name:     "withdraw IPv4 prefix of 64 bits",
			afi:      1,
			withdraw: true,
			nlri:     vpnTestNLRI([]byte{0x98, 0x80, 0x00, 0x00}, vpnTestRD, v4Prefix, []byte{0x09, 0x09, 0x09, 0x09}),
			fail:     true,
		},
		{
			name:   "announce IPv6 prefix of 128 bits",
			afi:    2,
			nlri:   vpnTestNLRI([]byte{0xd8, 0x00, 0x3e, 0x81}, vpnTestRD, make([]byte, 16)),
			labels: []uint32{1000},
		},
		{
			name: "announce IPv6 prefix of 136 bits",
			afi:  2,
			nlri: vpnTestNLRI([]byte{0xe0, 0x00, 0x3e, 0x81}, vpnTestRD, make([]byte, 17)),
			fail: true,
		},
		{
			name:     "withdraw IPv6 prefix of 136 bits",
			afi:      2,
			withdraw: true,
			nlri:     vpnTestNLRI([]byte{0xe0, 0x80, 0x00, 0x00}, vpnTestRD, make([]byte, 17)),
			fail:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeVPN(t, tt.afi, tt.withdraw, tt.ml, tt.nlri)
			if tt.fail {
				if err == nil {
					t.Fatalf("decoded %+v, want a malformed NLRI error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got.NLRI) != 1 {
				t.Fatalf("got %d NLRIs, want 1", len(got.NLRI))
			}
			r := got.NLRI[0]
			if len(r.Label) != len(tt.labels) {
				t.Fatalf("got %d labels, want %v", len(r.Label), tt.labels)
			}
			for i, l := range tt.labels {
				if r.Label[i].Value != l {
					t.Errorf("label[%d] = %d, want %d", i, r.Label[i].Value, l)
				}
			}
			wantRD := tt.rd
			if wantRD == "" {
				wantRD = "100:1"
			}
			if r.RD.String() != wantRD {
				t.Errorf("RD = %s, want %s", r.RD, wantRD)
			}
			if tt.afi == 1 && (r.Length != 32 || !net.IP(r.Prefix).Equal(net.IP(v4Prefix))) {
				t.Errorf("prefix = %v/%d, want 10.0.0.1/32", r.Prefix, r.Length)
			}
			if tt.cidr != "" {
				ip := make(net.IP, net.IPv6len)
				copy(ip, r.Prefix)
				if got := fmt.Sprintf("%s/%d", ip, r.Length); got != tt.cidr {
					t.Errorf("prefix = %s, want %s", got, tt.cidr)
				}
			}
		})
	}
}

// RFC 8277 §2.1: Count 0/1 triples are ignored, only the first triple per
// AFI/SAFI and the first copy of the capability count, and a length that is
// not a multiple of four is malformed.
func TestOpenMessageMultiLabelCapability(t *testing.T) {
	triple := func(afi byte, safi byte, count byte) []byte { return []byte{0x00, afi, safi, count} }
	tests := []struct {
		name string
		caps [][]byte
		want map[int]bool
	}{
		{name: "absent", want: map[int]bool{}},
		{
			name: "VPNv4 and labeled unicast v6",
			caps: [][]byte{vpnTestNLRI(triple(1, 128, 2), triple(2, 4, 255))},
			want: map[int]bool{NLRIMessageType(1, 128): true, NLRIMessageType(2, 4): true},
		},
		{
			name: "count 0 and 1 ignored",
			caps: [][]byte{vpnTestNLRI(triple(1, 128, 1), triple(2, 128, 0))},
			want: map[int]bool{NLRIMessageType(1, 128): false, NLRIMessageType(2, 128): false},
		},
		{
			name: "first triple per AFI/SAFI wins",
			caps: [][]byte{vpnTestNLRI(triple(1, 128, 3), triple(1, 128, 0))},
			want: map[int]bool{NLRIMessageType(1, 128): true},
		},
		{
			name: "only first copy significant",
			caps: [][]byte{triple(1, 128, 2), triple(1, 4, 2)},
			want: map[int]bool{NLRIMessageType(1, 128): true},
		},
		{name: "malformed length", caps: [][]byte{{0x00, 0x01, 0x80}}, want: map[int]bool{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OpenMessage{Capabilities: Capability{}}
			for _, c := range tt.caps {
				o.Capabilities[8] = append(o.Capabilities[8], &CapabilityData{Value: c})
			}
			got := o.MultiLabelCapability()
			if len(got) != len(tt.want) {
				t.Fatalf("MultiLabelCapability() = %v, want %v", got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("MultiLabelCapability()[%d] = %t, want %t", k, got[k], v)
				}
			}
		})
	}
}
