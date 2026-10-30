package bgp

import (
	"errors"
	"net"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/l3vpn"
)

// BGP Classful Transport (RFC 9832) wire-format tests. Per RFC 9832 §6.1 the
// NLRI follows RFC 8277 §2: [Path ID (4), RFC 7911] Length (1, bits after
// itself), Label(s) (3 each, S bit set on the last), RD (8), Prefix.

// ctV4NLRI holds two NLRIs:
//
//	0x78                      Length 120 = 24 label + 64 RD + 32 prefix
//	0x00 0x3e 0x81            Label 1000, S=1
//	0x00 0x00 0x00 0x64 ...   RD type 0, 100:1
//	0x0a 0x00 0x00 0x01       10.0.0.1/32
//
//	0x70                      Length 112 = 24 + 64 + 24
//	0x00 0x3e 0x91            Label 1001, S=1
//	0x00 0x00 0x00 0x64 ...   RD type 0, 100:1
//	0x0a 0x01 0x02            10.1.2.0/24
var ctV4NLRI = []byte{
	0x78,
	0x00, 0x3e, 0x81,
	0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
	0x0a, 0x00, 0x00, 0x01,
	0x70,
	0x00, 0x3e, 0x91,
	0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
	0x0a, 0x01, 0x02,
}

// ctMPReach builds an MP_REACH_NLRI attribute value (RFC 4760 §3).
func ctMPReach(afi byte, nh []byte, nlri []byte) []byte {
	b := []byte{0x00, afi, SAFIClassfulTransport, byte(len(nh))}
	b = append(b, nh...)
	b = append(b, 0x00) // Reserved
	return append(b, nlri...)
}

// ctMPUnreach builds an MP_UNREACH_NLRI attribute value (RFC 4760 §4).
func ctMPUnreach(afi byte, withdrawn []byte) []byte {
	return append([]byte{0x00, afi, SAFIClassfulTransport}, withdrawn...)
}

func decodeCTReach(t *testing.T, attr []byte, pathIDs base.PathIDState) (MPNLRI, *base.MPNLRI) {
	t.Helper()
	mp, err := UnmarshalMPReachNLRI(attr, false)
	if err != nil {
		t.Fatalf("UnmarshalMPReachNLRI() error: %v", err)
	}
	mp.(*MPReachNLRI).PathIDs = pathIDs
	nlri, err := mp.GetNLRICT()
	if err != nil {
		t.Fatalf("GetNLRICT() error: %v", err)
	}
	return mp, nlri
}

func checkCTRoute(t *testing.T, r base.Route, pathID uint32, labels []uint32, rd string, prefix net.IP, length uint8) {
	t.Helper()
	if r.PathID != pathID {
		t.Errorf("PathID = %d, want %d", r.PathID, pathID)
	}
	if len(r.Label) != len(labels) {
		t.Fatalf("got %d labels, want %d", len(r.Label), len(labels))
	}
	for i, l := range labels {
		if r.Label[i].Value != l {
			t.Errorf("label[%d] = %d, want %d", i, r.Label[i].Value, l)
		}
	}
	if got := r.RD.String(); got != rd {
		t.Errorf("RD = %s, want %s", got, rd)
	}
	if r.Length != length {
		t.Errorf("prefix length = %d, want %d", r.Length, length)
	}
	p := make(net.IP, len(prefix))
	copy(p, r.Prefix)
	if !p.Equal(prefix) {
		t.Errorf("prefix = %s, want %s", p, prefix)
	}
}

func TestNLRIMessageTypeClassfulTransport(t *testing.T) {
	if got := NLRIMessageType(1, 76); got != 38 {
		t.Errorf("NLRIMessageType(1, 76) = %d, want 38", got)
	}
	if got := NLRIMessageType(2, 76); got != 39 {
		t.Errorf("NLRIMessageType(2, 76) = %d, want 39", got)
	}
}

func TestGetNLRICTIPv4Reach(t *testing.T) {
	mp, nlri := decodeCTReach(t, ctMPReach(1, []byte{192, 0, 2, 1}, ctV4NLRI), base.PathIDUnknown)
	if mp.GetAFISAFIType() != 38 || mp.IsIPv6NLRI() {
		t.Fatalf("AFI/SAFI type = %d, IPv6 = %t, want 38, false", mp.GetAFISAFIType(), mp.IsIPv6NLRI())
	}
	if got := mp.GetNextHop(); got != "192.0.2.1" {
		t.Errorf("next hop = %s, want 192.0.2.1", got)
	}
	if len(nlri.NLRI) != 2 {
		t.Fatalf("got %d NLRIs, want 2", len(nlri.NLRI))
	}
	checkCTRoute(t, nlri.NLRI[0], 0, []uint32{1000}, "100:1", net.IP{10, 0, 0, 1}, 32)
	checkCTRoute(t, nlri.NLRI[1], 0, []uint32{1001}, "100:1", net.IP{10, 1, 2}, 24)
}

func TestGetNLRICTIPv6Reach(t *testing.T) {
	nh := net.ParseIP("2001:db8::1").To16()
	nlri := []byte{
		0xd8,             // Length 216 = 24 label + 64 RD + 128 prefix
		0x00, 0x7d, 0x01, // Label 2000, S=1
		0x00, 0x01, 0xc0, 0x00, 0x02, 0x01, 0x00, 0x07, // RD type 1, 192.0.2.1:7
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, // 2001:db8::5/128
	}
	mp, got := decodeCTReach(t, ctMPReach(2, nh, nlri), base.PathIDUnknown)
	if mp.GetAFISAFIType() != 39 || !mp.IsIPv6NLRI() || !mp.IsNextHopIPv6() {
		t.Fatalf("AFI/SAFI type = %d, IPv6 NLRI = %t, IPv6 NH = %t", mp.GetAFISAFIType(), mp.IsIPv6NLRI(), mp.IsNextHopIPv6())
	}
	if len(got.NLRI) != 1 {
		t.Fatalf("got %d NLRIs, want 1", len(got.NLRI))
	}
	checkCTRoute(t, got.NLRI[0], 0, []uint32{2000}, "192.0.2.1:7", net.ParseIP("2001:db8::5"), 128)
}

// RFC 8277 §2.2 / RFC 7911 §3: with ADD-PATH a 4-octet Path Identifier
// precedes the Length field. RFC 9832 §7.6 recommends ADD-PATH for BGP CT.
func TestGetNLRICTAddPath(t *testing.T) {
	nlri := append([]byte{0x00, 0x00, 0x00, 0x05}, ctV4NLRI[:16]...)
	_, got := decodeCTReach(t, ctMPReach(1, []byte{192, 0, 2, 1}, nlri), base.PathIDPresent)
	if len(got.NLRI) != 1 {
		t.Fatalf("got %d NLRIs, want 1", len(got.NLRI))
	}
	checkCTRoute(t, got.NLRI[0], 5, []uint32{1000}, "100:1", net.IP{10, 0, 0, 1}, 32)

	unreach, err := UnmarshalMPUnReachNLRI(ctMPUnreach(1, []byte{
		0x00, 0x00, 0x00, 0x05, // Path ID 5
		0x78, 0x80, 0x00, 0x00, // Length 120, Compatibility 0x800000
		0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01,
		0x0a, 0x00, 0x00, 0x01,
	}))
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI() error: %v", err)
	}
	unreach.(*MPUnReachNLRI).PathIDs = base.PathIDPresent
	w, err := unreach.GetNLRICT()
	if err != nil {
		t.Fatalf("GetNLRICT() error: %v", err)
	}
	checkCTRoute(t, w.NLRI[0], 5, nil, "100:1", net.IP{10, 0, 0, 1}, 32)
}

// RFC 8277 §2.4: the withdrawal Compatibility field SHOULD be 0x800000, some
// implementations send 0x000000, and it MUST be ignored on reception.
func TestGetNLRICTWithdraw(t *testing.T) {
	for _, compat := range [][]byte{{0x80, 0x00, 0x00}, {0x00, 0x00, 0x00}} {
		withdrawn := append([]byte{0x78}, compat...)
		withdrawn = append(withdrawn, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01)
		mp, err := UnmarshalMPUnReachNLRI(ctMPUnreach(1, withdrawn))
		if err != nil {
			t.Fatalf("UnmarshalMPUnReachNLRI() error: %v", err)
		}
		if mp.GetAFISAFIType() != 38 {
			t.Fatalf("AFI/SAFI type = %d, want 38", mp.GetAFISAFIType())
		}
		got, err := mp.GetNLRICT()
		if err != nil {
			t.Fatalf("compat %x: GetNLRICT() error: %v", compat, err)
		}
		if len(got.NLRI) != 1 {
			t.Fatalf("compat %x: got %d NLRIs, want 1", compat, len(got.NLRI))
		}
		checkCTRoute(t, got.NLRI[0], 0, nil, "100:1", net.IP{10, 0, 0, 1}, 32)
	}
}

// An MP_UNREACH_NLRI with no withdrawn routes is the End-of-RIB marker
// (RFC 4724 §2).
func TestGetNLRICTEndOfRIB(t *testing.T) {
	mp, err := UnmarshalMPUnReachNLRI(ctMPUnreach(2, nil))
	if err != nil {
		t.Fatalf("UnmarshalMPUnReachNLRI() error: %v", err)
	}
	if _, err := mp.GetNLRICT(); !errors.Is(err, l3vpn.ErrEmptyNLRI) {
		t.Fatalf("GetNLRICT() error = %v, want l3vpn.ErrEmptyNLRI", err)
	}
}

// RFC 9832 §6.2 allows next hop lengths 4, 12, 16, 24, 32 and 48 only.
func TestGetNLRICTNextHop(t *testing.T) {
	v6 := net.ParseIP("2001:db8::1").To16()
	ll := net.ParseIP("fe80::1").To16()
	rd0 := make([]byte, 8)
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	tests := []struct {
		name string
		nh   []byte
		want string
		ipv6 bool
		fail bool
	}{
		{name: "IPv4", nh: []byte{192, 0, 2, 1}, want: "192.0.2.1"},
		{name: "VPN-IPv4", nh: cat(rd0, []byte{192, 0, 2, 1}), want: "192.0.2.1"},
		{name: "IPv6", nh: v6, want: "2001:db8::1", ipv6: true},
		{name: "IPv6 and link-local", nh: cat(v6, ll), want: "2001:db8::1,fe80::1", ipv6: true},
		{name: "VPN-IPv6", nh: cat(rd0, v6), want: "2001:db8::1", ipv6: true},
		{name: "VPN-IPv6 and link-local", nh: cat(rd0, v6, rd0, ll), want: "2001:db8::1,fe80::1", ipv6: true},
		{name: "length 8", nh: make([]byte, 8), fail: true},
		{name: "length 20", nh: make([]byte, 20), fail: true},
		{name: "length 0", nh: nil, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mp, err := UnmarshalMPReachNLRI(ctMPReach(1, tt.nh, ctV4NLRI), false)
			if err != nil {
				t.Fatalf("UnmarshalMPReachNLRI() error: %v", err)
			}
			_, err = mp.GetNLRICT()
			if tt.fail {
				if err == nil {
					t.Fatal("GetNLRICT() expected an error for an invalid next hop length")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetNLRICT() error: %v", err)
			}
			if got := mp.GetNextHop(); got != tt.want {
				t.Errorf("GetNextHop() = %s, want %s", got, tt.want)
			}
			if got := mp.IsNextHopIPv6(); got != tt.ipv6 {
				t.Errorf("IsNextHopIPv6() = %t, want %t", got, tt.ipv6)
			}
		})
	}
}

func TestGetNLRICTMalformed(t *testing.T) {
	tests := []struct {
		name string
		nlri []byte
	}{
		{name: "length only", nlri: []byte{0x78}},
		{name: "truncated label", nlri: []byte{0x78, 0x00, 0x3e}},
		{name: "truncated RD", nlri: []byte{0x78, 0x00, 0x3e, 0x81, 0x00, 0x00, 0x00}},
		{name: "truncated prefix", nlri: ctV4NLRI[:14]},
		{name: "label stack without S bit", nlri: []byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x80}},
		{name: "zero length", nlri: []byte{0x00}},
		{name: "prefix longer than 128 bits", nlri: append([]byte{0xff, 0x00, 0x3e, 0x81}, make([]byte, 29)...)},
		{name: "length shorter than label and RD", nlri: []byte{0x20, 0x00, 0x3e, 0x81, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reach, err := UnmarshalMPReachNLRI(ctMPReach(1, []byte{192, 0, 2, 1}, tt.nlri), false)
			if err != nil {
				t.Fatalf("UnmarshalMPReachNLRI() error: %v", err)
			}
			if got, err := reach.GetNLRICT(); err == nil {
				t.Errorf("MP_REACH GetNLRICT() = %+v, want an error", got)
			}
			unreach, err := UnmarshalMPUnReachNLRI(ctMPUnreach(1, tt.nlri))
			if err != nil {
				t.Fatalf("UnmarshalMPUnReachNLRI() error: %v", err)
			}
			if got, err := unreach.GetNLRICT(); err == nil {
				t.Errorf("MP_UNREACH GetNLRICT() = %+v, want an error", got)
			}
		})
	}
}

func TestGetNLRICTWrongSAFI(t *testing.T) {
	var nf *NLRINotFoundError
	reach := &MPReachNLRI{AddressFamilyID: 1, SubAddressFamilyID: 128, NextHopAddressLength: 4, NLRI: ctV4NLRI}
	if _, err := reach.GetNLRICT(); !errors.As(err, &nf) {
		t.Errorf("MP_REACH GetNLRICT() error = %v, want NLRINotFoundError", err)
	}
	unreach := &MPUnReachNLRI{AddressFamilyID: 25, SubAddressFamilyID: 76, WithdrawnRoutes: ctV4NLRI}
	if _, err := unreach.GetNLRICT(); !errors.As(err, &nf) {
		t.Errorf("MP_UNREACH GetNLRICT() error = %v, want NLRINotFoundError", err)
	}
}

// RFC 9832 §4.3 Figure 2 and §13.2: Type 0x0a (transitive) or 0x4a
// (non-transitive), Sub-Type 0x02, 2-octet Reserved, 4-octet Transport Class ID.
func TestTransportClassExtCommunity(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want string
	}{
		{name: "transitive TC RT 100", b: []byte{0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}, want: "transport-target=0:100"},
		{name: "best-effort TC RT 0", b: []byte{0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, want: "transport-target=0:0"},
		{name: "max TC ID, reserved kept", b: []byte{0x0a, 0x02, 0x00, 0x01, 0xff, 0xff, 0xff, 0xff}, want: "transport-target=1:4294967295"},
		{name: "non-transitive TC RT 200", b: []byte{0x4a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8}, want: "nt-transport-target=0:200"},
		{name: "unknown sub-type", b: []byte{0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, want: "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exts, err := UnmarshalBGPExtCommunity(tt.b)
			if err != nil {
				t.Fatalf("UnmarshalBGPExtCommunity() error: %v", err)
			}
			if len(exts) != 1 {
				t.Fatalf("got %d communities, want 1", len(exts))
			}
			if got := exts[0].String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
			if got, want := exts[0].IsRouteTarget(), tt.b[1] == 0x02; got != want {
				t.Errorf("IsRouteTarget() = %t, want %t", got, want)
			}
		})
	}
}
