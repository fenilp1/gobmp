package bgp

import (
	"bytes"
	"testing"
)

// srv6ServiceTLV returns an SRv6 Service TLV (RFC 9252 §2) of the given type
// with one SRv6 SID Information Sub-TLV (§3.1) per entry of structures; an
// entry, when not nil, is the 6-octet value of that Sub-TLV's SRv6 SID
// Structure Sub-Sub-TLV (§3.2.1).
func srv6ServiceTLV(tlvType byte, structures ...[]byte) []byte {
	v := []byte{0x00} // Reserved
	for _, structure := range structures {
		info := make([]byte, 21) // Reserved1, SID, Flags, Endpoint Behavior, Reserved2
		info[1], info[2] = 0x20, 0x01
		if structure != nil {
			info = append(info, 0x01, 0x00, byte(len(structure)))
			info = append(info, structure...)
		}
		v = append(v, 0x01, 0x00, byte(len(info)))
		v = append(v, info...)
	}
	return append([]byte{tlvType, 0x00, byte(len(v))}, v...)
}

func cat(b ...[]byte) []byte {
	var out []byte
	for _, x := range b {
		out = append(out, x...)
	}
	return out
}

var (
	tLabelIndex = []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	tSRGB       = []byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40}
	tTL16       = []byte{0x28, 0x18, 0x10, 0x00, 0x10, 0x40} // LBL 40, LNL 24, FL 16, AL 0, TL 16, TO 64
	tTL0        = []byte{0x28, 0x18, 0x10, 0x00, 0x00, 0x00} // TL 0, TO 0
)

func TestHasSRv6Transposition(t *testing.T) {
	l3TL16 := srv6ServiceTLV(5, tTL16)
	l3TL0 := srv6ServiceTLV(5, tTL0)
	psid := func(b ...[]byte) []PathAttribute {
		return []PathAttribute{{AttributeType: 40, Attribute: cat(b...)}}
	}
	tests := []struct {
		name  string
		attrs []PathAttribute
		want  bool
	}{
		{name: "no Prefix-SID", want: false},
		{name: "Label-Index only", attrs: psid(tLabelIndex), want: false},
		{name: "Label-Index and Originator SRGB", attrs: psid(tLabelIndex, tSRGB), want: false},
		{name: "L3 Service, TL 16", attrs: psid(l3TL16), want: true},
		{name: "Label-Index then L3 Service, TL 16", attrs: psid(tLabelIndex, l3TL16), want: true},
		{name: "L3 Service, TL 0", attrs: psid(l3TL0), want: false},
		{name: "L3 Service, no SID Structure", attrs: psid(srv6ServiceTLV(5, nil)), want: false},
		{name: "L3 Service, short SID Structure", attrs: psid(srv6ServiceTLV(5, []byte{0x28, 0x18, 0x10, 0x00, 0x10})), want: false},
		{name: "L3 Service, unknown Sub-Sub-TLV before SID Structure", attrs: psid(func() []byte {
			info := cat(make([]byte, 21), []byte{0x02, 0x00, 0x01, 0xff}, []byte{0x01, 0x00, 0x06}, tTL16)
			v := cat([]byte{0x00, 0x01, 0x00, byte(len(info))}, info)
			return cat([]byte{0x05, 0x00, byte(len(v))}, v)
		}()), want: true},
		// RFC 9252 §2: the L2 Service TLV is for EVPN, not L3 routes.
		{name: "L2 Service only, TL 16", attrs: psid(srv6ServiceTLV(6, tTL16)), want: false},
		{name: "L2 Service TL 16, then L3 Service TL 0", attrs: psid(srv6ServiceTLV(6, tTL16), l3TL0), want: false},
		// RFC 9252 §7: all but the first L3 Service TLV are ignored.
		{name: "first L3 Service TL 0, second TL 16", attrs: psid(l3TL0, l3TL16), want: false},
		{name: "first L3 Service TL 16, second TL 0", attrs: psid(l3TL16, l3TL0), want: true},
		// RFC 9252 §3.1: the first SID Information Sub-TLV is used.
		{name: "first SID Information TL 0, second TL 16", attrs: psid(srv6ServiceTLV(5, tTL0, tTL16)), want: false},
		{name: "first SID Information TL 16, second TL 0", attrs: psid(srv6ServiceTLV(5, tTL16, tTL0)), want: true},
		// RFC 8669 §6: all but the first Prefix-SID attribute are discarded.
		{name: "second Prefix-SID attribute ignored", attrs: []PathAttribute{
			{AttributeType: 40, Attribute: tLabelIndex},
			{AttributeType: 40, Attribute: l3TL16},
		}, want: false},
		{name: "SID Structure bytes outside a Prefix-SID", attrs: []PathAttribute{{AttributeType: 41, Attribute: l3TL16}}, want: false},
		// RFC 9252 §7, RFC 8669 §6: a malformed attribute is not used.
		{name: "valid L3 Service TL 16, truncated second TLV", attrs: psid(l3TL16, []byte{0x05, 0x00, 0x40, 0x00}), want: false},
		{name: "valid L3 Service TL 16, trailing octets", attrs: psid(l3TL16, []byte{0x01, 0x00}), want: false},
		{name: "valid L3 Service TL 16, empty L2 Service TLV", attrs: psid(l3TL16, []byte{0x06, 0x00, 0x00}), want: false},
		{name: "valid L3 Service TL 16, Label-Index TLV past the end", attrs: psid(l3TL16, []byte{0x01, 0x00, 0x08, 0x00}), want: false},
		// RFC 8669 §6 with §3.1 "Length: 7" and §3.2 "Length: ... 2 +
		// (non-zero multiple of 6)".
		{name: "Label-Index length 8, then L3 Service TL 16", attrs: psid([]byte{0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00}, l3TL16), want: false},
		{name: "L3 Service TL 16, then Label-Index length 6", attrs: psid(l3TL16, []byte{0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}), want: false},
		{name: "Originator SRGB length 2 (no SRGB), then L3 Service TL 16", attrs: psid([]byte{0x03, 0x00, 0x02, 0x00, 0x00}, l3TL16), want: false},
		{name: "Originator SRGB length 9, then L3 Service TL 16", attrs: psid([]byte{0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40, 0x00}, l3TL16), want: false},
		{name: "Originator SRGB with two SRGBs, then L3 Service TL 16", attrs: psid([]byte{0x03, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40, 0x01, 0x86, 0xa0, 0x00, 0x03, 0xe8}, l3TL16), want: true},
		{name: "Label-Index and Originator SRGB, then L3 Service TL 16", attrs: psid(tLabelIndex, tSRGB, l3TL16), want: true},
		{name: "SID Information shorter than 21 octets", attrs: psid([]byte{0x05, 0x00, 0x18, 0x00, 0x01, 0x00, 0x14}, make([]byte, 20)), want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			up := &Update{PathAttributes: tt.attrs}
			if got := up.HasSRv6Transposition(); got != tt.want {
				t.Errorf("HasSRv6Transposition() = %t, want %t", got, tt.want)
			}
		})
	}
}

// The duplicate L3 Service TLV repro, octet for octet.
func TestHasSRv6TranspositionDuplicateL3ServiceWire(t *testing.T) {
	info := make([]byte, 21)
	first := cat([]byte{0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e}, info, []byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x00, 0x00})
	second := cat([]byte{0x05, 0x00, 0x22, 0x00, 0x01, 0x00, 0x1e}, info, []byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40})
	if !bytes.Equal(first[:7], srv6ServiceTLV(5, tTL0)[:7]) || len(first) != len(srv6ServiceTLV(5, tTL0)) {
		t.Fatalf("test vector framing differs from srv6ServiceTLV")
	}
	up := &Update{PathAttributes: []PathAttribute{{AttributeType: 40, Attribute: cat(first, second)}}}
	if up.HasSRv6Transposition() {
		t.Errorf("HasSRv6Transposition() = true, want false: the first L3 Service TLV has TL 0")
	}
	up = &Update{PathAttributes: []PathAttribute{{AttributeType: 40, Attribute: second}}}
	if !up.HasSRv6Transposition() {
		t.Errorf("HasSRv6Transposition() = false, want true for the TL 16 TLV alone")
	}
}

// Every truncation of a transposing Prefix-SID breaks its framing, so it is
// decoded without a panic and never reported as transposing.
func TestHasSRv6TranspositionTruncated(t *testing.T) {
	b := cat(tLabelIndex, srv6ServiceTLV(5, tTL16))
	for n := 0; n < len(b); n++ {
		up := &Update{PathAttributes: []PathAttribute{{AttributeType: 40, Attribute: b[:n]}}}
		if up.HasSRv6Transposition() {
			t.Errorf("HasSRv6Transposition() = true for %d of %d octets", n, len(b))
		}
	}
}

func TestHasSRv6TranspositionAllocs(t *testing.T) {
	up := &Update{PathAttributes: []PathAttribute{{AttributeType: 40, Attribute: cat(tLabelIndex, srv6ServiceTLV(5, tTL0, tTL16), srv6ServiceTLV(6, tTL16))}}}
	if n := testing.AllocsPerRun(100, func() { up.HasSRv6Transposition() }); n != 0 {
		t.Errorf("HasSRv6Transposition() allocates %v times, want 0", n)
	}
}
