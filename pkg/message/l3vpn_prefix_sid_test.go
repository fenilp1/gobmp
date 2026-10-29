package message

import (
	"encoding/json"
	"reflect"
	"testing"
)

// prefixSIDAttr returns a BGP Prefix-SID path attribute (type 40, RFC 8669 §3)
// carrying the given TLVs.
func prefixSIDAttr(tlvs ...[]byte) []byte {
	var v []byte
	for _, tlv := range tlvs {
		v = append(v, tlv...)
	}
	return append([]byte{0xc0, 0x28, byte(len(v))}, v...)
}

var (
	// RFC 8669 §3.1 Label-Index TLV: Type 1, Length 7, Reserved, Flags 0,
	// Label Index 100.
	psidLabelIndex = []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	// RFC 8669 §3.2 Originator SRGB TLV: Type 3, Length 8, Flags 0, one SRGB
	// 16000 + 8000.
	psidOriginatorSRGB = []byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40}
)

// psidSRv6L3Service returns an RFC 9252 §2 SRv6 L3 Service TLV (type 5)
// holding one SRv6 SID Information Sub-TLV (§3.1) for End.DT4 SID
// 2001:db8:1:1:: with, when structure is set, an SRv6 SID Structure
// Sub-Sub-TLV (§3.2.1) of LBL 40, LNL 24, FL 16, AL 0 and the given
// Transposition Length and Offset.
func psidSRv6L3Service(structure bool, tl, to byte) []byte {
	info := []byte{0x00} // Reserved1
	info = append(info, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0)
	info = append(info, 0x00, 0x00, 0x13, 0x00) // Flags, End.DT4 (19), Reserved2
	if structure {
		info = append(info, 0x01, 0x00, 0x06, 40, 24, 16, 0, tl, to)
	}
	v := []byte{0x00, 0x01, 0x00, byte(len(info))} // Reserved, Sub-TLV type 1
	v = append(v, info...)
	return append([]byte{0x05, 0x00, byte(len(v))}, v...)
}

// The label field of an L3VPN route carries SRv6 SID bits only when the
// Transposition Scheme is in use (RFC 9252 §4, §5.1): an SRv6 Service TLV
// whose SID Structure has a non-zero Transposition Length. A Prefix-SID with
// only SR-MPLS TLVs (RFC 8669), or an SRv6 SID sent whole, leaves an
// RFC 8277 MPLS label there.
func TestL3VPNLabelWithPrefixSID(t *testing.T) {
	vpnv4 := func(label ...byte) []byte {
		return l3vpnTestAttr(0x0e, 1, []byte{192, 0, 2, 1}, append(append([]byte{0x78}, label...),
			0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, // RD 100:1
			0x0a, 0x00, 0x00, 0x01, // 10.0.0.1/32
		))
	}
	tests := []struct {
		name string
		psid []byte
		nlri []byte
		want []uint32
	}{
		{
			name: "SR-MPLS Label-Index only",
			psid: prefixSIDAttr(psidLabelIndex),
			nlri: vpnv4(0x00, 0x3e, 0x81), // Label 1000, S=1
			want: []uint32{1000},
		},
		{
			name: "SR-MPLS Label-Index and Originator SRGB",
			psid: prefixSIDAttr(psidLabelIndex, psidOriginatorSRGB),
			nlri: vpnv4(0x00, 0x3e, 0x81),
			want: []uint32{1000},
		},
		{
			name: "SRv6 L3 Service, Transposition Length 16",
			psid: prefixSIDAttr(psidSRv6L3Service(true, 16, 64)),
			nlri: vpnv4(0x12, 0x34, 0x50), // transposed Function bits, no S bit
			want: []uint32{0x123450},
		},
		{
			name: "SRv6 L3 Service, Transposition Length 0",
			psid: prefixSIDAttr(psidSRv6L3Service(true, 0, 0)),
			nlri: vpnv4(0x00, 0x00, 0x31), // Implicit NULL, S=1
			want: []uint32{3},
		},
		{
			name: "SRv6 L3 Service without SID Structure",
			psid: prefixSIDAttr(psidSRv6L3Service(false, 0, 0)),
			nlri: vpnv4(0x00, 0x00, 0x31),
			want: []uint32{3},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgs := publishCT(t, false, ctTestUpdate(t, append(tt.psid, tt.nlri...), ctTestRT))
			if len(msgs) != 1 {
				t.Fatalf("published %d messages, want 1", len(msgs))
			}
			var got L3VPNPrefix
			if err := json.Unmarshal(msgs[0].payload, &got); err != nil {
				t.Fatalf("json.Unmarshal() error: %v", err)
			}
			if !reflect.DeepEqual(got.Labels, tt.want) {
				t.Errorf("labels = %v, want %v", got.Labels, tt.want)
			}
			if got.PrefixSID == nil {
				t.Errorf("prefix_sid missing from published message")
			}
		})
	}
}
