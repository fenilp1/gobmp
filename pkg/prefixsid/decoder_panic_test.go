package prefixsid

import "testing"

// Prefix-SID attribute with an SRv6 L3 Service TLV whose SID Structure
// Sub-Sub-TLV header claims 16 bytes but carries none (RFC 9252 §7).
// It used to panic with an out-of-range slice.
func TestUnmarshalBGPAttrPrefixSID_TruncatedSRv6SubSubTLV(t *testing.T) {
	b := []byte{
		0x05, 0x00, 0x1c, 0x00,
		0x01, 0x00, 0x18, 0x00,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x13, 0x00,
		0x01, 0x00, 0x10,
	}
	if _, err := UnmarshalBGPAttrPrefixSID(b); err == nil {
		t.Fatal("expected error for truncated SRv6 sub-sub-TLV")
	}
}

// RFC 8669 §3.1: Label-Index TLV length is 7. A different length used to be
// ignored, desynchronizing the parse of the following TLVs.
func TestUnmarshalBGPAttrPrefixSID_LabelIndexBadLength(t *testing.T) {
	b := []byte{0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x00}
	if _, err := UnmarshalBGPAttrPrefixSID(b); err == nil {
		t.Fatal("expected error for Label-Index TLV length 8")
	}
}
