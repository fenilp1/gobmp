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

var testSID = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

// srv6L3ServiceTLV builds an SRv6 L3 Service TLV (RFC 9252 §2) with one SID
// Information Sub-TLV carrying the given Sub-Sub-TLV bytes.
func srv6L3ServiceTLV(subsub []byte) []byte {
	sub := append(append([]byte{0x00}, testSID...), 0x00, 0x00, 0x13, 0x00)
	sub = append(sub, subsub...)
	tlv := []byte{0x05, 0, byte(4 + len(sub)), 0x00, 0x01, 0, byte(len(sub))}
	return append(tlv, sub...)
}

// A SID Structure Sub-Sub-TLV of length 7 is not malformed per RFC 9252 §7,
// so it must not discard the whole Prefix-SID, including a valid Label-Index.
func TestUnmarshalBGPAttrPrefixSID_LongSIDStructureKept(t *testing.T) {
	b := append([]byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64},
		srv6L3ServiceTLV([]byte{0x01, 0x00, 0x07, 0x28, 0x18, 0x10, 0x00, 0x10, 0x40, 0x00})...)
	psid, err := UnmarshalBGPAttrPrefixSID(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if psid.LabelIndex == nil || psid.LabelIndex.LabelIndex != 100 {
		t.Fatalf("Label-Index lost: %+v", psid.LabelIndex)
	}
	if psid.SRv6L3Service == nil {
		t.Fatal("SRv6 L3 Service lost")
	}
}

// RFC 8669 §6: only the first Label-Index TLV is used.
func TestUnmarshalBGPAttrPrefixSID_DuplicateLabelIndex(t *testing.T) {
	first := []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	for name, second := range map[string][]byte{
		"valid":     {0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8},
		"malformed": {0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8},
	} {
		psid, err := UnmarshalBGPAttrPrefixSID(append(append([]byte(nil), first...), second...))
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", name, err)
		}
		if psid.LabelIndex.LabelIndex != 100 {
			t.Errorf("%s: LabelIndex = %d, want 100", name, psid.LabelIndex.LabelIndex)
		}
	}
}

// RFC 9252 §7: all but the first SRv6 L3 Service TLV are ignored, so a
// malformed second one must not discard the first.
func TestUnmarshalBGPAttrPrefixSID_DuplicateSRv6L3Service(t *testing.T) {
	good := srv6L3ServiceTLV([]byte{0x01, 0x00, 0x06, 0x28, 0x18, 0x10, 0x00, 0x00, 0x00})
	bad := srv6L3ServiceTLV([]byte{0x01, 0x00, 0x10})
	psid, err := UnmarshalBGPAttrPrefixSID(append(append([]byte(nil), good...), bad...))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if psid.SRv6L3Service == nil || len(psid.SRv6L3Service.SubTLVs[1]) != 1 {
		t.Fatalf("SRv6 L3 Service = %+v, want the first instance", psid.SRv6L3Service)
	}
	if _, err := UnmarshalBGPAttrPrefixSID(bad); err == nil {
		t.Fatal("a malformed SRv6 L3 Service on its own must still be rejected")
	}
}
