package srv6

import (
	"math"
	"testing"
)

// srv6L3ServiceTruncatedSubSubTLV is the value of a Prefix-SID SRv6 L3 Service
// TLV (RFC 9252 §2) whose SID Structure Sub-Sub-TLV header claims 16 bytes
// but carries none. It used to panic with an out-of-range slice.
var srv6L3ServiceTruncatedSubSubTLV = []byte{
	0x00,             // RESERVED
	0x01, 0x00, 0x18, // SID Information Sub-TLV, length 24
	0x00,                                                                                           // RESERVED1
	0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SID
	0x00, 0x00, 0x13, // Flags, Endpoint Behavior
	0x00,             // RESERVED2
	0x01, 0x00, 0x10, // SID Structure Sub-Sub-TLV, length 16, no value
}

func TestUnmarshalSRv6L3Service_TruncatedSubSubTLV(t *testing.T) {
	if _, err := UnmarshalSRv6L3Service(srv6L3ServiceTruncatedSubSubTLV); err == nil {
		t.Fatal("expected error for truncated sub-sub-TLV value")
	}
}

func TestUnmarshalSRv6L3ServiceSubSubTLV_Truncated(t *testing.T) {
	for name, b := range map[string][]byte{
		"value":  {0x00, 0x01, 0x00, 0x10},
		"header": {0x00, 0x01, 0x00},
		"type":   {0x00, 0x01},
	} {
		if _, err := UnmarshalSRv6L3ServiceSubSubTLV(b); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestUnmarshalSRv6L3Service_Empty(t *testing.T) {
	if _, err := UnmarshalSRv6L3Service(nil); err == nil {
		t.Fatal("expected error for empty L3 Service TLV")
	}
}

func TestUnmarshalSRv6SIDStructureTLV_InvalidLength(t *testing.T) {
	for _, n := range []int{0, 1, 3, 5} {
		if _, err := UnmarshalSRv6SIDStructureTLV(make([]byte, n)); err == nil {
			t.Errorf("len %d: expected error", n)
		}
	}
	st, err := UnmarshalSRv6SIDStructureTLV([]byte{32, 16, 16, 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LBLength != 32 || st.LNLength != 16 || st.FunLength != 16 || st.ArgLength != 0 {
		t.Fatalf("unexpected SID structure %+v", st)
	}
}

// End.X SID TLV carrying a zero-length SID Structure sub-TLV (1252).
func TestUnmarshalSRv6EndXSIDTLV_EmptySIDStructure(t *testing.T) {
	b := []byte{
		0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x04, 0xe4, 0x00, 0x00,
	}
	if _, err := UnmarshalSRv6EndXSIDTLV(b); err == nil {
		t.Fatal("expected error for empty SID Structure sub-TLV")
	}
}

// A sub-TLV length near math.MaxUint16 would wrap the stored Length (l+4) and
// stall UnmarshalAllSRv6SubTLV's cursor.
func TestUnmarshalSRv6SubTLV_LengthWrap(t *testing.T) {
	l := math.MaxUint16 - 3
	b := make([]byte, 4+l)
	b[0], b[1] = 0x00, 0x01
	b[2], b[3] = byte(l>>8), byte(l)
	if _, err := UnmarshalAllSRv6SubTLV(b); err == nil {
		t.Fatal("expected error for wrapping sub-TLV length")
	}
}
