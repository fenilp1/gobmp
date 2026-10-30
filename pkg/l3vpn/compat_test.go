package l3vpn

import (
	"reflect"
	"testing"
)

// UnmarshalL3VPNNLRI keeps its signature and decodes like
// UnmarshalL3VPNNLRIWithOptions with PathID and SRv6 set and nothing else,
// but for the Compatibility field values; see TestUnmarshalL3VPNNLRICompatMarkers.
func TestUnmarshalL3VPNNLRICompat(t *testing.T) {
	rd := []byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01} // RD 100:1
	nlri := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	tests := []struct {
		name   string
		b      []byte
		pathID bool
		srv6   []bool
	}{
		{name: "one label", b: nlri([]byte{0x78, 0x00, 0x3e, 0x81}, rd, []byte{10, 0, 0, 1})},
		{name: "two labels", b: nlri([]byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, rd, []byte{10, 0, 0, 1})},
		{name: "Path ID flipped", pathID: true, b: nlri([]byte{0x78, 0x00, 0x3e, 0x81}, rd, []byte{10, 0, 0, 1})},
		{name: "Path ID", pathID: true, b: nlri([]byte{0, 0, 0, 7, 0x78, 0x00, 0x3e, 0x81}, rd, []byte{10, 0, 0, 1})},
		{name: "SRv6", srv6: []bool{true}, b: nlri([]byte{0x78, 0x12, 0x34, 0x50}, rd, []byte{10, 0, 0, 1})},
		{name: "IPv6 prefix", b: nlri([]byte{0xd8, 0x00, 0x3e, 0x81}, rd, make([]byte, 16))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalL3VPNNLRI(tt.b, tt.pathID, tt.srv6...)
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRI() error: %v", err)
			}
			want, err := UnmarshalL3VPNNLRIWithOptions(tt.b, Options{PathID: tt.pathID, SRv6: len(tt.srv6) == 1 && tt.srv6[0]})
			if err != nil {
				t.Fatalf("UnmarshalL3VPNNLRIWithOptions() error: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("UnmarshalL3VPNNLRI() = %+v, want %+v", got, want)
			}
		})
	}
}

// UnmarshalL3VPNNLRI, which does not know whether it decodes an
// announcement or a withdrawal, reads a 0x800000 or 0x000000 label field
// as the Compatibility field (RFC 8277 §2.4), as before;
// UnmarshalL3VPNNLRIWithOptions reads it as a label on an announcement
// (§2.2).
func TestUnmarshalL3VPNNLRICompatMarkers(t *testing.T) {
	rd := []byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01} // RD 100:1
	for _, tt := range []struct {
		field []byte
		label uint32
	}{{[]byte{0x80, 0x00, 0x00}, 0x80000}, {[]byte{0x00, 0x00, 0x00}, 0}} {
		b := append(append(append([]byte{0x78}, tt.field...), rd...), 10, 0, 0, 1)
		got, err := UnmarshalL3VPNNLRI(b, false)
		if err != nil || len(got.NLRI) != 1 || got.NLRI[0].Label != nil || got.NLRI[0].Length != 32 {
			t.Errorf("UnmarshalL3VPNNLRI(%x) = %+v, %v, want 10.0.0.1/32 with no label", tt.field, got, err)
		}
		got, err = UnmarshalL3VPNNLRIWithOptions(b, Options{AFI: 1})
		if err != nil || len(got.NLRI) != 1 || len(got.NLRI[0].Label) != 1 || got.NLRI[0].Label[0].Value != tt.label {
			t.Errorf("UnmarshalL3VPNNLRIWithOptions(%x) = %+v, %v, want label %d", tt.field, got, err, tt.label)
		}
		got, err = UnmarshalL3VPNNLRIWithOptions(b, Options{AFI: 1, Withdraw: true})
		if err != nil || len(got.NLRI) != 1 || got.NLRI[0].Label != nil {
			t.Errorf("UnmarshalL3VPNNLRIWithOptions(%x, Withdraw) = %+v, %v, want no label", tt.field, got, err)
		}
	}
}
