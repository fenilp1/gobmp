package l3vpn

import (
	"reflect"
	"testing"
)

// UnmarshalL3VPNNLRI keeps its signature and decodes like
// UnmarshalL3VPNNLRIWithOptions with PathID and SRv6 set and nothing else.
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
		{name: "label 0x800000", b: nlri([]byte{0x78, 0x80, 0x00, 0x00}, rd, []byte{10, 0, 0, 1})},
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
