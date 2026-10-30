package bgp

import "testing"

// TestLayer2InfoExtCommunity: type 0x80 sub-type 0x0a is "Layer2 Info
// Extended Community" in the IANA "Generic Transitive Extended Community
// Sub-Types" registry (RFC 4761 Section 3.2.4). Value: Encaps Type(1),
// Control Flags(1) |Z|Z|Z|Z|T|R|C|S| (RFC 8395 Section 2), Layer-2 MTU(2),
// Reserved(2).
func TestLayer2InfoExtCommunity(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "VPLS encaps 19, no flags, MTU 1500",
			input:  []byte{0x80, 0x0a, 0x13, 0x00, 0x05, 0xdc, 0x00, 0x00},
			expect: "layer2-info=Encaps=19 T=false R=false C=false S=false MTU=1500",
		},
		{
			name:   "S flag is the least significant bit",
			input:  []byte{0x80, 0x0a, 0x13, 0x01, 0x05, 0xdc, 0x00, 0x00},
			expect: "layer2-info=Encaps=19 T=false R=false C=false S=true MTU=1500",
		},
		{
			name:   "C flag",
			input:  []byte{0x80, 0x0a, 0x13, 0x02, 0x05, 0xdc, 0x00, 0x00},
			expect: "layer2-info=Encaps=19 T=false R=false C=true S=false MTU=1500",
		},
		{
			name:   "T and R flags (RFC 8395), Z bits ignored",
			input:  []byte{0x80, 0x0a, 0x05, 0xfc, 0x23, 0x28, 0x00, 0x00},
			expect: "layer2-info=Encaps=5 T=true R=true C=false S=false MTU=9000",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := makeExtCommunity(tt.input)
			if err != nil {
				t.Fatalf("makeExtCommunity() error = %v", err)
			}
			if got := ext.String(); got != tt.expect {
				t.Errorf("got %s, want %s", got, tt.expect)
			}
		})
	}
	// Sub-type 0x0a is unassigned under types 0x81 and 0x82; unchanged.
	for _, typ := range []byte{0x81, 0x82} {
		ext, err := makeExtCommunity([]byte{typ, 0x0a, 0x13, 0x00, 0x05, 0xdc, 0x00, 0x00})
		if err != nil {
			t.Fatalf("makeExtCommunity() error = %v", err)
		}
		if got := ext.String(); got != "Subtype unknown=[ 0x13, 0x00, 0x05, 0xDC, 0x00, 0x00 ]" {
			t.Errorf("type 0x%02x sub-type 0x0a: got %s", typ, got)
		}
	}
}
