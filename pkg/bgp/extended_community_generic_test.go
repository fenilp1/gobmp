package bgp

import "testing"

// TestGenericTransitiveSubTypes covers type 0x80 sub-types from the IANA
// "Generic Transitive Extended Community Sub-Types" registry:
// 0x0b E-Tree Info (RFC 7796 Section 6.2), 0x0c Flow spec
// traffic-rate-packets (RFC 8955 Section 7.2) and 0x0d Flow Specification
// for SFC Classifiers (RFC 9015 Section 7.4).
func TestGenericTransitiveSubTypes(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		expect string
	}{
		{
			name:   "E-Tree Info, MBZ bits ignored, P and V set",
			input:  []byte{0x80, 0x0b, 0xf0, 0x64, 0x00, 0xc8, 0x00, 0x03},
			expect: "e-tree-info=RootVLAN=100 LeafVLAN=200 P=true V=true",
		},
		{
			name:   "E-Tree Info, V only",
			input:  []byte{0x80, 0x0b, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x01},
			expect: "e-tree-info=RootVLAN=10 LeafVLAN=20 P=false V=true",
		},
		{
			name:   "traffic-rate-packets 1000 pps",
			input:  []byte{0x80, 0x0c, 0xfd, 0xe8, 0x44, 0x7a, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 65000 Rate: 1000 pps",
		},
		{
			name:   "traffic-rate-packets fractional rate is kept",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x3f, 0x00, 0x00, 0x00}, // 0.5
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 0.5 pps",
		},
		{
			name:   "traffic-rate-packets large rate",
			input:  []byte{0x80, 0x0c, 0x00, 0x01, 0x4f, 0xb2, 0xd0, 0x5e}, // 6e9
			expect: "flowspec-traffic-rate-packets=AS: 1 Rate: 6000000000 pps",
		},
		{
			name:   "traffic-rate-packets negative is treated as zero",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0xc4, 0x7a, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: 0 pps",
		},
		{
			name:   "traffic-rate-packets NaN is treated as zero",
			input:  []byte{0x80, 0x0c, 0x00, 0x00, 0x7f, 0xc0, 0x00, 0x00},
			expect: "flowspec-traffic-rate-packets=AS: 0 Rate: 0 pps",
		},
		{
			name:   "SFC classifier SPI/SI/SFT",
			input:  []byte{0x80, 0x0d, 0x00, 0x01, 0x00, 0xff, 0x00, 0x02},
			expect: "flowspec-sfc=SPI=256 SI=255 SFT=2",
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
}
