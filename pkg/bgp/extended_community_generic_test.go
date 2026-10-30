package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

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

// TestGenericTransitivePart2Part3SubTypes: the IANA "Generic Transitive
// Extended Community Part 2 Sub-Types" registry (type 0x81) assigns only
// 0x08, and "Part 3" (type 0x82) assigns 0x04, 0x08, 0x84 and 0x85; only
// 0x08 is flowspec (rt-redirect, RFC 8955 Section 7.4), so 0x06, 0x07 and
// 0x09 must not get flowspec names there.
func TestGenericTransitivePart2Part3SubTypes(t *testing.T) {
	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte{0x81, 0x08, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x64}, "flowspec-redirect=10.0.0.1:100"},
		{[]byte{0x82, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64}, "flowspec-redirect=65536:100"},
		{[]byte{0x81, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x81, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]"},
		{[]byte{0x81, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E ]"},
		{[]byte{0x82, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
		{[]byte{0x82, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 ]"},
		{[]byte{0x82, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2e}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x2E ]"},
		{[]byte{0x82, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "Subtype unknown=[ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ]"},
	}
	for _, tt := range tests {
		ext, err := makeExtCommunity(tt.input)
		if err != nil {
			t.Fatalf("makeExtCommunity(% x) error = %v", tt.input, err)
		}
		if got := ext.String(); got != tt.expect {
			t.Errorf("% x: got %s, want %s", tt.input, got, tt.expect)
		}
	}
}

// TestFlowspecTrafficRateBytes: RFC 8955 Section 7.1 says negative
// traffic-rate-bytes values MUST be treated as zero; non-negative values keep
// their existing rendering (bytes per second times 8, as bps).
func TestFlowspecTrafficRateBytes(t *testing.T) {
	tests := []struct {
		input  []byte
		expect string
	}{
		{[]byte{0x80, 0x06, 0xfd, 0xe8, 0x44, 0x7a, 0x00, 0x00}, "flowspec-traffic-rate=AS: 65000 Rate: 8000 bps"}, // 1000 B/s
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 0 bps"},
		{[]byte{0x80, 0x06, 0x00, 0x00, 0xc4, 0x7a, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 0 bps"}, // -1000
		{[]byte{0x80, 0x06, 0x00, 0x00, 0xbf, 0x80, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 0 bps"}, // -1
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x7f, 0xc0, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 0 bps"}, // NaN
		// Computed in uint64: rates of 2^29 B/s and more no longer wrap.
		// 536870911 is not a float32; 536870880 is the largest below 2^29.
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x4d, 0xff, 0xff, 0xff}, "flowspec-traffic-rate=AS: 0 Rate: 4294967040 bps"},           // 536870880 B/s
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x4e, 0x00, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 4294967296 bps"},           // 2^29 = float32(536870911)
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x4e, 0x95, 0x02, 0xf9}, "flowspec-traffic-rate=AS: 0 Rate: 10000000000 bps"},          // 1.25e9 B/s (10G)
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x5d, 0xff, 0xff, 0xff}, "flowspec-traffic-rate=AS: 0 Rate: 18446742974197923840 bps"}, // largest float32 below 2^61
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x5e, 0x00, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 18446744073709551615 bps"}, // 2^61 saturates
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x7f, 0x7f, 0xff, 0xff}, "flowspec-traffic-rate=AS: 0 Rate: 18446744073709551615 bps"}, // MaxFloat32
		{[]byte{0x80, 0x06, 0x00, 0x00, 0x7f, 0x80, 0x00, 0x00}, "flowspec-traffic-rate=AS: 0 Rate: 18446744073709551615 bps"}, // +Inf
	}
	for _, tt := range tests {
		ext, err := makeExtCommunity(tt.input)
		if err != nil {
			t.Fatalf("makeExtCommunity(% x) error = %v", tt.input, err)
		}
		if got := ext.String(); got != tt.expect {
			t.Errorf("% x: got %s, want %s", tt.input, got, tt.expect)
		}
	}
}

// TestFlowspecTrafficRateBytes_Unchanged checks that every rate that did not
// overflow the previous uint32 computation renders exactly as before.
func TestFlowspecTrafficRateBytes_Unchanged(t *testing.T) {
	for _, r := range []float32{0, 0.5, 1, 1000, 125000, 1.25e6, 536870880, 1e8} {
		v := []byte{0x80, 0x06, 0x00, 0x07, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(v[4:], math.Float32bits(r))
		ext, err := makeExtCommunity(v)
		if err != nil {
			t.Fatal(err)
		}
		want := "flowspec-traffic-rate=" + fmt.Sprintf("AS: %d Rate: %d bps", 7, uint32(r)*8)
		if got := ext.String(); got != want {
			t.Errorf("rate %v: got %s, want %s", r, got, want)
		}
	}
}
