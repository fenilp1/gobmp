package base

import (
	"net"
	"reflect"
	"strings"
	"testing"
)

func TestGetPrefixIPReachability(t *testing.T) {
	tests := []struct {
		name   string
		input  *PrefixDescriptor
		expect string

		ipv4 bool
	}{
		{
			name: "ipv4",
			input: &PrefixDescriptor{
				PrefixTLV: map[uint16]TLV{
					265: {
						Type:   265,
						Length: 5,
						Value:  []byte{32, 192, 168, 8, 8},
					},
				},
			},
			expect: "192.168.8.8",
			ipv4:   true,
		},
		{
			name: "ipv6",
			input: &PrefixDescriptor{
				PrefixTLV: map[uint16]TLV{
					265: {
						Type:   265,
						Length: 16,
						Value:  []byte{120, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
					},
				},
			},
			expect: "10::",
			ipv4:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			route := tt.input.GetPrefixIPReachability(tt.ipv4)
			var rs string
			if route == nil {
				t.Errorf("failed, no routes returned")
				return
			}
			if len(route.Prefix) == 16 {
				rs = net.IP(route.Prefix).To16().String()
			} else {
				rs = net.IP(route.Prefix).To4().String()
			}
			if strings.Compare(tt.expect, rs) != 0 {
				t.Errorf("failed, expected %s route got %s route", tt.expect, rs)
			}
		})
	}
}

func TestUnmarshalBaseNLRI(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		expect  []Route
		pathIDs PathIDState
		wantErr bool
	}{
		{
			name:    "EoR Case",
			input:   []byte{},
			pathIDs: PathIDAbsent,
			expect:  []Route{},
			wantErr: false,
		},
		{
			name:    "Default prefix",
			input:   []byte{0x0},
			pathIDs: PathIDAbsent,
			expect: []Route{
				{
					Length: 0x0,
					Prefix: []byte{},
				},
			},
		},
		{
			name:    "fail",
			input:   []byte{0, 8, 10, 24, 10, 0, 0, 24, 20, 0, 0},
			pathIDs: PathIDAbsent,
			expect: []Route{
				{
					Length: 0x0,
					Prefix: []byte{},
				},
				{
					Length: 0x08,
					Prefix: []byte{10},
				},
				{
					Length: 24,
					Prefix: []byte{10, 0, 0},
				},
				{
					Length: 24,
					Prefix: []byte{20, 0, 0},
				},
			},
		},
		{
			name:    "Panic_1",
			input:   []byte{0x00, 0x00, 0x00, 0x01, 0x18, 0x43, 0xd3, 0x35, 0x00, 0x00, 0x00, 0x01, 0x18, 0x2d, 0xa0, 0x00},
			pathIDs: PathIDPresent,
			expect: []Route{
				{
					PathID: 1,
					Length: 24,
					Prefix: []byte{67, 211, 53},
				},
				{
					PathID: 1,
					Length: 24,
					Prefix: []byte{45, 160, 0},
				},
			},
		},
		{
			name:    "issue #227",
			input:   []byte{0x1C, 0x02, 0x02, 0x02, 0x00},
			pathIDs: PathIDAbsent,
			expect: []Route{
				{
					PathID: 0,
					Length: 28,
					Prefix: []byte{2, 2, 2, 0},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnmarshalRoutes(tt.input, tt.pathIDs)
			if err != nil && !tt.wantErr {
				t.Fatalf("test failed with error: %+v", err)
			}
			if err == nil && tt.wantErr {
				t.Fatalf("test failed as expected error did not occur")
			}
			if err != nil {
				return
			}
			if !reflect.DeepEqual(tt.expect, got) {
				t.Fatalf("test failed as expected nlri %+v does not match actual nlri %+v", tt.expect, got)
			}
		})
	}
}

// TestUnmarshalRoutes_RetryLimit verifies that malformed input fails after one retry
// instead of recursing infinitely.
func TestUnmarshalRoutes_RetryLimit(t *testing.T) {
	// Single byte 0xFF — invalid prefix length whether pathID=true or false.
	// With pathID=true: not enough bytes for PathID (need 4).
	// With pathID=false: prefix length 255, need 32 bytes but only 0 remain.
	// Both fail → should return error, not hang.
	_, err := UnmarshalRoutes([]byte{0xFF}, PathIDUnknown)
	if err == nil {
		t.Fatal("expected error for malformed input, got nil")
	}
}

// TestUnmarshalRoutes_PathIDState checks that a known ADD-PATH state parses
// the field once, and only an unknown state retries with Path IDs (RFC 7911
// §3, RFC 7606 §5.3).
func TestUnmarshalRoutes_PathIDState(t *testing.T) {
	plain := []byte{0x08, 0x0a}                          // 10.0.0.0/8
	withID := []byte{0x00, 0x00, 0x00, 0x01, 0x08, 0x0a} // Path ID 1, 10.0.0.0/8
	tests := []struct {
		name    string
		input   []byte
		state   PathIDState
		wantErr bool
		pathID  uint32
	}{
		{name: "unknown, no Path ID", input: plain, state: PathIDUnknown},
		{name: "unknown, Path ID, retried", input: withID, state: PathIDUnknown, pathID: 1},
		{name: "absent, no Path ID", input: plain, state: PathIDAbsent},
		{name: "absent, Path ID", input: withID, state: PathIDAbsent, wantErr: true},
		{name: "present, Path ID", input: withID, state: PathIDPresent, pathID: 1},
		{name: "present, no Path ID", input: plain, state: PathIDPresent, wantErr: true},
		// A malformed field that reads as a /48 IPv4 route with Path ID
		// 0x20003e81 if Path IDs are assumed.
		{name: "absent, malformed", input: []byte{0x20, 0x00, 0x3e, 0x81, 0x30, 0x00, 0x3e, 0x81, 0x0a, 0x00, 0x00}, state: PathIDAbsent, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			routes, err := UnmarshalRoutes(tt.input, tt.state)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("UnmarshalRoutes() = %+v, want error", routes)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalRoutes() error: %v", err)
			}
			if len(routes) != 1 || routes[0].Length != 8 || routes[0].PathID != tt.pathID || !reflect.DeepEqual(routes[0].Prefix, []byte{0x0a}) {
				t.Errorf("UnmarshalRoutes() = %+v, want one route 10.0.0.0/8 with Path ID %d", routes, tt.pathID)
			}
		})
	}
}
