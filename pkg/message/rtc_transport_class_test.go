package message

import "testing"

// RFC 9832 §4.3: a Transport Class RT in an RTC NLRI is rendered in the RFC's
// "transport-target:0:100" notation rather than as raw hex; the non-transitive
// type 0x4a is named "nt-transport-target", as in the extended-community list.
func TestFormatRouteTargetTransportClass(t *testing.T) {
	tests := []struct {
		rt   []byte
		want string
	}{
		{rt: []byte{0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}, want: "transport-target:0:100"},
		{rt: []byte{0x4a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8}, want: "nt-transport-target:0:200"},
		{rt: []byte{0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}, want: "100:1"},
	}
	for _, tt := range tests {
		if got := formatRouteTarget(tt.rt); got != tt.want {
			t.Errorf("formatRouteTarget(%x) = %q, want %q", tt.rt, got, tt.want)
		}
	}
}
