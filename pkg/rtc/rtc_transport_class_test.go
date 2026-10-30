package rtc

import "testing"

// RFC 9832 §4.3: RTC (RFC 4684) applies to the Transport Class RT (type 0x0a,
// or 0x4a non-transitive, sub-type 0x02) carried on BGP CT routes.
func TestUnmarshalRTCNLRITransportClassRT(t *testing.T) {
	tests := []struct {
		name string
		rt   []byte
		want string
		fail bool
	}{
		{name: "transitive TC RT 100", rt: []byte{0x0a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}, want: "RTC{AS=65000, RT=transport-target:0:100}"},
		{name: "non-transitive TC RT 200", rt: []byte{0x4a, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8}, want: "RTC{AS=65000, RT=nt-transport-target:0:200}"},
		{name: "TC type with non RT sub-type", rt: []byte{0x0a, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}, fail: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := append([]byte{
				0x60,                   // Length: 96 bits
				0x00, 0x00, 0xfd, 0xe8, // Origin AS: 65000
			}, tt.rt...)
			r, err := UnmarshalRTCNLRI(b)
			if tt.fail {
				if err == nil {
					t.Fatalf("UnmarshalRTCNLRI() = %+v, want an error", r)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalRTCNLRI() error: %v", err)
			}
			if len(r.NLRI) != 1 {
				t.Fatalf("got %d NLRIs, want 1", len(r.NLRI))
			}
			if got := r.NLRI[0].String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
