package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// RFC 7606 Section 3(g) keeps repeated MP_REACH_NLRI attributes, whose
// repetition is for the monitored router to handle; each reaches the
// producer.
func TestRepeatedMPReachNLRI(t *testing.T) {
	mpReach := func(prefix ...byte) []byte {
		v := []byte{0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}
		v = append(v, prefix...)
		return append([]byte{0x80, 0x0E, byte(len(v))}, v...)
	}
	attrs := withPath(
		[]byte{0x02, 0x01, 0, 0, 0xFD, 0xE9},      // AS_SEQUENCE [65001]
		mpReach(32, 0x20, 0x01, 0x0d, 0xb8),       // 2001:db8::/32
		mpReach(48, 0x20, 0x01, 0x0d, 0xb8, 0, 1), // 2001:db8:1::/48
	)
	routes := produceRoutes(t, sentOpenAS(testLocalAS), bmp.PeerType0, 0x00, attrs)
	for _, prefix := range []string{"2001:db8::", "2001:db8:1::"} {
		if got := routes[prefix]; got.Action != "add" || got.OriginAS != 65001 {
			t.Errorf("%s: action %q origin_as %d, want add, 65001", prefix, got.Action, got.OriginAS)
		}
	}
}
