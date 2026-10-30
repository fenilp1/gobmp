package message

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// hexColonFmt is how ESIs and MAC addresses were formatted before hexColon.
func hexColonFmt(b []byte, n int) string {
	var s strings.Builder
	for i := 0; i < n; i++ {
		if i > 0 {
			s.WriteByte(':')
		}
		fmt.Fprintf(&s, "%02x", b[i])
	}
	return s.String()
}

// TestHexColon checks hexColon formats every octet value, and random ESIs
// and MAC addresses of every length up to 32 octets, as the fmt based code
// did.
func TestHexColon(t *testing.T) {
	for v := 0; v < 256; v++ {
		b := []byte{byte(v)}
		if got, want := hexColon(b, 1), hexColonFmt(b, 1); got != want {
			t.Fatalf("hexColon(%#x) = %q, want %q", v, got, want)
		}
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		b := make([]byte, 32)
		r.Read(b)
		n := r.Intn(len(b) + 1)
		if got, want := hexColon(b, n), hexColonFmt(b, n); got != want {
			t.Fatalf("hexColon(%x, %d) = %q, want %q", b, n, got, want)
		}
	}
}

func BenchmarkHexColon(b *testing.B) {
	esi := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99}
	b.Run("hexColon", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hexColon(esi, ESILength)
		}
	})
	b.Run("fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hexColonFmt(esi, ESILength)
		}
	})
}
