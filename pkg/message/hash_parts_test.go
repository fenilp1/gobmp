package message

import (
	"crypto/md5"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"
)

// hashPartsStream is hashParts as it was, writing each part and its zero
// separator to an MD5 hash in turn.
func hashPartsStream(parts ...string) string {
	h := md5.New()
	for _, part := range parts {
		_, _ = h.Write([]byte(part))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// TestHashPartsDigests checks hashParts returns the digests it returned
// when it streamed the parts: for no parts, empty parts, parts holding zero
// octets, parts that fill the stack buffer exactly or overflow it, and random
// parts.
func TestHashPartsDigests(t *testing.T) {
	tests := [][]string{
		nil,
		{},
		{""},
		{"", ""},
		{"\x00"},
		{"a\x00b", ""},
		{"unicast", "66efff4c945d3c3b87fc271b47d456db", "79c56ab0db70cf69163c11ad4f16def2", "10.0.0.0", "24", "true", "0", ""},
		{strings.Repeat("x", 255)},
		{strings.Repeat("x", 256)},
		{strings.Repeat("x", 127), strings.Repeat("y", 127)},
		{strings.Repeat("x", 4096), "y"},
	}
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 5000; i++ {
		parts := make([]string, r.Intn(12))
		for j := range parts {
			b := make([]byte, r.Intn(80))
			r.Read(b)
			parts[j] = string(b)
		}
		tests = append(tests, parts)
	}
	for _, parts := range tests {
		if got, want := hashParts(parts...), hashPartsStream(parts...); got != want {
			t.Fatalf("hashParts(%q) = %s, want %s", parts, got, want)
		}
	}
}

func BenchmarkHashParts(b *testing.B) {
	parts := []string{"unicast", "66efff4c945d3c3b87fc271b47d456db", "79c56ab0db70cf69163c11ad4f16def2", "10.0.0.0", "24", "true", "0", ""}
	b.Run("stack", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hashParts(parts...)
		}
	})
	b.Run("stream", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = hashPartsStream(parts...)
		}
	})
}
