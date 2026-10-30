package bmp

import (
	"fmt"
	"math/rand"
	"testing"
)

// sessionKeyFmt and peerIdentityFmt are SessionKey and PeerIdentity as they
// were, the oracle for TestPeerKeysOracle.
func sessionKeyFmt(p *PerPeerHeader) string {
	if p.PeerType == PeerType3 {
		return fmt.Sprintf("%d|%x|%s", p.PeerType, p.PeerDistinguisher, p.GetPeerBGPIDString())
	}
	return fmt.Sprintf("%d|%x|%t|%s", p.PeerType, p.PeerDistinguisher, p.flagV, p.GetPeerAddrString())
}

func peerIdentityFmt(p *PerPeerHeader) string {
	switch p.PeerType {
	case PeerType0, PeerType1, PeerType2:
		return fmt.Sprintf("%d-%s-%s-%d-%s", p.PeerType, p.GetPeerDistinguisherString(), p.GetPeerAddrString(), p.PeerAS, p.GetPeerBGPIDString())
	case PeerType3:
		return fmt.Sprintf("%d-%s-%s", p.PeerType, p.GetPeerDistinguisherString(), p.GetPeerBGPIDString())
	default:
		return ""
	}
}

// keyOrPanic returns f(p), or the panic it raised.
func keyOrPanic(f func(*PerPeerHeader) string, p *PerPeerHeader) (s string) {
	defer func() {
		if r := recover(); r != nil {
			s = fmt.Sprintf("panic: %v", r)
		}
	}()
	return f(p)
}

// TestPeerKeysOracle checks SessionKey and PeerIdentity return the keys the
// fmt based code did, for every peer type, unknown ones included, all flag
// combinations, IPv4 and IPv6 peers, random fields and short or missing
// distinguisher, address and BGP ID.
func TestPeerKeysOracle(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	field := func(n int) []byte {
		if n < 0 {
			return nil
		}
		b := make([]byte, n)
		r.Read(b)
		return b
	}
	n := 0
	for _, pt := range []PeerType{PeerType0, PeerType1, PeerType2, PeerType3, 4, 255} {
		for flags := 0; flags < 32; flags++ {
			for i := 0; i < 40; i++ {
				rdLen, addrLen, idLen := 8, 16, 4
				switch i % 8 {
				case 1:
					rdLen = -1
				case 2:
					rdLen = 3
				case 3:
					addrLen = 4
				case 4:
					addrLen = -1
				case 5:
					idLen = 16
				case 6:
					idLen = -1
				}
				p := &PerPeerHeader{
					PeerType:          pt,
					flagF:             flags&1 != 0,
					flagV:             flags&2 != 0,
					flagL:             flags&4 != 0,
					flagA:             flags&8 != 0,
					flagO:             flags&16 != 0,
					PeerDistinguisher: field(rdLen),
					PeerAddress:       field(addrLen),
					PeerAS:            r.Uint32(),
					PeerBGPID:         field(idLen),
				}
				if i%5 == 0 && addrLen == 16 {
					copy(p.PeerAddress, make([]byte, 10))
					p.PeerAddress[10], p.PeerAddress[11] = 0xff, 0xff
				}
				if got, want := keyOrPanic((*PerPeerHeader).SessionKey, p), keyOrPanic(sessionKeyFmt, p); got != want {
					t.Fatalf("SessionKey() of %+v = %q, want %q", p, got, want)
				}
				if got, want := keyOrPanic((*PerPeerHeader).PeerIdentity, p), keyOrPanic(peerIdentityFmt, p); got != want {
					t.Fatalf("PeerIdentity() of %+v = %q, want %q", p, got, want)
				}
				n++
			}
		}
	}
	t.Logf("checked %d headers", n)
}

func BenchmarkPeerKeys(b *testing.B) {
	p, err := UnmarshalPerPeerHeader(append([]byte{0, 0}, make([]byte, 40)...))
	if err != nil {
		b.Fatal(err)
	}
	b.Run("SessionKey", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = p.SessionKey()
		}
	})
	b.Run("SessionKey-fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = sessionKeyFmt(p)
		}
	})
	b.Run("PeerIdentity", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = p.PeerIdentity()
		}
	})
	b.Run("PeerIdentity-fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = peerIdentityFmt(p)
		}
	})
}
