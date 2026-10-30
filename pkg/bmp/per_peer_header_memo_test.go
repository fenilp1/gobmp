package bmp

import "testing"

// TestMemoizeStrings checks the getters return the same strings once
// MemoizeStrings has run, for IPv4 and IPv6 peers of every peer type, and
// that a copy of the header changed afterwards computes its own.
func TestMemoizeStrings(t *testing.T) {
	type strs struct{ hash, bgpID, addr, ts string }
	get := func(p *PerPeerHeader) strs {
		return strs{p.GetPeerHash(), p.GetPeerBGPIDString(), p.GetPeerAddrString(), p.GetPeerTimestamp()}
	}
	for _, peerType := range []byte{0, 1, 2, 3} {
		for _, flags := range []byte{0x00, 0x80, 0x40, 0xff} {
			b := []byte{peerType, flags, 0, 1, 0, 0, 0xfd, 0xe9, 0, 7}
			b = append(b, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 1)
			b = append(b, 0, 0, 0xfd, 0xe8, 10, 0, 0, 1)
			b = append(b, 0x68, 0, 0, 1, 0, 1, 0, 2)
			p, err := UnmarshalPerPeerHeader(b)
			if err != nil {
				t.Fatalf("UnmarshalPerPeerHeader(%x) error: %v", b, err)
			}
			want := get(p)
			p.MemoizeStrings()
			if got := get(p); got != want {
				t.Fatalf("peer type %d flags %#x: memoized %+v, want %+v", peerType, flags, got, want)
			}
			c := *p
			c.PeerAS = 65010
			c.PeerBGPID = []byte{10, 0, 0, 9}
			c.PeerTimestamp = []byte{0, 0, 0, 1, 0, 0, 0, 1}
			fresh := c
			fresh.strs = nil
			if got, want := get(&c), get(&fresh); got != want {
				t.Fatalf("copy: got %+v, want %+v", got, want)
			}
		}
	}
	// A short timestamp is left to GetPeerTimestamp, which panics on it.
	p := &PerPeerHeader{PeerAddress: make([]byte, 16), PeerBGPID: make([]byte, 4)}
	p.MemoizeStrings()
	defer func() {
		if recover() == nil {
			t.Fatal("GetPeerTimestamp() of a short timestamp did not panic")
		}
	}()
	p.GetPeerTimestamp()
}
