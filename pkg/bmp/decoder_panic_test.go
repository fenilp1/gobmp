package bmp

import "testing"

// PeerUp whose OPEN messages carry a 4-octet AS capability (code 65) of
// length 0 (RFC 6793 §3 requires 4). The router accepted the OPEN
// (RFC 7854 §4.10), so the PeerUp must decode and report not 4-octet capable.
func TestUnmarshalPeerUpMessage_Cap65BadLength(t *testing.T) {
	open := []byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x21, 0x01, 0x04, 0xfd, 0xe8, 0x00, 0xb4, 192, 0, 2, 1,
		0x04, 0x02, 0x02, 0x41, 0x00,
	}
	body := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2, 0x00, 0xb3, 0x9c, 0x40}
	body = append(body, open...)
	body = append(body, open...)
	pu, err := UnmarshalPeerUpMessage(body, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := pu.SentOpen.Is4BytesASCapable(); ok {
		t.Fatal("expected not 4-octet AS capable")
	}
}
