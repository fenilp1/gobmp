package bmp

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
)

func TestIdentityFromPeerUpLocalAS(t *testing.T) {
	tests := []struct {
		name string
		open *bgp.OpenMessage
		want uint32
	}{
		{"no Sent OPEN", nil, 0},
		{"2-octet speaker", &bgp.OpenMessage{MyAS: 64700}, 64700},
		{"4-octet capability", &bgp.OpenMessage{MyAS: 23456, Capabilities: bgp.Capability{
			65: {{Value: []byte{0xFA, 0x56, 0xEA, 0x01}}},
		}}, 4200000001},
		{"AS_TRANS without capability", &bgp.OpenMessage{MyAS: 23456}, 0},
		{"short capability", &bgp.OpenMessage{MyAS: 64700, Capabilities: bgp.Capability{
			65: {{Value: []byte{0xFA, 0x56}}},
		}}, 64700},
	}
	ph := testPeerHeader(t, PeerType0, []byte{192, 0, 2, 2}, 65000, []byte{10, 0, 0, 1})
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			peerUp := testPeerUp([]byte{192, 0, 2, 1})
			peerUp.SentOpen = tt.open
			got := IdentityFromPeerUp(Message{PeerHeader: ph, Payload: peerUp})
			if got.LocalAS != tt.want {
				t.Errorf("LocalAS = %d, want %d", got.LocalAS, tt.want)
			}
		})
	}
}
