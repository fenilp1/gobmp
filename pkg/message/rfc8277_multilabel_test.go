package message

import (
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestMultiLabelCapabilityFromPeerUp checks how the Multiple Labels
// Capability (RFC 8277 §2.1) learned from a Peer Up drives label decoding in
// later Route Monitoring messages. Confirmed (both OPENs list it): labels
// are read by the S bit only. Known absent: exactly one label with the S bit
// ignored (RFC 8277 §2.2), then the S bit walk if that is invalid. Unknown
// (no Peer Up seen): the S bit walk, then one label. L3VPN and BGP CT share
// the decoder, so both are checked.
func TestMultiLabelCapabilityFromPeerUp(t *testing.T) {
	rd := []byte{0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01} // RD 100:1
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	v4Prefix := []byte{0x0a, 0x00, 0x00, 0x01}
	// Labels 100 (S=0) and 200 (S=1), 10.0.0.1/32.
	twoLabels := cat([]byte{0x90, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, rd, v4Prefix)
	// Label 1000 with S=0, 10.0.0.1/32.
	oneLabelS0 := cat([]byte{0x78, 0x00, 0x3e, 0x80}, rd, v4Prefix)
	// Label 1000 with S=0, RD 256:1 whose first bytes read as a label with
	// S=1, 10.0.0.1/32.
	labelLikeRD := cat([]byte{0x78, 0x00, 0x3e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01}, v4Prefix)
	// Labels 100 (S=0) and 3 (S=1), 2001:db8:1::/64.
	v6TwoLabels := cat([]byte{0xb0, 0x00, 0x06, 0x40, 0x00, 0x00, 0x31}, rd, []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00})
	v4NH := []byte{192, 0, 2, 1}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	mlCap := func(afi, safi byte) bgp.Capability {
		return bgp.Capability{8: {{Value: []byte{0x00, afi, safi, 0x02}}}}
	}
	none := bgp.Capability{}
	tests := []struct {
		name       string
		noPeerUp   bool
		sent, recv bgp.Capability
		afi, safi  byte
		nlri       []byte
		wantType   int
		wantLabels []uint32 // nil: nothing published
		wantPrefix string
		wantRD     string // 100:1 if empty
	}{
		{name: "L3VPN confirmed", sent: mlCap(1, 128), recv: mlCap(1, 128), afi: 1, safi: 128, nlri: twoLabels, wantType: bmp.L3VPNMsg, wantLabels: []uint32{100, 200}, wantPrefix: "10.0.0.1"},
		{name: "BGP CT confirmed", sent: mlCap(1, 76), recv: mlCap(1, 76), afi: 1, safi: 76, nlri: twoLabels, wantType: bmp.ClassfulTransportMsg, wantLabels: []uint32{100, 200}, wantPrefix: "10.0.0.1"},
		{name: "L3VPN only sent", sent: mlCap(1, 128), recv: none, afi: 1, safi: 128, nlri: twoLabels, wantType: bmp.L3VPNMsg, wantLabels: []uint32{100, 200}, wantPrefix: "10.0.0.1"},
		{name: "L3VPN two labels, no Peer Up", noPeerUp: true, afi: 1, safi: 128, nlri: twoLabels, wantType: bmp.L3VPNMsg, wantLabels: []uint32{100, 200}, wantPrefix: "10.0.0.1"},
		{name: "VPNv6 two labels, no Peer Up", noPeerUp: true, afi: 2, safi: 128, nlri: v6TwoLabels, wantType: bmp.L3VPNMsg, wantLabels: []uint32{100, 3}, wantPrefix: "2001:db8:1::"},
		{name: "L3VPN two labels, capability absent", sent: none, recv: none, afi: 1, safi: 128, nlri: twoLabels, wantType: bmp.L3VPNMsg, wantLabels: []uint32{100, 200}, wantPrefix: "10.0.0.1"},
		{name: "L3VPN label-like RD, capability absent", sent: none, recv: none, afi: 1, safi: 128, nlri: labelLikeRD, wantType: bmp.L3VPNMsg, wantLabels: []uint32{1000}, wantPrefix: "10.0.0.1", wantRD: "256:1"},
		{name: "BGP CT label-like RD, capability absent", sent: none, recv: none, afi: 1, safi: 76, nlri: labelLikeRD, wantType: bmp.ClassfulTransportMsg, wantLabels: []uint32{1000}, wantPrefix: "10.0.0.1", wantRD: "256:1"},
		{name: "L3VPN S=0 without capability", sent: none, recv: none, afi: 1, safi: 128, nlri: oneLabelS0, wantType: bmp.L3VPNMsg, wantLabels: []uint32{1000}, wantPrefix: "10.0.0.1"},
		{name: "BGP CT S=0 without capability", sent: none, recv: none, afi: 1, safi: 76, nlri: oneLabelS0, wantType: bmp.ClassfulTransportMsg, wantLabels: []uint32{1000}, wantPrefix: "10.0.0.1"},
		{name: "L3VPN S=0, no Peer Up", noPeerUp: true, afi: 1, safi: 128, nlri: oneLabelS0, wantType: bmp.L3VPNMsg, wantLabels: []uint32{1000}, wantPrefix: "10.0.0.1"},
		// RFC 8277 §2.2: 0x000000 and 0x800000 on an announcement are labels.
		{name: "L3VPN label 0x000000", noPeerUp: true, afi: 1, safi: 128, nlri: cat([]byte{0x78, 0x00, 0x00, 0x00}, rd, v4Prefix), wantType: bmp.L3VPNMsg, wantLabels: []uint32{0}, wantPrefix: "10.0.0.1"},
		{name: "BGP CT label 0x800000", noPeerUp: true, afi: 1, safi: 76, nlri: cat([]byte{0x78, 0x80, 0x00, 0x00}, rd, v4Prefix), wantType: bmp.ClassfulTransportMsg, wantLabels: []uint32{0x80000}, wantPrefix: "10.0.0.1"},
		// A confirmed capability never falls back to a single label.
		{name: "L3VPN S=0 with capability confirmed", sent: mlCap(1, 128), recv: mlCap(1, 128), afi: 1, safi: 128, nlri: oneLabelS0, wantType: bmp.L3VPNMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{}
			p := NewProducer(pub, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			if !tt.noPeerUp {
				peerUp := buildPeerUpMessage(t, "192.168.1.1")
				peerUp.SentOpen.Capabilities = tt.sent
				peerUp.ReceivedOpen.Capabilities = tt.recv
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
			}

			nh := v4NH
			if tt.afi == 2 {
				nh = v6NH
			}
			attr := cat([]byte{0x00, tt.afi, tt.safi, byte(len(nh))}, nh, []byte{0x00}, tt.nlri)
			attr = append([]byte{0x80, 0x0e, byte(len(attr))}, attr...)
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: ctTestUpdate(t, attr)}})

			var got []recordedMsg
			for _, m := range pub.msgs {
				if m.msgType == tt.wantType {
					got = append(got, m)
				}
			}
			if tt.wantLabels == nil {
				if len(got) != 0 {
					t.Fatalf("published %d messages for a malformed NLRI, want 0", len(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("published %d messages of type %d, want 1", len(got), tt.wantType)
			}
			msg, _ := decodeCT(t, got[0])
			if !reflect.DeepEqual(msg.Labels, tt.wantLabels) {
				t.Errorf("labels = %v, want %v", msg.Labels, tt.wantLabels)
			}
			wantRD := tt.wantRD
			if wantRD == "" {
				wantRD = "100:1"
			}
			if msg.VPNRD != wantRD || msg.Prefix != tt.wantPrefix {
				t.Errorf("route = %s %s/%d, want %s %s", msg.VPNRD, msg.Prefix, msg.PrefixLen, wantRD, tt.wantPrefix)
			}
		})
	}
}
