package message

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestLabeledUnicastRFC8277 checks labeled unicast (AFI 1/2 SAFI 4) end to
// end, from the Peer Up that sets the Multiple Labels and ADD-PATH
// capabilities to the published UnicastPrefix:
//   - Withdraw: the 3-octet Compatibility field is ignored (RFC 8277 §2.4).
//   - Announce, capability confirmed: labels up to the S bit (§2.3).
//   - Announce, capability absent: one label, S bit ignored (§2.2), then the
//     S bit walk if that is invalid.
//   - Announce, no Peer Up seen: the S bit walk, then one label.
//   - The prefix is at most 32 bits for AFI 1 and 128 for AFI 2 (§2.2,
//     RFC 7606 §5.3).
//   - A 4-octet Path Identifier precedes the Length with ADD-PATH (§2.2,
//     §2.3, RFC 7911 §3).
func TestLabeledUnicastRFC8277(t *testing.T) {
	cat := func(parts ...[]byte) []byte {
		var b []byte
		for _, p := range parts {
			b = append(b, p...)
		}
		return b
	}
	v4Host := []byte{0x0a, 0x00, 0x00, 0x01}                        // 10.0.0.1
	v6Net := []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x00} // 2001:db8:1::/64
	// fd00:1234:5678:9abc::/64, no 3 bytes of which read as a label with S=1.
	v6Alt := []byte{0xfd, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc}
	pathID := []byte{0x00, 0x00, 0x00, 0x07}
	// Length 32, label 1000 (S=1), 48.0.0.0/8, then an NLRI of Length 0.
	zeroLength := []byte{0x20, 0x00, 0x3e, 0x81, 0x30, 0x00, 0x3e, 0x81, 0x0a, 0x00, 0x00}
	v4NH := []byte{192, 0, 2, 1}
	v6NH := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}

	const (
		noPeerUp = iota
		absent
		confirmed
		// Both OPENs list the capability for AFI/SAFI afi/128 only, so SAFI
		// 4 uses the RFC 8277 §2.2 encoding (§2.3).
		vpnOnly
	)
	// Peer Up capabilities for AFI afi SAFI 4.
	// ap is the ADD-PATH Send/Receive value, 0 for none.
	caps := func(afi byte, state int, ap byte) bgp.Capability {
		c := bgp.Capability{}
		switch state {
		case confirmed:
			c[8] = []*bgp.CapabilityData{{Value: []byte{0x00, afi, 4, 0x02}}}
		case vpnOnly:
			c[8] = []*bgp.CapabilityData{{Value: []byte{0x00, afi, 128, 0x02}}}
		}
		if ap != 0 {
			c[69] = []*bgp.CapabilityData{{Value: []byte{0x00, afi, 4, ap}}}
		}
		return c
	}
	tests := []struct {
		name    string
		state   int
		addPath bool // Send/Receive (3) in both OPENs
		// ADD-PATH Send/Receive values of the sent and received OPENs, used
		// in place of addPath when set.
		apSent, apRecv byte
		afi            byte
		withdraw       bool
		nlri           []byte
		// Expected route; nothing published if prefix is empty.
		labels []uint32
		prefix string
		len    int32
		pathID int32
	}{
		// RFC 8277 §2.4: the Compatibility field MUST be ignored on reception.
		{name: "v4 withdraw compatibility 0x000640", state: absent, afi: 1, withdraw: true, nlri: cat([]byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: "10.0.0.1", len: 32},
		{name: "v4 withdraw compatibility 0x000000", state: noPeerUp, afi: 1, withdraw: true, nlri: cat([]byte{0x30, 0x00, 0x00, 0x00}, v4Host[:3]), prefix: "10.0.0.0", len: 24},
		{name: "v4 withdraw compatibility 0x000640, confirmed", state: confirmed, afi: 1, withdraw: true, nlri: cat([]byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: "10.0.0.1", len: 32},
		{name: "v6 withdraw compatibility 0x000640", state: absent, afi: 2, withdraw: true, nlri: cat([]byte{0x58, 0x00, 0x06, 0x40}, v6Net), prefix: "2001:db8:1::", len: 64},

		// RFC 8277 §2.2: on an announcement, 0x800000 is label 524288, not
		// the withdraw Compatibility value.
		{name: "v4 first label 0x800000, absent", state: absent, afi: 1, nlri: cat([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: "10.0.0.1", len: 32},
		{name: "v4 first label 0x800000, no Peer Up", state: noPeerUp, afi: 1, nlri: cat([]byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: "10.0.0.1", len: 32},
		{name: "v4 labels 0x800000 and 200, confirmed", state: confirmed, afi: 1, nlri: cat([]byte{0x50, 0x80, 0x00, 0x00, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{0x80000, 200}, prefix: "10.0.0.1", len: 32},
		{name: "v6 first label 0x800000, absent", state: absent, afi: 2, nlri: cat([]byte{0x58, 0x80, 0x00, 0x00}, v6Net), labels: []uint32{0x80000}, prefix: "2001:db8:1::", len: 64},
		{name: "v6 first label 0x800001, no Peer Up", state: noPeerUp, afi: 2, nlri: cat([]byte{0x58, 0x80, 0x00, 0x01}, v6Net), labels: []uint32{0x80000}, prefix: "2001:db8:1::", len: 64},

		// RFC 8277 §2.2: without the capability the S bit MUST be ignored.
		{name: "v4 one label S=0, absent", state: absent, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: "10.0.0.1", len: 32},
		{name: "v4 one label S=0, no Peer Up", state: noPeerUp, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: "10.0.0.1", len: 32},
		{name: "v6 one label S=0, absent", state: absent, afi: 2, nlri: cat([]byte{0x58, 0x00, 0x3e, 0x80}, v6Net), labels: []uint32{1000}, prefix: "2001:db8:1::", len: 64},
		{name: "v6 one label S=0, no Peer Up", state: noPeerUp, afi: 2, nlri: cat([]byte{0x58, 0x00, 0x3e, 0x80}, v6Alt), labels: []uint32{1000}, prefix: "fd00:1234:5678:9abc::", len: 64},
		{name: "v6 first label 0x800000, no Peer Up", state: noPeerUp, afi: 2, nlri: cat([]byte{0x58, 0x80, 0x00, 0x00}, v6Alt), labels: []uint32{0x80000}, prefix: "fd00:1234:5678:9abc::", len: 64},
		// RFC 8277 §2.3: with the capability the stack ends at S=1, so a
		// single label with S=0 cannot be parsed.
		{name: "v4 one label S=0, capability for SAFI 128 only", state: vpnOnly, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: "10.0.0.1", len: 32},
		{name: "v6 two labels, capability for SAFI 128 only", state: vpnOnly, afi: 2, nlri: cat([]byte{0x70, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v6Net), labels: []uint32{100}, prefix: "c:8120:10d:b800:100::", len: 88},
		{name: "v4 one label S=0, confirmed", state: confirmed, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, v4Host)},

		// Two labels, 100 (S=0) and 200 (S=1).
		{name: "v4 two labels, confirmed", state: confirmed, afi: 1, nlri: cat([]byte{0x50, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{100, 200}, prefix: "10.0.0.1", len: 32},
		{name: "v4 two labels, no Peer Up", state: noPeerUp, afi: 1, nlri: cat([]byte{0x50, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{100, 200}, prefix: "10.0.0.1", len: 32},
		// One label would leave a 56-bit IPv4 prefix, so the S bit walk is used.
		{name: "v4 two labels, absent", state: absent, afi: 1, nlri: cat([]byte{0x50, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{100, 200}, prefix: "10.0.0.1", len: 32},
		{name: "v6 two labels, confirmed", state: confirmed, afi: 2, nlri: cat([]byte{0x70, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v6Net), labels: []uint32{100, 200}, prefix: "2001:db8:1::", len: 64},
		{name: "v6 two labels, no Peer Up", state: noPeerUp, afi: 2, nlri: cat([]byte{0x70, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v6Net), labels: []uint32{100, 200}, prefix: "2001:db8:1::", len: 64},
		// RFC 8277 §2.1, §2.2: without the capability a sender MUST NOT
		// bind two labels; one label leaves a valid 88-bit IPv6 prefix and
		// is the reading the RFC requires.
		{name: "v6 two labels, absent", state: absent, afi: 2, nlri: cat([]byte{0x70, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v6Net), labels: []uint32{100}, prefix: "c:8120:10d:b800:100::", len: 88},

		// Prefix bytes that read as a label with S=1: label 1000 (S=0) then
		// 10.0.1.1/32, whose first three bytes are label 40960 with S=1.
		{name: "v4 label-like prefix, absent", state: absent, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, []byte{0x0a, 0x00, 0x01, 0x01}), labels: []uint32{1000}, prefix: "10.0.1.1", len: 32},
		// With the capability unknown the S bit walk goes first and wins.
		{name: "v4 label-like prefix, no Peer Up", state: noPeerUp, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, []byte{0x0a, 0x00, 0x01, 0x01}), labels: []uint32{1000, 40960}, prefix: "1.0.0.0", len: 8},
		// Label 1000 (S=0) then 2001:db8::/32, whose first bytes read as
		// label 8193 with S=1.
		// 2001:db8:1::/64 after an S=0 label reads as label 131088 with S=1
		// and b800:100::/40 when the capability is unknown.
		{name: "v6 label-like prefix, no Peer Up", state: noPeerUp, afi: 2, nlri: cat([]byte{0x58, 0x00, 0x3e, 0x80}, v6Net), labels: []uint32{1000, 131088}, prefix: "b800:100::", len: 40},
		{name: "v6 label-like prefix, absent", state: absent, afi: 2, nlri: cat([]byte{0x38, 0x00, 0x3e, 0x80}, []byte{0x20, 0x01, 0x0d, 0xb8}), labels: []uint32{1000}, prefix: "2001:db8::", len: 32},

		// RFC 8277 §2.2, RFC 7606 §5.3: the prefix length after the label
		// is at most 32 bits for AFI 1 and 128 for AFI 2.
		{name: "v4 prefix of 40 bits", state: absent, afi: 1, nlri: cat([]byte{0x40, 0x00, 0x06, 0x41}, v4Host, []byte{0x00})},
		{name: "v4 prefix of 33 bits, no Peer Up", state: noPeerUp, afi: 1, nlri: cat([]byte{0x39, 0x00, 0x06, 0x41}, v4Host, []byte{0x00})},
		{name: "v4 withdraw prefix of 40 bits", state: absent, afi: 1, withdraw: true, nlri: cat([]byte{0x40, 0x80, 0x00, 0x00}, v4Host, []byte{0x00})},
		{name: "v4 prefix of 32 bits", state: absent, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: "10.0.0.1", len: 32},
		{name: "v6 prefix of 136 bits", state: absent, afi: 2, nlri: cat([]byte{0xa0, 0x00, 0x06, 0x41}, v6Net, v6Net, []byte{0x00})},
		{name: "v6 prefix of 128 bits", state: absent, afi: 2, nlri: cat([]byte{0x98, 0x00, 0x06, 0x41}, v6Net, v6Net), labels: []uint32{100}, prefix: "2001:db8:1:0:2001:db8:1:0", len: 128},

		// ADD-PATH (RFC 7911 §3): the Path Identifier precedes the Length.
		{name: "v4 ADD-PATH first label 0x800000", state: absent, addPath: true, afi: 1, nlri: cat(pathID, []byte{0x38, 0x80, 0x00, 0x00}, v4Host), labels: []uint32{0x80000}, prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v4 ADD-PATH one label S=0", state: absent, addPath: true, afi: 1, nlri: cat(pathID, []byte{0x38, 0x00, 0x3e, 0x80}, v4Host), labels: []uint32{1000}, prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v4 ADD-PATH two labels, confirmed", state: confirmed, addPath: true, afi: 1, nlri: cat(pathID, []byte{0x50, 0x00, 0x06, 0x40, 0x00, 0x0c, 0x81}, v4Host), labels: []uint32{100, 200}, prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v4 ADD-PATH withdraw compatibility 0x000640", state: absent, addPath: true, afi: 1, withdraw: true, nlri: cat(pathID, []byte{0x38, 0x00, 0x06, 0x40}, v4Host), prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v4 ADD-PATH prefix of 40 bits", state: absent, addPath: true, afi: 1, nlri: cat(pathID, []byte{0x40, 0x00, 0x06, 0x41}, v4Host, []byte{0x00})},
		{name: "v6 ADD-PATH first label 0x800000", state: absent, addPath: true, afi: 2, nlri: cat(pathID, []byte{0x58, 0x80, 0x00, 0x00}, v6Net), labels: []uint32{0x80000}, prefix: "2001:db8:1::", len: 64, pathID: 7},
		{name: "v6 ADD-PATH withdraw compatibility 0x000640", state: absent, addPath: true, afi: 2, withdraw: true, nlri: cat(pathID, []byte{0x58, 0x00, 0x06, 0x40}, v6Net), prefix: "2001:db8:1::", len: 64, pathID: 7},
		// Path Identifiers present while ADD-PATH is not known for the
		// table: decoded by retrying with the Path ID flag flipped.
		{name: "v4 Path ID, no Peer Up", state: noPeerUp, afi: 1, nlri: cat(pathID, []byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v6 Path ID, no Peer Up", state: noPeerUp, afi: 2, nlri: cat(pathID, []byte{0x58, 0x00, 0x06, 0x41}, v6Net), labels: []uint32{100}, prefix: "2001:db8:1::", len: 64, pathID: 7},

		// A malformed field (the second NLRI has Length 0) reads as one
		// route with Path ID 0x20003e81 when the retry assumes Path IDs.
		{name: "v4 zero Length, no Peer Up", state: noPeerUp, afi: 1, nlri: zeroLength, labels: []uint32{1000}, prefix: "10.0.0.0", len: 24, pathID: 0x20003e81},
		{name: "v4 zero Length, ADD-PATH off", state: absent, afi: 1, nlri: zeroLength, labels: []uint32{1000}, prefix: "10.0.0.0", len: 24, pathID: 0x20003e81},
		// ADD-PATH on: NLRI without Path IDs are read by the retry.
		{name: "v4 no Path ID, ADD-PATH on", state: absent, addPath: true, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: "10.0.0.1", len: 32},
		{name: "v6 no Path ID, ADD-PATH on", state: absent, addPath: true, afi: 2, nlri: cat([]byte{0x58, 0x00, 0x06, 0x41}, v6Net), labels: []uint32{100}, prefix: "2001:db8:1::", len: 64},
		// ADD-PATH in one direction only (RFC 7911 §5): read with the Path
		// ID flag flipped when the first parse fails.
		{name: "v4 Path ID, ADD-PATH receive/send", state: absent, apSent: 1, apRecv: 2, afi: 1, nlri: cat(pathID, []byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: "10.0.0.1", len: 32, pathID: 7},
		{name: "v4 no Path ID, ADD-PATH send/both", state: absent, apSent: 2, apRecv: 3, afi: 1, nlri: cat([]byte{0x38, 0x00, 0x06, 0x41}, v4Host), labels: []uint32{100}, prefix: "10.0.0.1", len: 32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub := &recordingPublisher{}
			p := NewProducer(pub, false).(*producer)
			ph := makePeerHeader(t, bmp.PeerType0, 0x00)
			if tt.state != noPeerUp {
				peerUp := buildPeerUpMessage(t, "192.168.1.1")
				apSent, apRecv := tt.apSent, tt.apRecv
				if tt.addPath {
					apSent, apRecv = 3, 3
				}
				peerUp.SentOpen.Capabilities = caps(tt.afi, tt.state, apSent)
				peerUp.ReceivedOpen.Capabilities = caps(tt.afi, tt.state, apRecv)
				p.producingWorker(bmp.Message{PeerHeader: ph, Payload: peerUp, SpeakerIP: "10.2.1.3"})
			}

			var attr []byte
			if tt.withdraw {
				attr = luTestAttr(0x0f, tt.afi, nil, tt.nlri)
			} else {
				nh := v4NH
				if tt.afi == 2 {
					nh = v6NH
				}
				attr = luTestAttr(0x0e, tt.afi, nh, tt.nlri)
			}
			p.produceRouteMonitorMessage(bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: testUpdate(t, attr)}})

			var got []UnicastPrefix
			for _, m := range pub.msgs {
				if m.msgType != bmp.UnicastPrefixMsg {
					continue
				}
				var u UnicastPrefix
				if err := json.Unmarshal(m.payload, &u); err != nil {
					t.Fatalf("json.Unmarshal() error: %v", err)
				}
				got = append(got, u)
			}
			if tt.prefix == "" {
				if len(got) != 0 {
					t.Fatalf("published %+v for a malformed NLRI, want nothing", got)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("published %d unicast prefixes, want 1: %+v", len(got), got)
			}
			u := got[0]
			wantAction := "add"
			if tt.withdraw {
				wantAction = "del"
			}
			if u.Action != wantAction || u.Prefix != tt.prefix || u.PrefixLen != tt.len || u.PathID != tt.pathID {
				t.Errorf("published %s %s/%d path %d, want %s %s/%d path %d",
					u.Action, u.Prefix, u.PrefixLen, u.PathID, wantAction, tt.prefix, tt.len, tt.pathID)
			}
			if !reflect.DeepEqual(u.Labels, tt.labels) {
				t.Errorf("labels = %v, want %v", u.Labels, tt.labels)
			}
		})
	}
}
