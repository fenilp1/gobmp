package bmp

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// mirrorTLV encodes a Route Mirroring TLV (RFC 7854 §4.7).
func mirrorTLV(t uint16, v []byte) []byte {
	b := make([]byte, 4, 4+len(v))
	binary.BigEndian.PutUint16(b[0:], t)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	return append(b, v...)
}

// bgpPDU returns a BGP PDU of length n with the given marker byte and type; the body is zero.
func bgpPDU(marker byte, msgType uint8, n int) []byte {
	b := make([]byte, n)
	copy(b, bytes.Repeat([]byte{marker}, 16))
	binary.BigEndian.PutUint16(b[16:], uint16(n))
	b[18] = msgType
	return b
}

// bgpKeepalive is a 19-byte BGP KEEPALIVE PDU: all-ones marker, length 19, type 4.
func bgpKeepalive() []byte {
	return bgpPDU(0xff, 4, 19)
}

// bgpErroredUpdate is a 23-byte BGP UPDATE whose Total Path Attribute Length (0xffff)
// overruns the PDU, so it must not be decoded beyond its header.
func bgpErroredUpdate() []byte {
	b := bytes.Repeat([]byte{0xff}, 16)
	return append(b, 0x00, 0x17, 0x02, 0x00, 0x00, 0xff, 0xff)
}

func TestUnmarshalRouteMirrorMessage(t *testing.T) {
	extended := bgpPDU(0xff, 2, 5000) // RFC 8654 Extended Message
	zeroMarker := bgpPDU(0x00, 4, 19)
	tests := []struct {
		name         string
		input        []byte
		want         []RouteMirrorTLV
		wantWarnings int
	}{
		{
			name:  "no TLVs",
			input: []byte{},
			want:  []RouteMirrorTLV{},
		},
		{
			name:  "single BGP Message TLV",
			input: mirrorTLV(RouteMirrorTLVBGPMessage, bgpKeepalive()),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVBGPMessage, Value: bgpKeepalive(), BGPLength: 19, BGPType: 4},
			},
		},
		{
			name: "Errored PDU followed by BGP Message",
			input: append(mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x00}),
				mirrorTLV(RouteMirrorTLVBGPMessage, bgpErroredUpdate())...),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x00}, InfoCode: RouteMirrorInfoErroredPDU},
				{Type: RouteMirrorTLVBGPMessage, Value: bgpErroredUpdate(), BGPLength: 23, BGPType: 2},
			},
		},
		{
			name:  "Messages Lost alone",
			input: mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x01}),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x01}, InfoCode: RouteMirrorInfoMessagesLost},
			},
		},
		{
			name: "unknown TLV type retained raw",
			input: append(mirrorTLV(0x8000, []byte{0xde, 0xad}),
				mirrorTLV(RouteMirrorTLVBGPMessage, bgpKeepalive())...),
			want: []RouteMirrorTLV{
				{Type: 0x8000, Value: []byte{0xde, 0xad}},
				{Type: RouteMirrorTLVBGPMessage, Value: bgpKeepalive(), BGPLength: 19, BGPType: 4},
			},
		},
		{
			name:  "BGP length field not matching the PDU is reported as found",
			input: mirrorTLV(RouteMirrorTLVBGPMessage, append(bgpKeepalive()[:16], 0x00, 0x40, 0x04)),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVBGPMessage, Value: append(bgpKeepalive()[:16], 0x00, 0x40, 0x04), BGPLength: 64, BGPType: 4},
			},
		},
		{
			name:  "extended BGP message longer than 4096 bytes",
			input: mirrorTLV(RouteMirrorTLVBGPMessage, extended),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVBGPMessage, Value: extended, BGPLength: 5000, BGPType: 2},
			},
		},
		{
			name:  "marker not all ones is reported as found",
			input: mirrorTLV(RouteMirrorTLVBGPMessage, zeroMarker),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVBGPMessage, Value: zeroMarker, BGPLength: 19, BGPType: 4},
			},
		},
		{
			// Reviewer repro: Messages Lost next to a 2-byte BGP Message TLV.
			name:  "BGP PDU shorter than 19 bytes kept as malformed next to Messages Lost",
			input: []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff},
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x01}, InfoCode: RouteMirrorInfoMessagesLost},
				{Type: RouteMirrorTLVBGPMessage, Value: []byte{0xff, 0xff}, Malformed: true},
			},
			wantWarnings: 1,
		},
		{
			name:         "18-byte BGP PDU kept as malformed",
			input:        mirrorTLV(RouteMirrorTLVBGPMessage, bgpKeepalive()[:18]),
			want:         []RouteMirrorTLV{{Type: RouteMirrorTLVBGPMessage, Value: bgpKeepalive()[:18], Malformed: true}},
			wantWarnings: 1,
		},
		{
			name:         "empty BGP PDU kept as malformed",
			input:        mirrorTLV(RouteMirrorTLVBGPMessage, nil),
			want:         []RouteMirrorTLV{{Type: RouteMirrorTLVBGPMessage, Value: []byte{}, Malformed: true}},
			wantWarnings: 1,
		},
		{
			name:         "Information TLV shorter than 2 bytes kept as malformed",
			input:        mirrorTLV(RouteMirrorTLVInformation, []byte{0x00}),
			want:         []RouteMirrorTLV{{Type: RouteMirrorTLVInformation, Value: []byte{0x00}, Malformed: true}},
			wantWarnings: 1,
		},
		{
			name:         "Information TLV longer than 2 bytes decodes its code",
			input:        mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x01, 0xaa}),
			want:         []RouteMirrorTLV{{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x01, 0xaa}, InfoCode: RouteMirrorInfoMessagesLost}},
			wantWarnings: 1,
		},
		{
			name:         "Errored PDU without a BGP Message",
			input:        mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x00}),
			want:         []RouteMirrorTLV{{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x00}, InfoCode: RouteMirrorInfoErroredPDU}},
			wantWarnings: 1,
		},
		{
			name: "BGP Message not the last TLV",
			input: append(mirrorTLV(RouteMirrorTLVBGPMessage, bgpKeepalive()),
				mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x00})...),
			want: []RouteMirrorTLV{
				{Type: RouteMirrorTLVBGPMessage, Value: bgpKeepalive(), BGPLength: 19, BGPType: 4},
				{Type: RouteMirrorTLVInformation, Value: []byte{0x00, 0x00}, InfoCode: RouteMirrorInfoErroredPDU},
			},
			wantWarnings: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm, err := UnmarshalRouteMirrorMessage(tt.input)
			if err != nil {
				t.Fatalf("UnmarshalRouteMirrorMessage() error = %v", err)
			}
			if len(rm.TLVs) != len(tt.want) {
				t.Fatalf("got %d TLVs, want %d: %+v", len(rm.TLVs), len(tt.want), rm.TLVs)
			}
			for i, want := range tt.want {
				got := rm.TLVs[i]
				if got.Type != want.Type || !bytes.Equal(got.Value, want.Value) || got.Malformed != want.Malformed ||
					got.BGPLength != want.BGPLength || got.BGPType != want.BGPType || got.InfoCode != want.InfoCode {
					t.Errorf("TLV %d = %+v, want %+v", i, got, want)
				}
			}
			if w := routeMirrorWarnings(rm.TLVs); len(w) != tt.wantWarnings {
				t.Errorf("routeMirrorWarnings() = %q, want %d warnings", w, tt.wantWarnings)
			}
		})
	}
}

// TestUnmarshalRouteMirrorMessageErrors covers truncated TLV framing, after which
// the rest of the message cannot be parsed.
func TestUnmarshalRouteMirrorMessageErrors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{name: "truncated TLV type", input: []byte{0x00}},
		{name: "truncated TLV length", input: []byte{0x00, 0x00, 0x00}},
		{name: "truncated TLV value", input: mirrorTLV(RouteMirrorTLVBGPMessage, bgpKeepalive())[:10]},
		{name: "value truncated after a valid TLV", input: append(mirrorTLV(RouteMirrorTLVInformation, []byte{0x00, 0x01}), 0x00, 0x00, 0x00, 0x05, 0x01)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm, err := UnmarshalRouteMirrorMessage(tt.input)
			if err == nil {
				t.Fatalf("UnmarshalRouteMirrorMessage() = %+v, want an error", rm)
			}
			if rm != nil {
				t.Errorf("UnmarshalRouteMirrorMessage() returned %+v with error", rm)
			}
		})
	}
}
