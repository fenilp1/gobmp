// Package fuzzseed holds seed inputs and helpers shared by the decoder fuzz
// tests. It is imported only from _test.go files.
package fuzzseed

import (
	"encoding/binary"
	"flag"
	"os"
	"testing"
)

// Quiet sends glog output to /dev/null in fuzz worker processes, so the
// fuzzer is not bound by log writes. The coordinator, which prints progress
// and failures, and normal test runs are left alone.
func Quiet(tb testing.TB) {
	if f := flag.Lookup("test.fuzzworker"); f == nil || f.Value.String() != "true" {
		return
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		return
	}
	// logtostderr disables glog's file sink; stderr is then /dev/null.
	_ = flag.Set("logtostderr", "true")
	stderr := os.Stderr
	os.Stderr = null
	tb.Cleanup(func() {
		os.Stderr = stderr
		_ = flag.Set("logtostderr", "false")
		_ = null.Close()
	})
}

// Attr encodes a BGP path attribute using the extended length format.
func Attr(flags, typ byte, v []byte) []byte {
	b := []byte{flags | 0x10, typ, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	return append(b, v...)
}

var srv6SID = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

func cat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

var (
	origin = Attr(0x40, 1, []byte{0})
	asPath = Attr(0x40, 2, []byte{2, 2, 0, 0, 0xfd, 0xe9, 0, 0, 0xfd, 0xeb})
)

// Attrs are path attributes covering the decoders most exposed to untrusted
// input, including the inputs of previously fixed crashes.
var Attrs = [][]byte{
	origin,
	asPath,
	Attr(0x40, 3, []byte{192, 0, 2, 1}),
	Attr(0x80, 4, []byte{0, 0, 0, 100}),
	Attr(0xc0, 8, []byte{0xfd, 0xe9, 0, 1}),
	Attr(0xc0, 16, []byte{0x00, 0x02, 0x00, 0x64, 0, 0, 0, 1}),
	Attr(0xc0, 32, []byte{0, 0, 0xfd, 0xe9, 0, 0, 0, 1, 0, 0, 0, 2}),
	// D-PATH (RFC 10039 §4): segments of one and two domains, then a segment
	// shorter than its domain count.
	Attr(0xc0, 36, []byte{1, 0, 0, 0xfd, 0xe8, 0, 1, 0x80, 2, 0, 0, 0xfd, 0xe9, 0, 2, 0x46, 192, 0, 2, 1, 0, 3, 0x80}),
	Attr(0xc0, 36, []byte{1, 0, 0, 0xfd, 0xe8, 0, 1, 0x80, 2, 0, 0, 0xfd, 0xe9, 0, 2, 0x46}),
	// MP_REACH_NLRI IPv6 unicast.
	Attr(0x80, 14, []byte{0, 2, 1, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 152, 183, 11, 0, 16, 0x20, 0x01}),
	// MP_REACH_NLRI BGP-LS Node NLRI (RFC 9552 §5.2).
	Attr(0x80, 14, []byte{
		0x40, 0x04, 0x47, 0x04, 0xc0, 0x00, 0x02, 0x02, 0x00,
		0x00, 0x01, 0x00, 0x1d, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x02,
		0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x04,
		0x00, 0x04, 0xc0, 0x00, 0x02, 0x01,
	}),
	// MP_UNREACH_NLRI IPv4 unicast.
	Attr(0x80, 15, []byte{0, 1, 1, 24, 10, 0, 0}),
	// Prefix-SID Label-Index (RFC 8669 §3.1).
	Attr(0xc0, 40, []byte{1, 0, 7, 0, 0, 0, 0, 0, 0, 0xa4}),
	srv6PrefixSID,
	// Crash: SID Structure sub-sub-TLV header without value.
	Attr(0xc0, 40, cat([]byte{5, 0, 0x1c, 0, 1, 0, 0x18, 0}, srv6SID,
		[]byte{0, 0, 0x13, 0, 1, 0, 0x10})),
	// BGP-LS attribute: SID Structure (RFC 9514 §8), node name, End.X SID.
	Attr(0x80, 29, cat([]byte{0x04, 0xe4, 0, 4, 32, 16, 16, 0, 0x04, 0x02, 0, 2, 'r', '1',
		0x04, 0x52, 0, 30, 0, 5, 0, 0, 0, 0}, srv6SID, []byte{0x04, 0xe4, 0, 4, 32, 16, 16, 0})),
	// Crash: SID Structure TLV of length 1.
	Attr(0x80, 29, []byte{0x04, 0xe4, 0, 1, 0}),
	// Crash: End.X SID with an empty SID Structure sub-TLV.
	Attr(0x80, 29, cat([]byte{0x04, 0x52, 0, 26, 0, 5, 0, 0, 0, 0}, srv6SID, []byte{0x04, 0xe4, 0, 0})),

	// MP_REACH_NLRI for every AFI/SAFI family the decoder supports. NLRI
	// payloads are taken from the per-family package tests.
	mpReach(25, 70, nh4, []byte{0x03, 0x11, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x20, 0xac, 0x1f, 0x65, 0x06}),                                                                                                 // EVPN IMET
	mpReach(25, 70, nh4, []byte{0x02, 0x21, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x00, 0x81, 0xc4, 0xbc, 0x77, 0x8a, 0x00, 0x18, 0xa9, 0x71}), // EVPN MAC/IP
	mpReach(1, 133, nil, []byte{0x05, 0x02, 0x18, 0x0a, 0x00, 0x07, 0x03, 0x03, 0x81, 0x2f}),                                                                                                                                                       // flowspec
	mpReach(2, 133, nil, []byte{0x07, 0x01, 0x20, 0x00, 0x20, 0x01, 0x0d, 0xb8}),                                                                                                                                                                   // IPv6 flowspec
	mpReach(1, 134, nh4, cat([]byte{0x0d}, rd, []byte{0x02, 0x18, 0x0a, 0x00, 0x07})),                                                                                                                                                              // VPN flowspec
	mpReach(1, 73, nh4, []byte{0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x63, 0x0a, 0x00, 0x00, 0x0d}),                                                                                                                                      // SR Policy
	mupReach,
	mpReach(1, 5, nh4, []byte{0x01, 0x0c, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01, 0x00, 0x01, 0x0a, 0x00, 0x00, 0x01}),                 // MCAST-VPN Intra-AS I-PMSI A-D
	mpReach(1, 129, nh4, []byte{0x04, 0x12, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0xc8, 10, 0, 0, 1, 10, 0, 0, 2}), // MVPN Leaf A-D
	mpReach(1, 2, nh4, []byte{24, 232, 1, 1}), // multicast
	mpReach(25, 65, nh4, []byte{0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x01, 0x00, 0x00, 0x00, 0x0a, 0x18, 0x6a, 0x00}), // VPLS
	mpReach(1, 132, nh4, []byte{0x60, 0x00, 0x00, 0xfd, 0xe8, 0x00, 0x02, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}),                                     // RTC
	mpReach(1, 128, cat(rdZero, nh4), []byte{120, 5, 220, 49, 0, 0, 2, 65, 0, 0, 253, 235, 3, 3, 3, 3}),                                            // L3VPN
	mpReach(1, 4, nh4, []byte{0x38, 0x00, 0x00, 0x31, 0x0a, 0x01, 0x02, 0x03}),                                                                     // labeled unicast
	mpReach(16388, 71, nh4, []byte{0x00, 0x02, 0x00, 0x73, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x1a, 0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0xfd, 0xe8, 0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x05, 0x00, 0x10, 0xfc, 0x00, 0xdd, 0xdd, 0x00, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x06, 0x00, 0x10, 0xfc, 0x00, 0xdd, 0xdd, 0x00, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x07, 0x00, 0x02, 0x00, 0x02}), // BGP-LS link
	mpReach(16388, 71, nh4, lsNLRI(3, lsNodeDesc, []byte{0x01, 0x09, 0x00, 0x04, 0x18, 0x09, 0x00, 0xcb})),                      // BGP-LS IPv4 prefix
	mpReach(16388, 71, nh4, lsNLRI(6, lsNodeDesc, []byte{0x01, 0x07, 0x00, 0x02, 0x00, 0x02, 0x02, 0x06, 0x00, 0x10}, srv6SID)), // BGP-LS SRv6 SID

	// PMSI Tunnel (RFC 6514 §5), from the pmsi package tests.
	Attr(0xc0, 22, []byte{0x00, 0x07, 0x0a, 0x00, 0x00, 0x01}),
	Attr(0xc0, 22, []byte{0x00, 0x06, 0x00, 0x00, 0x00, 192, 0, 2, 1}),
	// Tunnel Encapsulation (RFC 9012), from the tunnel encap tests.
	Attr(0xc0, 23, []byte{0x00, 0x0d, 0x00, 0x06, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x64}),
	srPolicyTunnelEncap,
	// NHC (draft-ietf-idr-nhc), from the bgp-nhc tests.
	Attr(0xc0, 39, []byte{0, 1, 1, 4, 198, 51, 100, 1, 0, 5, 0, 1, 0xaa, 0, 3, 0, 8, 192, 0, 2, 1, 0, 0, 0xfd, 0xe8}),
	// ATTR_SET (RFC 6368) embedding ORIGIN.
	Attr(0xc0, 128, []byte{0, 0, 0xfd, 0xea, 0x40, 0x01, 0x01, 0x00}),
}

var (
	// Prefix-SID SRv6 L3 Service with SID Structure (RFC 9252 §3.2.1).
	srv6PrefixSID = Attr(0xc0, 40, cat([]byte{5, 0, 0x22, 0, 1, 0, 0x1e, 0}, srv6SID,
		[]byte{0, 0, 0x13, 0, 1, 0, 6, 0x28, 0x18, 0x10, 0, 0x10, 0x40}))
	nh4    = []byte{192, 0, 2, 1}
	rd     = []byte{0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x01}
	rdZero = make([]byte, 8)
	// BGP-LS NLRI header body: Protocol-ID 2, Identifier 0, Local Node
	// Descriptors (AS 5070, BGP-LS ID 0, IGP Router-ID).
	lsNodeDesc = []byte{
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x1a,
		0x02, 0x00, 0x00, 0x04, 0x00, 0x00, 0x13, 0xce,
		0x02, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x03, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x93,
	}
	// SR Policy Tunnel Encapsulation (RFC 9256), from the srpolicy tests.
	srPolicyTunnelEncap = Attr(0xc0, 23, []byte{0x00, 0x0f, 0x00, 0x48, 0x0c, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0d, 0x06, 0x00, 0x00, 0xdb, 0xba, 0x00, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6a, 0xa0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xdc, 0x10, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00, 0x18, 0x6a, 0xa0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xdc, 0xd0, 0x00})
)

// lsNLRI encodes a BGP-LS NLRI (RFC 9552 §5.2) of type t.
func lsNLRI(t uint16, body ...[]byte) []byte {
	v := cat(body...)
	return cat([]byte{byte(t >> 8), byte(t), byte(len(v) >> 8), byte(len(v))}, v)
}

// mupReach is a MUP Interwork Segment Discovery route; MUP routes are
// produced only with an SRv6 Prefix-SID.
var mupReach = mpReach(1, 85, nh4, []byte{0x01, 0x00, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x18, 0x0a, 0x0a, 0x0a})

// mpReach encodes an MP_REACH_NLRI attribute (RFC 4760 §3).
func mpReach(afi uint16, safi byte, nh, nlri []byte) []byte {
	v := []byte{byte(afi >> 8), byte(afi), safi, byte(len(nh))}
	return Attr(0x80, 14, cat(v, nh, []byte{0}, nlri))
}

// UpdateBody encodes the body of a BGP UPDATE (after the 19-byte header).
func UpdateBody(attrs, nlri []byte) []byte {
	b := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(attrs)))
	return cat(b, attrs, nlri)
}

// Message encodes a full BGP message (marker, length, type) around body.
func Message(typ byte, body []byte) []byte {
	b := make([]byte, 19, 19+len(body))
	for i := 0; i < 16; i++ {
		b[i] = 0xff
	}
	binary.BigEndian.PutUint16(b[16:], uint16(19+len(body)))
	b[18] = typ
	return append(b, body...)
}

// UpdateBodies returns BGP UPDATE bodies, one per seed attribute plus
// origin/AS_PATH and one carrying every attribute.
func UpdateBodies() [][]byte {
	var out [][]byte
	for _, a := range Attrs {
		out = append(out, UpdateBody(cat(origin, asPath, a), nil))
	}
	// SR Policy routes need both the SAFI 73 NLRI and the Tunnel Encapsulation.
	srPolicyReach := mpReach(1, 73, nh4, []byte{0x60, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x63, 0x0a, 0x00, 0x00, 0x0d})
	out = append(out, UpdateBody(cat(origin, asPath, srPolicyReach, srPolicyTunnelEncap), nil))
	out = append(out, UpdateBody(cat(origin, asPath, mupReach, srv6PrefixSID), nil))
	out = append(out, UpdateBody(cat(Attrs...), []byte{24, 192, 0, 2}))
	return out
}

// OpenBodies returns BGP OPEN messages as passed to bgp.UnmarshalBGPOpenMessage
// (without the marker): a typical OPEN and the 4-octet AS crash input.
func OpenBodies() [][]byte {
	caps := []byte{
		2, 6, 1, 4, 0, 1, 0, 1, // MP IPv4 unicast
		2, 6, 1, 4, 0x40, 0x04, 0, 0x47, // MP BGP-LS
		2, 2, 2, 0, // route refresh
		2, 6, 0x41, 4, 0, 0, 0xfd, 0xe8, // 4-octet AS
		2, 6, 0x45, 4, 0, 1, 1, 3, // ADD-PATH
		2, 3, 9, 1, 3, // BGP Role
	}
	return [][]byte{
		openBody(caps),
		openBody([]byte{2, 2, 0x41, 0}),
	}
}

func openBody(opt []byte) []byte {
	b := []byte{0, 0, 1, 4, 0xfd, 0xe8, 0, 0xb4, 192, 0, 2, 1, byte(len(opt))}
	b = append(b, opt...)
	binary.BigEndian.PutUint16(b, uint16(16+len(b)))
	return b
}

// PeerUpBody encodes a BMP Peer Up body (after the per-peer header).
func PeerUpBody(open []byte) []byte {
	marker := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	b := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 192, 0, 2, 2, 0, 179, 0x9c, 0x40}
	return cat(b, marker, open, marker, open)
}

// PerPeerHeader is a BMP per-peer header (RFC 7854 §4.2) for an IPv4 peer.
var PerPeerHeader = cat(make([]byte, 22), []byte{192, 0, 2, 1, 0, 0, 0xfd, 0xe8, 192, 0, 2, 1}, make([]byte, 8))

// BMP encodes a BMP message (RFC 7854 §4.1) of type typ around body.
func BMP(typ byte, body []byte) []byte {
	b := []byte{3, 0, 0, 0, 0, typ}
	binary.BigEndian.PutUint32(b[1:], uint32(6+len(body)))
	return append(b, body...)
}

// BMPMessages returns one BMP message of each type, with Route Monitoring
// messages for every seed UPDATE and Peer Up messages for every seed OPEN.
func BMPMessages() [][]byte {
	var out [][]byte
	for _, u := range UpdateBodies() {
		out = append(out, BMP(0, cat(PerPeerHeader, Message(2, u))))
	}
	for _, o := range OpenBodies() {
		out = append(out, BMP(3, cat(PerPeerHeader, PeerUpBody(o))))
	}
	out = append(out,
		BMP(1, cat(PerPeerHeader, []byte{0, 0, 0, 1, 0, 7, 0, 8, 0, 0, 0, 0, 0, 0, 0, 5})),
		BMP(2, cat(PerPeerHeader, []byte{1}, Message(3, []byte{6, 2}))),
		BMP(4, []byte{0, 2, 0, 2, 'r', '1'}),
		BMP(5, []byte{0, 1, 0, 2, 0, 0}),
	)
	return out
}
