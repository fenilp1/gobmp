package message

import (
	"encoding/binary"
	"fmt"
	"net"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// This file benchmarks the Producer per AFI/SAFI. Each case is the wire
// encoding of one BGP UPDATE (RFC 4271 §4.3) carried by a Route Monitoring
// message, with the path attributes of a typical Internet or VPN route plus
// those its family needs.

// benchPathAttr encodes a path attribute (RFC 4271 §4.3) with flags, type
// code and value, setting the Extended Length bit when the value needs it.
func benchPathAttr(flags, code byte, value []byte) []byte {
	if len(value) > 255 {
		flags |= 0x10
	}
	b := []byte{flags, code}
	if flags&0x10 != 0 {
		b = binary.BigEndian.AppendUint16(b, uint16(len(value)))
	} else {
		b = append(b, byte(len(value)))
	}
	return append(b, value...)
}

// Path attribute flags (RFC 4271 §4.3).
const (
	benchWellKnown   = 0x40 // well-known, transitive
	benchOptional    = 0x80 // optional, non-transitive
	benchOptionalTra = 0xc0 // optional, transitive
)

// benchMPReach returns MP_REACH_NLRI (RFC 4760 §3).
func benchMPReach(afi uint16, safi byte, nh, nlri []byte) []byte {
	v := binary.BigEndian.AppendUint16(nil, afi)
	v = append(v, safi, byte(len(nh)))
	v = append(v, nh...)
	v = append(v, 0x00) // Reserved
	v = append(v, nlri...)
	return benchPathAttr(benchOptional, bgp.MP_REACH_NLRI, v)
}

// benchMPUnreach returns MP_UNREACH_NLRI (RFC 4760 §4).
func benchMPUnreach(afi uint16, safi byte, withdrawn []byte) []byte {
	v := binary.BigEndian.AppendUint16(nil, afi)
	v = append(v, safi)
	v = append(v, withdrawn...)
	return benchPathAttr(benchOptional, bgp.MP_UNREACH_NLRI, v)
}

// benchRT returns a Route Target extended community, 2-octet AS specific
// (RFC 4360 §4).
func benchRT(as uint16, n uint32) []byte {
	b := []byte{0x00, 0x02}
	b = binary.BigEndian.AppendUint16(b, as)
	return binary.BigEndian.AppendUint32(b, n)
}

// benchCommonAttrs returns ORIGIN IGP, AS_PATH of five 4-octet ASNs, NEXT_HOP
// nextHop when not nil, MULTI_EXIT_DISC, LOCAL_PREF, four COMMUNITIES (RFC
// 1997), two Route Target EXTENDED COMMUNITIES and extComms (RFC 4360) and
// two LARGE_COMMUNITY (RFC 8092).
func benchCommonAttrs(nextHop []byte, extComms ...[]byte) [][]byte {
	asPath := []byte{0x02, 5} // AS_SEQUENCE
	for _, as := range []uint32{65001, 3356, 1299, 2914, 13335} {
		asPath = binary.BigEndian.AppendUint32(asPath, as)
	}
	attrs := [][]byte{
		benchPathAttr(benchWellKnown, 1, []byte{0x00}),
		benchPathAttr(benchWellKnown, 2, asPath),
	}
	if nextHop != nil {
		attrs = append(attrs, benchPathAttr(benchWellKnown, 3, nextHop))
	}
	var comms []byte
	for _, c := range [][2]uint16{{65001, 100}, {65001, 200}, {3356, 2}, {3356, 501}} {
		comms = binary.BigEndian.AppendUint16(comms, c[0])
		comms = binary.BigEndian.AppendUint16(comms, c[1])
	}
	ec := append(benchRT(65001, 1), benchRT(65001, 2)...)
	for _, c := range extComms {
		ec = append(ec, c...)
	}
	var large []byte
	for _, c := range [][3]uint32{{65001, 1, 1}, {65001, 2, 2}} {
		for _, v := range c {
			large = binary.BigEndian.AppendUint32(large, v)
		}
	}
	return append(attrs,
		benchPathAttr(benchOptional, 4, binary.BigEndian.AppendUint32(nil, 100)),
		benchPathAttr(benchWellKnown, 5, binary.BigEndian.AppendUint32(nil, 200)),
		benchPathAttr(benchOptionalTra, 8, comms),
		benchPathAttr(benchOptionalTra, 16, ec),
		benchPathAttr(benchOptionalTra, 32, large),
	)
}

// benchUpdate returns a BGP UPDATE message body (RFC 4271 §4.3) with the
// Withdrawn Routes, the path attributes sorted by type code and the NLRI.
func benchUpdate(withdrawn []byte, attrs [][]byte, nlri []byte) []byte {
	sort.SliceStable(attrs, func(i, j int) bool { return attrs[i][1] < attrs[j][1] })
	var pa []byte
	for _, a := range attrs {
		pa = append(pa, a...)
	}
	b := binary.BigEndian.AppendUint16(nil, uint16(len(withdrawn)))
	b = append(b, withdrawn...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(pa)))
	b = append(b, pa...)
	return append(b, nlri...)
}

// benchPeerHeader returns a Global Instance Peer header (RFC 7854 §4.2) for
// the IPv4 peer addr, AS 65000, with BGP ID bgpID and a peer timestamp as a
// router sets it.
func benchPeerHeader(addr, bgpID string) *bmp.PerPeerHeader {
	b := []byte{byte(bmp.PeerType0), 0}
	b = append(b, make([]byte, 8)...)  // Peer Distinguisher
	b = append(b, make([]byte, 12)...) // IPv4 peer address
	b = append(b, net.ParseIP(addr).To4()...)
	b = append(b, 0x00, 0x00, 0xfd, 0xe8) // AS 65000
	b = append(b, net.ParseIP(bgpID).To4()...)
	b = append(b, 0x68, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00)
	ph, err := bmp.UnmarshalPerPeerHeader(b)
	if err != nil {
		panic(err)
	}
	return attachDefaultTestIdentity(ph)
}

// benchPeerUp returns a Peer Up message for ph.
func benchPeerUp(ph *bmp.PerPeerHeader) bmp.Message {
	local := make([]byte, 16)
	copy(local[10:], []byte{0xff, 0xff, 192, 168, 1, 1})
	return bmp.Message{
		PeerHeader: ph,
		Payload: &bmp.PeerUpMessage{
			LocalAddress: local,
			LocalPort:    179,
			RemotePort:   45678,
			SentOpen:     &bgp.OpenMessage{Version: 4, MyAS: 65000, HoldTime: 90, BGPID: []byte{10, 0, 0, 1}},
			ReceivedOpen: &bgp.OpenMessage{Version: 4, MyAS: 65001, HoldTime: 90, BGPID: []byte{10, 0, 0, 2}},
		},
		SpeakerIP: "10.2.1.3",
	}
}

// benchCountingPublisher counts the messages published and closes done once
// it has counted want.
type benchCountingPublisher struct {
	n    atomic.Int64
	want int64
	done chan struct{}
}

func (c *benchCountingPublisher) PublishMessage(int, []byte, []byte) error {
	if c.n.Add(1) == c.want {
		close(c.done)
	}
	return nil
}

func (c *benchCountingPublisher) Stop() {}

// benchPrefixSIDAttr returns a BGP Prefix-SID path attribute (RFC 8669 §3)
// carrying the given TLVs.
func benchPrefixSIDAttr(tlvs ...[]byte) []byte {
	var v []byte
	for _, tlv := range tlvs {
		v = append(v, tlv...)
	}
	return benchPathAttr(benchOptionalTra, 40, v)
}

var (
	// RFC 8669 §3.1 Label-Index TLV: Label Index 100.
	benchPSIDLabelIndex = []byte{0x01, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64}
	// RFC 8669 §3.2 Originator SRGB TLV: one SRGB 16000 + 8000.
	benchPSIDOriginatorSRGB = []byte{0x03, 0x00, 0x08, 0x00, 0x00, 0x00, 0x3e, 0x80, 0x00, 0x1f, 0x40}
)

// benchRepeat concatenates nlri(i) for i in [0, n).
func benchRepeat(n int, nlri func(i int) []byte) []byte {
	var b []byte
	for i := 0; i < n; i++ {
		b = append(b, nlri(i)...)
	}
	return b
}

var (
	benchV4NH   = []byte{192, 0, 2, 1}
	benchV6NH   = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	benchRD     = []byte{0x00, 0x00, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01} // RD 65001:1, type 0
	benchVPNNH4 = append(make([]byte, 8), benchV4NH...)                  // RD 0 + IPv4 (RFC 4364 §4.3.2)
	benchVPNNH6 = append(make([]byte, 8), benchV6NH...)                  // RD 0 + IPv6 (RFC 4659 §3.2.1)
)

// benchV4Prefix returns 10.(i/256).(i%256).0/24 as an NLRI (RFC 4271 §4.3).
func benchV4Prefix(i int) []byte { return []byte{24, 10, byte(i >> 8), byte(i)} }

// benchV6Prefix returns 2001:db8:i::/48 as an NLRI (RFC 4760 §5).
func benchV6Prefix(i int) []byte { return []byte{48, 0x20, 0x01, 0x0d, 0xb8, byte(i >> 8), byte(i)} }

// benchLabel returns a 3-octet label field with the Bottom of Stack bit
// (RFC 3032 §2.1, RFC 8277 §2).
func benchLabel(label uint32) []byte {
	v := label<<4 | 1
	return []byte{byte(v >> 16), byte(v >> 8), byte(v)}
}

// benchLUPrefix returns 10.255.(i/256).(i%256)/32 with label 16000+i (RFC
// 8277 §2.2).
func benchLUPrefix(i int) []byte {
	b := append([]byte{24 + 32}, benchLabel(16000+uint32(i))...)
	return append(b, 10, 255, byte(i>>8), byte(i))
}

// benchVPNPrefix returns prefix, length bits, under label and RD 65001:1 (RFC
// 8277 §2.2, RFC 4364 §4.3.4).
func benchVPNPrefix(label []byte, bits int, prefix []byte) []byte {
	b := append([]byte{byte(24 + 64 + bits)}, label...)
	b = append(b, benchRD...)
	return append(b, prefix...)
}

// benchSRv6L3Service returns an SRv6 L3 Service TLV (RFC 9252 §2) with one
// SRv6 SID Information Sub-TLV (§3.1) for SID 2001:db8:1:1:: with endpoint
// behavior behavior and an SRv6 SID Structure Sub-Sub-TLV (§3.2.1) of LBL 40,
// LNL 24, FL 16, AL 0, Transposition Length 16 and Offset 64.
func benchSRv6L3Service(behavior uint16) []byte {
	info := []byte{0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0}
	info = append(info, 0x00)
	info = binary.BigEndian.AppendUint16(info, behavior)
	info = append(info, 0x00)
	info = append(info, 0x01, 0x00, 0x06, 40, 24, 16, 0, 16, 64)
	v := []byte{0x00, 0x01, 0x00, byte(len(info))}
	v = append(v, info...)
	return append([]byte{0x05, 0x00, byte(len(v))}, v...)
}

// benchEVPNType2 returns a MAC/IP Advertisement route (RFC 7432 §7.2) for MAC
// 00:00:5e:00:(i/256):(i%256) and IPv4 10.10.(i/256).(i%256), VNI 10100 (RFC
// 8365 §5.1.3).
func benchEVPNType2(i int) []byte {
	v := append([]byte(nil), benchRD...)
	v = append(v, make([]byte, 10)...) // ESI 0, single-homed
	v = append(v, 0, 0, 0, 0)          // Ethernet Tag ID
	v = append(v, 48, 0x00, 0x00, 0x5e, 0x00, byte(i>>8), byte(i))
	v = append(v, 32, 10, 10, byte(i>>8), byte(i))
	v = append(v, 0x00, 0x27, 0x74) // VNI 10100
	return append([]byte{2, byte(len(v))}, v...)
}

// benchEVPNType5 returns an IP Prefix route (RFC 9136 §3.1) for
// 10.20.i.0/24, no gateway, VNI 50000.
func benchEVPNType5(i int) []byte {
	v := append([]byte(nil), benchRD...)
	v = append(v, make([]byte, 10)...) // ESI
	v = append(v, 0, 0, 0, 0)          // Ethernet Tag ID
	v = append(v, 24, 10, 20, byte(i), 0)
	v = append(v, 0, 0, 0, 0)       // Gateway IP
	v = append(v, 0x00, 0xc3, 0x50) // VNI 50000
	return append([]byte{5, byte(len(v))}, v...)
}

// benchTLV returns a BGP-LS TLV (RFC 9552 §5.1).
func benchTLV(t uint16, v []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, t)
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	return append(b, v...)
}

// benchLSNodeDesc returns a Local (256) or Remote (257) Node Descriptors TLV
// (RFC 9552 §5.2.1.2) of AS 65001, BGP-LS Identifier 0 and IS-IS System ID
// 0000.0000.00n.
func benchLSNodeDesc(t uint16, n byte) []byte {
	v := benchTLV(512, []byte{0, 0, 0xfd, 0xe9})
	v = append(v, benchTLV(513, []byte{0, 0, 0, 0})...)
	v = append(v, benchTLV(515, []byte{0, 0, 0, 0, 0, n})...)
	return benchTLV(t, v)
}

// benchLSNLRI returns a Link-State NLRI (RFC 9552 §5.2) of IS-IS Level 2
// with the descriptors given.
func benchLSNLRI(nlriType uint16, desc ...[]byte) []byte {
	v := []byte{2, 0, 0, 0, 0, 0, 0, 0, 0} // Protocol-ID IS-IS L2, Identifier 0
	for _, d := range desc {
		v = append(v, d...)
	}
	return benchTLV(nlriType, v)
}

// benchLSNode, benchLSLink and benchLSPrefix return a Node, Link and IPv4
// Topology Prefix NLRI (RFC 9552 §5.2.1, §5.2.2, §5.2.3).
func benchLSNode(int) []byte { return benchLSNLRI(1, benchLSNodeDesc(256, 1)) }

func benchLSLink(i int) []byte {
	return benchLSNLRI(2, benchLSNodeDesc(256, 1), benchLSNodeDesc(257, 2),
		benchTLV(258, []byte{0, 0, 0, byte(i + 1), 0, 0, 0, byte(i + 2)}), // Link Local/Remote Identifiers
		benchTLV(259, []byte{10, 0, byte(i), 1}),                          // IPv4 interface address
		benchTLV(260, []byte{10, 0, byte(i), 2}))                          // IPv4 neighbor address
}

func benchLSPrefix(i int) []byte {
	return benchLSNLRI(3, benchLSNodeDesc(256, 1),
		benchTLV(265, []byte{24, 10, 40, byte(i)})) // IP Reachability Information
}

// benchLSAttr returns the BGP-LS Attribute (RFC 9552 §5.3) of tlvs.
func benchLSAttr(tlvs ...[]byte) []byte {
	var v []byte
	for _, t := range tlvs {
		v = append(v, t...)
	}
	return benchPathAttr(benchOptional, 29, v)
}

var (
	// Node: flags, name, IS-IS area, router ID, SR Capabilities with SRGB
	// 16000/8000, SR Algorithm 0 and 1 (RFC 9552 §5.3.1, RFC 9085 §2.1).
	benchLSNodeAttr = benchLSAttr(
		benchTLV(1024, []byte{0x00}),
		benchTLV(1026, []byte("pe1.example.net")),
		benchTLV(1027, []byte{0x49, 0x00, 0x01}),
		benchTLV(1028, []byte{10, 0, 0, 1}),
		benchTLV(1034, append([]byte{0x80, 0x00, 0x00, 0x1f, 0x40}, benchTLV(1161, []byte{0x00, 0x3e, 0x80})...)),
		benchTLV(1035, []byte{0, 1}),
	)
	// Link: router IDs, admin group, bandwidths, TE and IGP metrics and an
	// Adjacency SID (RFC 9552 §5.3.2, RFC 9085 §2.2.1).
	benchLSLinkAttr = benchLSAttr(
		benchTLV(1028, []byte{10, 0, 0, 1}),
		benchTLV(1030, []byte{10, 0, 0, 2}),
		benchTLV(1088, []byte{0, 0, 0, 1}),
		benchTLV(1089, []byte{0x4e, 0xee, 0x6b, 0x28}),                 // 2e9 bytes/s
		benchTLV(1090, []byte{0x4e, 0xee, 0x6b, 0x28}),                 // 2e9 bytes/s
		benchTLV(1091, bytesRepeat([]byte{0x4e, 0xee, 0x6b, 0x28}, 8)), // 8 priorities
		benchTLV(1092, []byte{0, 0, 0, 10}),
		benchTLV(1095, []byte{0, 0, 10}),
		benchTLV(1099, []byte{0x30, 0x00, 0x00, 0x00, 0x00, 0x5d, 0xc0}), // V, L, label 24000
	)
	// Prefix: IGP flags, metric and a Prefix SID index (RFC 9552 §5.3.3, RFC
	// 9085 §2.3.1).
	benchLSPrefixAttr = benchLSAttr(
		benchTLV(1152, []byte{0x00}),
		benchTLV(1155, []byte{0, 0, 0, 10}),
		benchTLV(1158, []byte{0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x65}), // N, index 101
	)
)

func bytesRepeat(b []byte, n int) []byte {
	var r []byte
	for i := 0; i < n; i++ {
		r = append(r, b...)
	}
	return r
}

// benchSRPolicyTunnelEncap is a Tunnel Encapsulation Attribute (RFC 9012)
// with an SR Policy tunnel (RFC 9830): Preference, Binding SID and two
// weighted segment lists of two type A segments each.
var benchSRPolicyTunnelEncap = benchPathAttr(benchOptionalTra, 23, []byte{
	0x00, 0x0F, 0x00, 0x48, 0x0C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x0D, 0x06, 0x00, 0x00,
	0xDB, 0xBA, 0x00, 0x00, 0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	0x01, 0x06, 0x00, 0x00, 0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0x10, 0x00,
	0x80, 0x00, 0x19, 0x00, 0x09, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x06, 0x00, 0x00,
	0x18, 0x6A, 0xA0, 0x00, 0x01, 0x06, 0x00, 0x00, 0x05, 0xDC, 0xD0, 0x00,
})

// benchFlowspec returns an IPv4 Flow Specification (RFC 8955 §4) matching
// destination 10.30.i.0/24, TCP, destination port 443.
func benchFlowspec(i int) []byte {
	v := []byte{0x01, 24, 10, 30, byte(i)} // Destination Prefix
	v = append(v, 0x03, 0x81, 0x06)        // IP Protocol == 6
	v = append(v, 0x05, 0x91, 0x01, 0xbb)  // Destination Port == 443
	return append([]byte{byte(len(v))}, v...)
}

// benchMCASTVPNType7 returns a C-multicast Source Tree Join route (RFC 6514
// §4.7) for (192.0.2.10, 232.1.(i/256).(i%256)).
func benchMCASTVPNType7(i int) []byte {
	v := append([]byte(nil), benchRD...)
	v = binary.BigEndian.AppendUint32(v, 65001)
	v = append(v, 32, 192, 0, 2, 10, 32, 232, 1, byte(i>>8), byte(i))
	return append([]byte{7, byte(len(v))}, v...)
}

// benchVPLS returns a VPLS NLRI (RFC 4761 §3.2.2) for VE ID i+1, block of 10
// labels from 100000.
func benchVPLS(i int) []byte {
	v := []byte{0x00, 17}
	v = append(v, benchRD...)
	v = binary.BigEndian.AppendUint16(v, uint16(i+1))
	v = append(v, 0x00, 0x00, 0x00, 0x0a)
	return append(v, 0x18, 0x6a, 0x01)
}

// benchMUPISD returns an Interwork Segment Discovery route
// (draft-ietf-bess-mup-safi §3.1.1) for 10.50.i.0/24.
func benchMUPISD(i int) []byte {
	v := append([]byte(nil), benchRD...)
	v = append(v, 24, 10, 50, byte(i))
	return append([]byte{0x01, 0x00, 0x01, byte(len(v))}, v...)
}

// benchRTC returns a Route Target membership NLRI (RFC 4684 §4) for origin AS
// 65001 and RT 65001:i.
func benchRTC(i int) []byte {
	v := binary.BigEndian.AppendUint32([]byte{96}, 65001)
	return append(v, benchRT(65001, uint32(i))...)
}

// afiBenchCase is one family and NLRI count of the matrix.
type afiBenchCase struct {
	name string
	// routes is the number of NLRI of the UPDATE, and the number of messages
	// it must produce.
	routes int
	// msgType is the type all the messages must be published with.
	msgType int
	update  []byte
}

// afiBenchCases returns the AFI/SAFI benchmark matrix.
func afiBenchCases() []afiBenchCase {
	var cases []afiBenchCase
	add := func(name string, routes, msgType int, update []byte) {
		cases = append(cases, afiBenchCase{name: fmt.Sprintf("%s/nlri=%d", name, routes), routes: routes, msgType: msgType, update: update})
	}
	for _, n := range []int{1, 64} {
		add("ipv4-unicast-nlri-field", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(nil, benchCommonAttrs(benchV4NH), benchRepeat(n, benchV4Prefix)))
		add("ipv4-unicast-mp-reach", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil), benchMPReach(1, 1, benchV4NH, benchRepeat(n, benchV4Prefix))), nil))
		add("ipv6-unicast-mp-reach", n, bmp.UnicastPrefixV6Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil), benchMPReach(2, 1, benchV6NH, benchRepeat(n, benchV6Prefix))), nil))
		add("ipv4-withdraw-field", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(benchRepeat(n, benchV4Prefix), nil, nil))
		add("ipv6-withdraw-mp-unreach", n, bmp.UnicastPrefixV6Msg,
			benchUpdate(nil, [][]byte{benchMPUnreach(2, 1, benchRepeat(n, benchV6Prefix))}, nil))
		add("ipv4-labeled-unicast-prefix-sid", n, bmp.UnicastPrefixV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(1, 4, benchV4NH, benchRepeat(n, benchLUPrefix)),
				benchPrefixSIDAttr(benchPSIDLabelIndex, benchPSIDOriginatorSRGB)), nil))
		add("vpnv4", n, bmp.L3VPNV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(1, 128, benchVPNNH4, benchRepeat(n, func(i int) []byte {
					return benchVPNPrefix(benchLabel(24001), 24, benchV4Prefix(i)[1:])
				}))), nil))
		add("vpnv6", n, bmp.L3VPNV6Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(2, 128, benchVPNNH6, benchRepeat(n, func(i int) []byte {
					return benchVPNPrefix(benchLabel(24002), 48, benchV6Prefix(i)[1:])
				}))), nil))
		add("vpnv4-srv6", n, bmp.L3VPNV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(1, 128, benchVPNNH6, benchRepeat(n, func(i int) []byte {
					return benchVPNPrefix([]byte{0x00, 0x40, 0x00}, 24, benchV4Prefix(i)[1:]) // Function 0x0040 transposed
				})),
				benchPrefixSIDAttr(benchSRv6L3Service(19))), nil)) // End.DT4
		add("vpnv6-srv6", n, bmp.L3VPNV6Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(2, 128, benchVPNNH6, benchRepeat(n, func(i int) []byte {
					return benchVPNPrefix([]byte{0x00, 0x41, 0x00}, 48, benchV6Prefix(i)[1:])
				})),
				benchPrefixSIDAttr(benchSRv6L3Service(18))), nil)) // End.DT6
		add("vpnv4-withdraw-mp-unreach", n, bmp.L3VPNV4Msg,
			benchUpdate(nil, [][]byte{benchMPUnreach(1, 128, benchRepeat(n, func(i int) []byte {
				return benchVPNPrefix([]byte{0x80, 0x00, 0x00}, 24, benchV4Prefix(i)[1:]) // RFC 8277 §2.4
			}))}, nil))
		evpnEC := [][]byte{
			{0x03, 0x0c, 0, 0, 0, 0, 0x00, 0x08}, // Encapsulation VXLAN (RFC 9012 §4.1)
		}
		add("evpn-type2-mac-ip", n, bmp.EVPNMsg,
			benchUpdate(nil, append(benchCommonAttrs(nil, evpnEC...),
				benchMPReach(25, 70, benchV4NH, benchRepeat(n, benchEVPNType2))), nil))
		add("evpn-type5-ip-prefix", n, bmp.EVPNMsg,
			benchUpdate(nil, append(benchCommonAttrs(nil, append(evpnEC,
				[]byte{0x06, 0x03, 0x00, 0x00, 0x5e, 0x00, 0x53, 0x01})...), // Router's MAC (RFC 9135 §8.1)
				benchMPReach(25, 70, benchV4NH, benchRepeat(n, benchEVPNType5))), nil))
		add("bgp-ls-prefix", n, bmp.LSPrefixMsg,
			benchUpdate(nil, append(benchCommonAttrs(nil)[:2],
				benchMPReach(16388, 71, benchV4NH, benchRepeat(n, benchLSPrefix)), benchLSPrefixAttr), nil))
		add("flowspec-v4", n, bmp.FlowspecV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil, []byte{0x80, 0x06, 0, 0, 0, 0, 0, 0}), // traffic-rate 0
				benchMPReach(1, 133, nil, benchRepeat(n, benchFlowspec))), nil))
		add("ipv4-multicast", n, bmp.MulticastV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil), benchMPReach(1, 2, benchV4NH, benchRepeat(n, benchV4Prefix))), nil))
		add("mcast-vpn-type7", n, bmp.MCASTVPNV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil), benchMPReach(1, 5, benchV4NH, benchRepeat(n, benchMCASTVPNType7))), nil))
		add("mup-isd", n, bmp.MUPV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil),
				benchMPReach(1, 85, benchV4NH, benchRepeat(n, benchMUPISD)),
				benchPathAttr(benchOptionalTra, 40, mupPrefixSIDAttribute())), nil))
		add("rtc", n, bmp.RTCV4Msg,
			benchUpdate(nil, append(benchCommonAttrs(nil), benchMPReach(1, 132, benchV4NH, benchRepeat(n, benchRTC))), nil))
	}
	// Families that carry one NLRI per UPDATE: each node and link has its own
	// attribute, an SR Policy candidate path its own Tunnel Encapsulation
	// (RFC 9830 §2.1), a VPLS instance its own Route Targets.
	add("bgp-ls-node", 1, bmp.LSNodeMsg,
		benchUpdate(nil, append(benchCommonAttrs(nil)[:2], benchMPReach(16388, 71, benchV4NH, benchLSNode(0)), benchLSNodeAttr), nil))
	add("bgp-ls-link", 1, bmp.LSLinkMsg,
		benchUpdate(nil, append(benchCommonAttrs(nil)[:2], benchMPReach(16388, 71, benchV4NH, benchLSLink(0)), benchLSLinkAttr), nil))
	add("sr-policy-v4", 1, bmp.SRPolicyV4Msg,
		benchUpdate(nil, append(benchCommonAttrs(nil),
			benchMPReach(1, 73, benchV4NH, []byte{96, 0, 0, 0, 1, 0, 0, 0, 100, 10, 0, 0, 9}), // Distinguisher 1, Color 100, Endpoint 10.0.0.9
			benchSRPolicyTunnelEncap), nil))
	add("vpls", 1, bmp.VPLSMsg,
		benchUpdate(nil, append(benchCommonAttrs(nil, []byte{0x80, 0x0a, 19, 0x00, 0x05, 0xdc, 0, 0}), // Layer2 Info, VPLS, MTU 1500 (RFC 4761 §3.2.4)
			benchMPReach(25, 65, benchV4NH, benchVPLS(0))), nil))
	return cases
}

// afiBenchMessage decodes c into the Route Monitoring message of peer ph.
func afiBenchMessage(tb testing.TB, ph *bmp.PerPeerHeader, c afiBenchCase) bmp.Message {
	tb.Helper()
	update, err := bgp.UnmarshalBGPUpdateWithAS4Hint(c.update, true)
	if err != nil {
		tb.Fatalf("%s: UnmarshalBGPUpdateWithAS4Hint() error: %v", c.name, err)
	}
	return bmp.Message{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: update}, SpeakerIP: "10.2.1.3"}
}

// afiBenchHeader returns the per-peer header of the benchmarks, with a peer
// timestamp as a router sets it.
func afiBenchHeader() *bmp.PerPeerHeader {
	return benchPeerHeader("192.0.2.1", "10.0.0.1")
}

// checkAFIBenchCase fails unless c produces c.routes messages of c.msgType,
// so a decode failure, which is only logged, does not go unnoticed.
func checkAFIBenchCase(tb testing.TB, c afiBenchCase) {
	tb.Helper()
	ph := afiBenchHeader()
	pub := &recordingPublisher{}
	p := NewProducer(pub, true).(*producer)
	p.producingWorker(benchPeerUp(ph))
	n := len(pub.msgs)
	p.producingWorker(afiBenchMessage(tb, ph, c))
	got := pub.msgs[n:]
	if len(got) != c.routes {
		tb.Fatalf("%s: published %d messages, want %d", c.name, len(got), c.routes)
	}
	for _, m := range got {
		if m.msgType != c.msgType {
			tb.Fatalf("%s: published message type %d, want %d: %s", c.name, m.msgType, c.msgType, m.payload)
		}
	}
}

// TestAFIBenchCases checks the benchmark matrix produces what it should.
func TestAFIBenchCases(t *testing.T) {
	for _, c := range afiBenchCases() {
		checkAFIBenchCase(t, c)
	}
}

// BenchmarkProducerAFI feeds b.N Route Monitoring messages of each case,
// after a Peer Up, through Producer and waits until all they produce is
// published, as the server does. It reports the time, process CPU time,
// bytes and allocations per route, that is per message published.
func BenchmarkProducerAFI(b *testing.B) {
	for _, c := range afiBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			checkAFIBenchCase(b, c)
			ph := afiBenchHeader()
			rm := afiBenchMessage(b, ph, c)
			pub := &benchCountingPublisher{want: 1 + int64(b.N)*int64(c.routes), done: make(chan struct{})}
			p := NewProducer(pub, true).(*producer)
			queue := make(chan bmp.Message)
			stop := make(chan struct{})
			returned := make(chan struct{})
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			cpuBefore, cpuOK := benchCPUTime()
			b.ReportAllocs()
			b.ResetTimer()
			go func() {
				p.Producer(queue, stop)
				close(returned)
			}()
			queue <- benchPeerUp(ph)
			for i := 0; i < b.N; i++ {
				queue <- rm
			}
			<-pub.done
			b.StopTimer()
			cpuAfter, _ := benchCPUTime()
			runtime.ReadMemStats(&after)
			close(stop)
			<-returned
			routes := float64(b.N) * float64(c.routes)
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/routes, "ns/route")
			if cpuOK {
				// Includes the CPU time of the garbage collector and of
				// all other goroutines of the process.
				b.ReportMetric(float64((cpuAfter-cpuBefore).Nanoseconds())/routes, "cpu-ns/route")
			}
			b.ReportMetric(float64(after.TotalAlloc-before.TotalAlloc)/routes, "B/route")
			b.ReportMetric(float64(after.Mallocs-before.Mallocs)/routes, "allocs/route")
		})
	}
}

// BenchmarkUpdateDecodeAFI measures decoding the UPDATE of each case, which
// the parser does before the Producer gets it.
func BenchmarkUpdateDecodeAFI(b *testing.B) {
	for _, c := range afiBenchCases() {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := bgp.UnmarshalBGPUpdateWithAS4Hint(c.update, true); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportMetric(float64(b.Elapsed().Nanoseconds())/(float64(b.N)*float64(c.routes)), "ns/route")
		})
	}
}
