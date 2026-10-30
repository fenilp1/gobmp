package bgp

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strconv"
	"testing"

	"github.com/sbezverk/tools"
)

// The fmt based extended and large community formatting that String used
// before, kept as the oracle for TestExtCommunityStringOracle and
// TestLgCommunityStringOracle.

// Transitive Two-Octet AS-Specific Extended Community
func fmtType0(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type0-length=%d", len(value))
	}
	switch subType {
	case 0x04:
		// Link Bandwidth: Local Administrator (value[2:6]) is IEEE 754 float32, bytes/sec
		f := binary.BigEndian.Uint32(value[2:6])
		return getSubType(transAS2SubTypes, subType) + fmt.Sprintf("%03f", math.Float32frombits(f))
	default:
		return getSubType(transAS2SubTypes, subType) + fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:]))
	}
}

// Transitive IPv4 Specific Extended Community
func fmtType1(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type1-length=%d", len(value))
	}
	return getSubType(transIPv4SubTypes, subType) + fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:]))
}

// Transitive Four-Octet AS-Specific Extended Community
func fmtType2(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type2-length=%d", len(value))
	}
	return getSubType(transAS4SubTypes, subType) + fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:]))
}

// Transitive Opaque Extended Community
func fmtType3(subType uint8, value []byte) string {
	if len(value) < 4 {
		return fmt.Sprintf("invalid-type3-length=%d", len(value))
	}
	var s string
	switch subType {
	case 0xb:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	case 0xc:
		if len(value) < 6 {
			return fmt.Sprintf("invalid-type3-length=%d", len(value))
		}
		// RFC 9012 4.1: Value = Reserved(2)+Reserved(2)+Tunnel Type(2);
		// the tunnel type is the last two octets, not value[2:4].
		s = fmt.Sprintf("%d", binary.BigEndian.Uint16(value[4:6]))
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	}
	return getSubType(transOpaqueSubTypes, subType) + s
}

// BGP MUP Extended Community
// The sub-type selects both the segment the community identifies and the
// format of the Global and Local Administrator fields.
func fmtType12(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type12-length=%d", len(value))
	}
	var s string
	switch subType {
	case 0x0, 0x3:
		// 2-octet AS Global Administrator, 4-octet Local Administrator
		s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:6]))
	case 0x1, 0x4:
		// IPv4 address Global Administrator, 2-octet Local Administrator
		s = fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:6]))
	case 0x2, 0x5:
		// 4-octet AS Global Administrator, 2-octet Local Administrator
		s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:6]))
	default:
		s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:6]))
	}
	return getSubType(mupSubTypes, subType) + s
}

// EVPN Extended Community
func fmtType6(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type6-length=%d", len(value))
	}
	var s string
	switch subType {
	case 0x01:
		// RFC 7432 7.5: ESI Label is an RFC 3032 label stack entry (3
		// octets, label in the high-order 20 bits) like base.MakeLabel.
		esiLabel := uint32(value[3])<<16 | uint32(value[4])<<8 | uint32(value[5]&0xf0)
		esiLabel >>= 4
		s = fmt.Sprintf("%d:%d", value[0], esiLabel)
	case 0x02:
		fallthrough
	case 0x03:
		for i, m := range value {
			s += tools.ConvertToHex(m)
			if i < len(value)-1 {
				s += ":"
			}
		}
	case 0x00:
		s = fmt.Sprintf("%d:%d", value[0], binary.BigEndian.Uint32(value[2:]))
	case 0x06:
		s = fmt.Sprintf("%d:0x%04x", value[0], binary.BigEndian.Uint16(value[1:]))
	case 0x10:
		// EVPN Link Bandwidth [draft-ietf-bess-evpn-unequal-lb]
		// value[0] = Value-Units: 0 = Mbps, 1 = generalized weight
		// value[1:6] = Value-Weight: 5-octet unsigned integer
		units := value[0]
		weight := uint64(value[1])<<32 | uint64(binary.BigEndian.Uint32(value[2:6]))
		switch units {
		case 0:
			s = fmt.Sprintf("%d Mbps", weight)
		case 1:
			s = fmt.Sprintf("weight %d", weight)
		default:
			s = fmt.Sprintf("units=%d weight=%d", units, weight)
		}
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))
	}

	return getSubType(evpnSubTypes, subType) + s
}

// Transitive IPv6 Address Specific Extended Community (RFC 5701)
// Type 0x05, Format: Type (1) + Sub-Type (1) + IPv6 Address (16) + Local Admin (2)
func fmtType5(subType uint8, value []byte) string {
	if len(value) < 18 {
		return "invalid-ipv6-ec-length"
	}

	// Extract IPv6 address (first 16 bytes)
	ipv6 := net.IP(value[0:16])

	// Extract local administrator (last 2 bytes)
	localAdmin := binary.BigEndian.Uint16(value[16:18])

	var s string
	switch subType {
	case 0x02:
		s = "rt=" + ipv6.String() + ":" + strconv.Itoa(int(localAdmin))
	case 0x03:
		s = "ro=" + ipv6.String() + ":" + strconv.Itoa(int(localAdmin))
	default:
		s = "subtype-" + strconv.Itoa(int(subType)) + "=" + ipv6.String() + ":" + strconv.Itoa(int(localAdmin))
	}

	return s
}

// 0x08 Flow spec redirect/mirror to IP next-hop [draft-simpson-idr-flowspec-redirect] 2012-09-28
func fmtType8(subType uint8, value []byte) string {
	return ECPFlowspec + "redirect_to_ip_next_hop"
}

// Non-Transitive Two-Octet AS-Specific Extended Community
func fmtType40(subType uint8, value []byte) string {
	if len(value) < 6 {
		return fmt.Sprintf("invalid-type40-length=%d", len(value))
	}
	var s string
	switch subType {
	case 0x04:
		// Link Bandwidth: Local Administrator (value[2:6]) is IEEE 754 float32, bytes/sec
		f := binary.BigEndian.Uint32(value[2:6])
		s = fmt.Sprintf("%03f", math.Float32frombits(f))
	default:
		s = fmt.Sprintf("%d", binary.BigEndian.Uint32(value[0:4]))

	}

	return getSubType(nonTransAS2SubTypes, subType) + s
}

// Non-Transitive Opaque Extended Community (RFC 8097)
// Type 0x43, Subtype 0x00 - Origin Validation State
func fmtType43(subType uint8, value []byte) string {
	var s string
	switch subType {
	case 0x00:
		// RFC 8097: Last byte contains validation state
		// 0 = valid, 1 = not found, 2 = invalid
		if len(value) >= 6 {
			state := value[5] // Last byte of 6-byte value
			switch state {
			case 0:
				s = "valid"
			case 1:
				s = "not-found"
			case 2:
				s = "invalid"
			default:
				// RFC 8097: Values > 2 should trigger discard
				s = fmt.Sprintf("unknown=%d", state)
			}
		} else {
			s = "invalid-length"
		}
	default:
		s = fmt.Sprintf("unknown-subtype=%d", subType)
	}
	return getSubType(nonTransOpaqueSubTypes, subType) + s
}

// Flowspec Extended Community
func fmtType80(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x0a:
			f := value[1]
			return fmt.Sprintf("%sEncaps=%d T=%t R=%t C=%t S=%t MTU=%d", ECPLayer2Info, value[0],
				f&0x08 != 0, f&0x04 != 0, f&0x02 != 0, f&0x01 != 0, binary.BigEndian.Uint16(value[2:4]))
		case 0x0b:
			return fmt.Sprintf("%sRootVLAN=%d LeafVLAN=%d P=%t V=%t", ECPETreeInfo,
				binary.BigEndian.Uint16(value[0:2])&0x0fff, binary.BigEndian.Uint16(value[2:4])&0x0fff,
				value[5]&0x02 != 0, value[5]&0x01 != 0)
		case 0x0c:
			rate := math.Float32frombits(binary.BigEndian.Uint32(value[2:]))
			if !(rate > 0) {
				rate = 0
			}
			s = fmt.Sprintf("AS: %d Rate: %s pps", binary.BigEndian.Uint16(value[:2]), strconv.FormatFloat(float64(rate), 'f', -1, 32))
		case 0x0d:
			s = fmt.Sprintf("SPI=%d SI=%d SFT=%d", uint32(value[0])<<16|uint32(value[1])<<8|uint32(value[2]), value[3], binary.BigEndian.Uint16(value[4:6]))
		case 0x06:
			rate := math.Float32frombits(binary.BigEndian.Uint32(value[2:]))
			var bps uint64
			switch {
			case !(rate > 0):
				bps = 0
			case rate >= 1<<61:
				bps = math.MaxUint64
			default:
				bps = uint64(rate) * 8
			}
			s = fmt.Sprintf("AS: %d Rate: %d bps", binary.BigEndian.Uint16(value[:2]), bps)
		case 0x08:
			s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint16(value[0:2]), binary.BigEndian.Uint32(value[2:]))
		case 0x07:
			// Traffic-Action Extended Community (RFC 8955 Section 7.3)
			// Bit 47 (T): Terminal Action, Bit 46 (S): Sample
			terminalAction := value[5]&0x01 != 0
			sampleBit := value[5]&0x02 != 0
			s = fmt.Sprintf("T=%t S=%t", terminalAction, sampleBit)
		case 0x09:
			// Traffic Marking Extended Community (RFC 8955 Section 7.5)
			// Lower 6 bits of last byte contain DSCP value
			dscp := value[5] & 0x3F
			s = fmt.Sprintf("DSCP=%d", dscp)
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecSubTypes, subType) + s
}

func fmtType81(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x08:
			s = fmt.Sprintf("%s:%d", net.IP(value[0:4]).To4().String(), binary.BigEndian.Uint16(value[4:]))
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecRedirectSubTypes, subType) + s
}

func fmtType82(subType uint8, value []byte) string {
	var s string

	if len(value) == 6 {
		switch subType {
		case 0x08:
			s = fmt.Sprintf("%d:%d", binary.BigEndian.Uint32(value[0:4]), binary.BigEndian.Uint16(value[4:]))
		default:
			s = tools.MessageHex(value)
		}
	} else {
		s = fmt.Sprintf("invalid value length of %d", len(value))
	}
	return getSubType(flowspecRedirectSubTypes, subType) + s
}

// fmtExtComm is extComm as it was: a map with Extended Community as a key, it return a function to process a type specific sub type.
var fmtExtComm = map[uint8]func(uint8, []byte) string{
	0x0:  fmtType0,
	0x1:  fmtType1,
	0x2:  fmtType2,
	0x3:  fmtType3,
	0x5:  fmtType5,
	0x6:  fmtType6,
	0x8:  fmtType8,
	0xc:  fmtType12,
	0x40: fmtType40,
	0x43: fmtType43,
	0x80: fmtType80,
	0x81: fmtType81,
	0x82: fmtType82,
}

// fmtExtCommunityString is ExtCommunity.String as it was.
func fmtExtCommunityString(ext *ExtCommunity) string {
	var s string
	// var prefix string
	var subType uint8
	if ext.SubType == nil {
		subType = 0xff
	} else {
		subType = *ext.SubType
	}
	f := fmtExtComm[ext.Type]
	if f == nil {
		s = "unknown="
		s += fmt.Sprintf("Type: %d Subtype: %d Value: %s", ext.Type, subType, tools.MessageHex(ext.Value))
		return s
	}
	return f(subType, ext.Value)
}

func fmtLgCommunityString(lg *LgCommunity) string {
	return fmt.Sprintf("%d:%d:%d", lg.GlobalAdmin, lg.LocalData1, lg.LocalData2)
}

// extCommunityTestValues returns the 8-octet extended communities of type t
// and sub-type st to check: all zero, all ones, single bits and random ones.
func extCommunityTestValues(r *rand.Rand, t, st byte) [][]byte {
	var vs [][]byte
	for _, fill := range []byte{0x00, 0xff, 0x80, 0x01} {
		b := []byte{t, st, fill, fill, fill, fill, fill, fill}
		vs = append(vs, b)
	}
	for i := 2; i < 8; i++ {
		b := []byte{t, st, 0, 0, 0, 0, 0, 0}
		b[i] = 0xff
		vs = append(vs, b)
	}
	for i := 0; i < 6; i++ {
		b := make([]byte, 8)
		r.Read(b)
		b[0], b[1] = t, st
		vs = append(vs, b)
	}
	return vs
}

// TestExtCommunityStringOracle checks String formats every type and sub-type
// as the fmt based code did, for values that hit every branch, including
// IEEE 754 special values and the Flowspec rate conversion.
func TestExtCommunityStringOracle(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	n := 0
	for typ := 0; typ < 256; typ++ {
		for st := 0; st < 256; st++ {
			for _, b := range extCommunityTestValues(r, byte(typ), byte(st)) {
				ext, err := makeExtCommunity(b)
				if err != nil {
					t.Fatalf("makeExtCommunity(%x) error: %v", b, err)
				}
				if got, want := ext.String(), fmtExtCommunityString(ext); got != want {
					t.Fatalf("String() of %x = %q, want %q", b, got, want)
				}
				n++
			}
		}
	}
	// Float32 special values in the Link Bandwidth and Flowspec rate.
	for _, f := range []float32{0, -0.0, 1, 1.5, 125000000, float32(math.Inf(1)), float32(math.Inf(-1)), float32(math.NaN()), math.MaxFloat32, math.SmallestNonzeroFloat32, 4294967296} {
		v := math.Float32bits(f)
		for _, typ := range []byte{0x00, 0x40, 0x80} {
			for _, st := range []byte{0x04, 0x06} {
				b := []byte{typ, st, 0xfd, 0xe9, 0, 0, 0, 0}
				binary.BigEndian.PutUint32(b[4:], v)
				ext, _ := makeExtCommunity(b)
				if got, want := ext.String(), fmtExtCommunityString(ext); got != want {
					t.Fatalf("String() of %x = %q, want %q", b, got, want)
				}
			}
		}
	}
	t.Logf("checked %d extended communities", n)
}

// TestExtCommunityTypeFuncsOracle checks each type function, which other
// decoders call with values of other lengths, against the fmt based one for
// every sub-type and value lengths 0 to 20.
func TestExtCommunityTypeFuncsOracle(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for typ, f := range extComm {
		old := fmtExtComm[typ]
		if old == nil {
			t.Fatalf("type %#x has no oracle", typ)
		}
		for st := 0; st < 256; st++ {
			for l := 0; l <= 20; l++ {
				for i := 0; i < 3; i++ {
					v := make([]byte, l)
					r.Read(v)
					if got, want := f(uint8(st), v), old(uint8(st), v); got != want {
						t.Fatalf("type %#x sub-type %#x value %x: got %q, want %q", typ, st, v, got, want)
					}
				}
			}
		}
	}
	if len(extComm) != len(fmtExtComm) {
		t.Fatalf("%d type functions, oracle has %d", len(extComm), len(fmtExtComm))
	}
	// A nil sub-type is formatted as 0xff.
	for typ := 0; typ < 256; typ++ {
		ext := &ExtCommunity{Type: uint8(typ), Value: []byte{1, 2, 3, 4, 5, 6, 7}}
		if got, want := ext.String(), fmtExtCommunityString(ext); got != want {
			t.Fatalf("type %#x without sub-type: got %q, want %q", typ, got, want)
		}
	}
}

// TestLgCommunityStringOracle checks String formats large communities as
// the fmt based code did.
func TestLgCommunityStringOracle(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	vals := []uint32{0, 1, 9, 10, 65535, 65536, math.MaxUint32}
	for _, a := range vals {
		for _, b := range vals {
			for _, c := range vals {
				lg := &LgCommunity{a, b, c}
				if got, want := lg.String(), fmtLgCommunityString(lg); got != want {
					t.Fatalf("String() = %q, want %q", got, want)
				}
			}
		}
	}
	for i := 0; i < 100000; i++ {
		lg := &LgCommunity{r.Uint32(), r.Uint32(), r.Uint32()}
		if got, want := lg.String(), fmtLgCommunityString(lg); got != want {
			t.Fatalf("String() = %q, want %q", got, want)
		}
	}
}

func BenchmarkCommunityString(b *testing.B) {
	rt, _ := makeExtCommunity([]byte{0x00, 0x02, 0xfd, 0xe9, 0x00, 0x00, 0x00, 0x01})
	lg := &LgCommunity{65001, 1, 1}
	b.Run("ext", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = rt.String()
		}
	})
	b.Run("ext-fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fmtExtCommunityString(rt)
		}
	})
	b.Run("large", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = lg.String()
		}
	})
	b.Run("large-fmt", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = fmtLgCommunityString(lg)
		}
	})
}
