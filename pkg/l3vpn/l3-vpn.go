package l3vpn

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// ErrEmptyNLRI is returned when L3VPN NLRI data has zero length,
// signaling an End-of-RIB marker per RFC 4724 §2.
var ErrEmptyNLRI = errors.New("NLRI length is 0")

// Options gives the session and attribute context that RFC 8277 VPN NLRI
// (AFI 1/2, SAFI 128) is decoded in.
type Options struct {
	// PathID is set when ADD-PATH is negotiated: a 4-octet Path Identifier
	// precedes the Length field (RFC 8277 §2.2, §2.3; RFC 7911 §3). A failed
	// parse is tried once more with it flipped.
	PathID bool
	// SRv6 is set when the label field carries SRv6 SID bits (RFC 9252 §4
	// transposition, see bgp.Update.HasSRv6Transposition); exactly one label
	// field is read.
	SRv6 bool
	// MultiLabel is the Multiple Labels Capability state; see
	// base.DecodeLabeledNLRI.
	MultiLabel base.MultiLabel
	// Withdraw selects the MP_UNREACH_NLRI encoding (RFC 8277 §2.4): a 3-octet
	// Compatibility field, ignored on reception, in place of the labels.
	Withdraw bool
	// AFI is the address family, 1 or 2: the prefix after the RD may be up
	// to 32 or 128 bits (RFC 8277 §2.2). Zero allows up to 128.
	AFI uint16
}

// UnmarshalL3VPNNLRI parses announced VPNv4/VPNv6 NLRI; srv6 sets
// Options.SRv6. It is UnmarshalL3VPNNLRIWithOptions with the Multiple Labels
// Capability state unknown and no address family, so an MP_UNREACH_NLRI
// field, whose Compatibility field is not a label, should be decoded with
// Options.Withdraw instead.
func UnmarshalL3VPNNLRI(b []byte, pathID bool, srv6 ...bool) (*base.MPNLRI, error) {
	return UnmarshalL3VPNNLRIWithOptions(b, Options{PathID: pathID, SRv6: len(srv6) == 1 && srv6[0]})
}

// UnmarshalL3VPNNLRIWithOptions parses VPNv4/VPNv6 NLRI according to opts.
// If parsing fails, it will try exactly once with the PathID flag flipped.
func UnmarshalL3VPNNLRIWithOptions(b []byte, opts Options) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("L3VPN NLRI Raw: %s, options: %+v", tools.MessageHex(b), opts)
	}
	if len(b) == 0 {
		return nil, ErrEmptyNLRI
	}

	// First attempt with the provided pathID flag
	if mp, err := parseLabelStack(b, opts); err == nil {
		return mp, nil
	}

	// Single fallback attempt with flipped pathID
	opts.PathID = !opts.PathID
	return parseLabelStack(b, opts)
}

// parseLabelStack picks the label field reading: the Compatibility field for
// withdrawals, one SRv6 field, or the announced label stack readings that
// base.DecodeLabeledNLRI orders by the Multiple Labels Capability state.
func parseLabelStack(b []byte, opts Options) (*base.MPNLRI, error) {
	switch {
	case opts.Withdraw:
		return parseL3VPNNLRI(b, opts, base.CompatibilityField)
	case opts.SRv6:
		return parseL3VPNNLRI(b, opts, base.SRv6Label)
	}
	return base.DecodeLabeledNLRI(opts.MultiLabel, func(f base.LabelField) (*base.MPNLRI, error) {
		return parseL3VPNNLRI(b, opts, f)
	})
}

// parseL3VPNNLRI performs the actual parsing without any recursion, reading
// the label field of each NLRI as f says.
func parseL3VPNNLRI(b []byte, opts Options, f base.LabelField) (*base.MPNLRI, error) {
	maxPrefixBits := 128
	if opts.AFI == 1 {
		maxPrefixBits = 32
	}
	mpnlri := base.MPNLRI{NLRI: make([]base.Route, 0)}
	p := 0

	for p < len(b) {
		up := base.Route{}

		// Optional Path ID (4 bytes)
		if opts.PathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes for PathID at pos %d", p)
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}

		// NLRI length in bits (covers label or compat field + RD + prefix)
		if p >= len(b) {
			return nil, fmt.Errorf("missing NLRI length at pos %d", p)
		}
		up.Length = b[p]
		if up.Length == 0 {
			return nil, fmt.Errorf("invalid NLRI length (0 bits) at pos %d", p)
		}
		p++

		// Labels, or the Compatibility field of a withdrawal (RFC 8277 §2.4)
		labels, n, err := base.ReadLabelField(b[p:], f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse label field at pos %d: %w", p, err)
		}
		up.Label = labels
		p += n

		// Route Distinguisher (8 bytes)
		if p+8 > len(b) {
			return nil, fmt.Errorf("not enough bytes for RD at pos %d", p)
		}
		rd, err := base.MakeRD(b[p : p+8])
		if err != nil {
			return nil, fmt.Errorf("failed to parse RD at pos %d: %w", p, err)
		}
		up.RD = rd
		p += 8

		// Overhead in bits: label field + 8-byte RD
		overheadBits := n*8 + 64

		// Exact prefix length in bits. A prefix longer than the address family
		// allows makes the NLRI malformed (RFC 8277 §2.2, RFC 7606 §3(j)).
		prefixBits := int(up.Length) - overheadBits
		if prefixBits < 0 || prefixBits > maxPrefixBits {
			return nil, fmt.Errorf("malformed NLRI: computed prefix length %d bits outside 0-%d (NLRI=%d, overhead=%d)",
				prefixBits, maxPrefixBits, up.Length, overheadBits)
		}

		// Bytes to read for the prefix (ceil to octet)
		prefixBytes := (prefixBits + 7) / 8
		if p+prefixBytes > len(b) {
			return nil, fmt.Errorf("not enough bytes for prefix at pos %d (need %d)", p, prefixBytes)
		}
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])
		p += prefixBytes
		if prefixBits%8 != 0 {
			// Mask off unused bits in the last byte if prefix length is not a multiple of 8
			up.Prefix[prefixBytes-1] &= 0xFF << (8 - (prefixBits % 8))
		}
		// Store the exact bit length of the IP prefix (not rounded).
		// The overhead (label + RD) has already been subtracted via prefixBits.
		// Rounding up would corrupt CIDR lengths like /30 → /32.
		up.Length = uint8(prefixBits)

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
