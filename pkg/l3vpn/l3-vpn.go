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

// MultiLabel is a session's Multiple Labels Capability state for an AFI/SAFI
// (RFC 8277 §2.1, §2.3). It selects how announced label stacks are read.
type MultiLabel uint8

const (
	// MultiLabelUnknown means the capability state is not known, e.g. no
	// Peer Up was seen for the table.
	MultiLabelUnknown MultiLabel = iota
	// MultiLabelAbsent means the capability is known not to be both sent and
	// received, so NLRI carry exactly one label (RFC 8277 §2.2).
	MultiLabelAbsent
	// MultiLabelConfirmed means both OPEN messages list the AFI/SAFI with a
	// Count of at least 2 (RFC 8277 §2.3).
	MultiLabelConfirmed
)

// Options gives the session and attribute context that RFC 8277 VPN NLRI
// (AFI 1/2, SAFI 128 and the same layout in SAFI 76) is decoded in.
type Options struct {
	// PathID is set when ADD-PATH is negotiated: a 4-octet Path Identifier
	// precedes the Length field (RFC 8277 §2.2, §2.3; RFC 7911 §3).
	PathID bool
	// SRv6 is set when the label field carries SRv6 SID bits (RFC 9252 §4
	// transposition, see bgp.Update.HasSRv6Transposition); exactly one label
	// field is read.
	SRv6 bool
	// MultiLabel is the Multiple Labels Capability state; see parseLabelStack.
	MultiLabel MultiLabel
	// Withdraw selects the MP_UNREACH_NLRI encoding (RFC 8277 §2.4): a 3-octet
	// Compatibility field, ignored on reception, in place of the labels.
	Withdraw bool
	// IPv6 is set for AFI 2: the prefix after the RD may be up to 128 bits,
	// otherwise up to 32 (RFC 8277 §2.2).
	IPv6 bool
}

// UnmarshalL3VPNNLRI parses VPNv4/VPNv6 NLRI according to opts.
// If parsing fails, it will try exactly once with the PathID flag flipped. No recursion...
func UnmarshalL3VPNNLRI(b []byte, opts Options) (*base.MPNLRI, error) {
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

// parseLabelStack parses announced label stacks in an order chosen by the
// Multiple Labels Capability state:
//   - Confirmed: labels up to the one with the S bit set only (RFC 8277 §2.3).
//   - Absent: exactly one label with its S bit ignored (RFC 8277 §2.2), and
//     the S bit walk only if that parse is invalid.
//   - Unknown: the S bit walk, then exactly one label if that is invalid.
//
// A passive collector must stay correct when its view of the capability is
// stale or shared between sessions, hence the fallbacks; for a compliant
// router both readings agree. Strict single-label decoding goes first when
// the capability is known absent because the S bit walk can produce a valid
// looking but wrong parse when an RD byte reads as a label with S set.
// Withdrawals and SRv6 have no label stack to choose.
func parseLabelStack(b []byte, opts Options) (*base.MPNLRI, error) {
	if opts.Withdraw || opts.SRv6 || opts.MultiLabel == MultiLabelConfirmed {
		return parseL3VPNNLRI(b, opts, false)
	}
	first := opts.MultiLabel == MultiLabelAbsent
	mp, err := parseL3VPNNLRI(b, opts, first)
	if err == nil {
		return mp, nil
	}
	if mp, ferr := parseL3VPNNLRI(b, opts, !first); ferr == nil {
		return mp, nil
	}
	return nil, err
}

// parseL3VPNNLRI performs the actual parsing without any recursion. With
// singleLabel set, each NLRI carries exactly one label whose S bit is ignored.
func parseL3VPNNLRI(b []byte, opts Options, singleLabel bool) (*base.MPNLRI, error) {
	maxPrefixBits := 32
	if opts.IPv6 {
		maxPrefixBits = 128
	}
	mpnlri := base.MPNLRI{NLRI: make([]base.Route, 0)}
	p := 0

	for p < len(b) {
		up := base.Route{Label: make([]*base.Label, 0)}

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

		if opts.Withdraw {
			// RFC 8277 §2.4: the 3-octet Compatibility field (0x800000, or
			// 0x000000 from some implementations) MUST be ignored on reception.
			if p+3 > len(b) {
				return nil, fmt.Errorf("not enough bytes for compatibility field at pos %d", p)
			}
			up.Label = nil
			p += 3
		} else {
			for {
				if p+3 > len(b) {
					return nil, fmt.Errorf("not enough bytes for label at pos %d", p)
				}
				l, err := base.MakeLabel(b[p:p+3], opts.SRv6)
				if err != nil {
					return nil, fmt.Errorf("failed to parse label at pos %d: %w", p, err)
				}
				up.Label = append(up.Label, l)
				p += 3
				// RFC 8277 §2.2: without the Multiple Labels Capability there
				// is exactly one label and its S bit MUST be ignored.
				if opts.SRv6 || singleLabel || l.BoS {
					break
				}
			}
		}

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

		// Overhead in bits: (label bytes or 3 bytes for compat) + 8-byte RD
		labelBytes := 3
		if up.Label != nil {
			labelBytes = len(up.Label) * 3
		}
		overheadBits := (labelBytes * 8) + 64

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
