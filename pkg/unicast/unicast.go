package unicast

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/tools"
)

// UnmarshalUnicastNLRI builds MP NLRI object from the slice of bytes
func UnmarshalUnicastNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}
	mpnlri := base.MPNLRI{}
	r, err := base.UnmarshalRoutes(b, pathID)
	if err != nil {
		return nil, err
	}
	mpnlri.NLRI = r

	return &mpnlri, nil
}

// Options gives the session and attribute context that RFC 8277 labeled
// unicast NLRI (AFI 1/2, SAFI 4) is decoded in.
type Options struct {
	// PathID is set when ADD-PATH is negotiated: a 4-octet Path Identifier
	// precedes the Length field (RFC 8277 §2.2, §2.3; RFC 7911 §3). A failed
	// parse is tried once more with it flipped.
	PathID bool
	// MultiLabel is the Multiple Labels Capability state; see
	// base.DecodeLabeledNLRI.
	MultiLabel base.MultiLabel
	// Withdraw selects the MP_UNREACH_NLRI encoding (RFC 8277 §2.4): a 3-octet
	// Compatibility field, ignored on reception, in place of the labels.
	Withdraw bool
	// AFI is the address family, 1 or 2: the prefix may be up to 32 or 128
	// bits (RFC 8277 §2.2, §2.3). Zero allows up to 128.
	AFI uint16
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes of an
// announced labeled unicast NLRI field. It is UnmarshalLUNLRIWithOptions with
// the Multiple Labels Capability state unknown and no address family, so an
// MP_UNREACH_NLRI field, whose Compatibility field is not a label, should be
// decoded with Options.Withdraw instead.
func UnmarshalLUNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	return UnmarshalLUNLRIWithOptions(b, Options{PathID: pathID})
}

// UnmarshalLUNLRIWithOptions builds MP NLRI object from the slice of bytes of
// an MP_REACH_NLRI or MP_UNREACH_NLRI attribute of AFI 1/2 SAFI 4, decoded per
// RFC 8277 §2 according to opts. A failed parse is tried once more with the
// PathID flag flipped.
func UnmarshalLUNLRIWithOptions(b []byte, opts Options) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Label Unicast NLRI Raw: %s options: %+v", tools.MessageHex(b), opts)
	}
	// Return empty NLRI if no data
	if len(b) == 0 {
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}
	mp, err := parseLabelField(b, opts)
	if err == nil {
		return mp, nil
	}
	opts.PathID = !opts.PathID
	if mp, ferr := parseLabelField(b, opts); ferr == nil {
		return mp, nil
	}
	glog.Errorf("failed to reconstruct labeled unicast prefix from slice %s with error: %+v",
		tools.MessageHex(b), err)
	return nil, err
}

// parseLabelField picks the label field reading: the Compatibility field for
// withdrawals, else the label stack readings that base.DecodeLabeledNLRI
// orders by the Multiple Labels Capability state. RFC 9252 transposition does
// not apply: global IPv4/IPv6 over SRv6 uses SAFI 1 (RFC 9252 §5.3, §5.4).
func parseLabelField(b []byte, opts Options) (*base.MPNLRI, error) {
	if opts.Withdraw {
		return parseLUNLRI(b, opts, base.CompatibilityField)
	}
	return base.DecodeLabeledNLRI(opts.MultiLabel, func(f base.LabelField) (*base.MPNLRI, error) {
		return parseLUNLRI(b, opts, f)
	})
}

// parseLUNLRI parses the NLRI field, reading the label field of each NLRI as
// f says.
func parseLUNLRI(b []byte, opts Options, f base.LabelField) (*base.MPNLRI, error) {
	maxPrefixBits := 128
	if opts.AFI == 1 {
		maxPrefixBits = 32
	}
	mpnlri := base.MPNLRI{NLRI: make([]base.Route, 0)}
	for p := 0; p < len(b); {
		up := base.Route{}
		if opts.PathID {
			if p+4 > len(b) {
				return nil, fmt.Errorf("not enough bytes for PathID at pos %d", p)
			}
			up.PathID = binary.BigEndian.Uint32(b[p : p+4])
			p += 4
		}
		// Length in bits of the label field and prefix
		if p >= len(b) {
			return nil, fmt.Errorf("missing NLRI length at pos %d", p)
		}
		length := int(b[p])
		if length == 0 {
			return nil, fmt.Errorf("invalid NLRI length (0 bits) at pos %d", p)
		}
		p++

		labels, n, err := base.ReadLabelField(b[p:], f)
		if err != nil {
			return nil, fmt.Errorf("failed to parse label field at pos %d: %w", p, err)
		}
		up.Label = labels
		p += n

		// A prefix longer than the address family allows makes the NLRI
		// malformed (RFC 8277 §2.2, §2.3; RFC 7606 §5.3).
		prefixBits := length - n*8
		if prefixBits < 0 || prefixBits > maxPrefixBits {
			return nil, fmt.Errorf("malformed NLRI: prefix length %d bits outside 0-%d (NLRI=%d, label field=%d)",
				prefixBits, maxPrefixBits, length, n*8)
		}
		prefixBytes := (prefixBits + 7) / 8
		if p+prefixBytes > len(b) {
			return nil, fmt.Errorf("not enough bytes for prefix at pos %d (need %d)", p, prefixBytes)
		}
		up.Prefix = make([]byte, prefixBytes)
		copy(up.Prefix, b[p:p+prefixBytes])
		p += prefixBytes
		up.Length = uint8(prefixBits)

		mpnlri.NLRI = append(mpnlri.NLRI, up)
	}

	return &mpnlri, nil
}
