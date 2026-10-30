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

// UnmarshalUnicastNLRIWithState builds MP NLRI object from the slice of
// bytes of a SAFI 1 NLRI field of AFI 2 (ipv6) or 1, reading Path
// Identifiers as state s says (see base.UnmarshalRoutesWithState).
func UnmarshalUnicastNLRIWithState(b []byte, s base.PathIDState, ipv6 bool) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Unicast NLRI Raw: %s", tools.MessageHex(b))
	}
	if len(b) == 0 {
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}
	return base.UnmarshalRoutesWithState(b, s, ipv6)
}

// Options gives the session and attribute context that RFC 8277 labeled
// unicast NLRI (AFI 1/2, SAFI 4) is decoded in.
type Options struct {
	// PathIDs says whether a 4-octet Path Identifier precedes the Length
	// field (RFC 8277 §2.2, §2.3; RFC 7911 §3) and whether a failed parse is
	// tried once more with the setting flipped; see base.DecodeWithPathID.
	PathIDs base.PathIDState
	// PathID is the setting tried first while PathIDs is unknown; a failed
	// parse with it set is then tried once more without.
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
	// compatMarker reads a label field of 0x800000 as no label, for
	// UnmarshalLUNLRI; see isCompatMarker.
	compatMarker bool
}

// isCompatMarker reports whether the label field at the start of b is
// 0x800000. UnmarshalLUNLRI, which is not told whether it decodes an
// MP_REACH_NLRI or MP_UNREACH_NLRI field, reads it as the withdrawal
// Compatibility field (RFC 8277 §2.4), as it always did. On an announcement
// it would be a single label with S=0, which RFC 8277 §2.2 does not allow
// ("MUST be set to one on transmission").
func isCompatMarker(b []byte) bool {
	return len(b) >= 3 && b[0] == 0x80 && b[1] == 0x00 && b[2] == 0x00
}

// UnmarshalLUNLRI builds MP NLRI object from the slice of bytes of a labeled
// unicast MP_REACH_NLRI or MP_UNREACH_NLRI field. It is
// UnmarshalLUNLRIWithOptions with the Multiple Labels Capability state
// unknown and no address family, except that, not knowing the direction, it
// reads a label field of 0x800000 as the Compatibility field (RFC 8277
// §2.4), as before.
func UnmarshalLUNLRI(b []byte, pathID bool) (*base.MPNLRI, error) {
	return UnmarshalLUNLRIWithOptions(b, Options{PathID: pathID, compatMarker: true})
}

// UnmarshalLUNLRIWithOptions builds MP NLRI object from the slice of bytes of
// an MP_REACH_NLRI or MP_UNREACH_NLRI attribute of AFI 1/2 SAFI 4, decoded per
// RFC 8277 §2 according to opts.
func UnmarshalLUNLRIWithOptions(b []byte, opts Options) (*base.MPNLRI, error) {
	if glog.V(6) {
		glog.Infof("MP Label Unicast NLRI Raw: %s options: %+v", tools.MessageHex(b), opts)
	}
	// Return empty NLRI if no data
	if len(b) == 0 {
		return &base.MPNLRI{NLRI: make([]base.Route, 0)}, nil
	}
	mp, err := decodeLUPathIDs(b, opts)
	if err == nil {
		return mp, nil
	}
	glog.Errorf("failed to reconstruct labeled unicast prefix from slice %s with error: %+v",
		tools.MessageHex(b), err)
	return nil, err
}

// decodeLUPathIDs parses b with the Path ID setting of opts.PathIDs (see
// base.DecodeWithPathID). While it is unknown, as before, a field that fails
// with Path IDs is retried without them, but not the other way round: many
// malformed fields read as a route once their first four octets are taken
// as a Path ID.
func decodeLUPathIDs(b []byte, opts Options) (*base.MPNLRI, error) {
	if opts.PathIDs != base.PathIDUnknown {
		return base.DecodeWithPathID(opts.PathIDs, opts.PathID, func(pathID bool) (*base.MPNLRI, error) {
			o := opts
			o.PathID = pathID
			return parseLabelField(b, o)
		})
	}
	mp, err := parseLabelField(b, opts)
	if err != nil && opts.PathID {
		opts.PathID = false
		if mp, ferr := parseLabelField(b, opts); ferr == nil {
			return mp, nil
		}
	}
	return mp, err
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
		if opts.compatMarker && f != base.CompatibilityField && isCompatMarker(b[p:]) {
			labels, n, err = nil, 3, nil
		}
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
