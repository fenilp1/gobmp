package base

import "fmt"

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

// LabelField selects how ReadLabelField reads the label field of an RFC 8277
// NLRI, the part between the Length and the prefix (or RD).
type LabelField uint8

const (
	// LabelStack reads labels up to and including the one with the S bit
	// set (RFC 8277 §2.3).
	LabelStack LabelField = iota
	// SingleLabel reads exactly one label and ignores its S bit (RFC 8277
	// §2.2).
	SingleLabel
	// SRv6Label reads one 3-octet field holding transposed SRv6 SID bits
	// (RFC 9252 §4).
	SRv6Label
	// CompatibilityField skips the 3-octet Compatibility field of a
	// withdrawal, whatever its value (RFC 8277 §2.4).
	CompatibilityField
)

// ReadLabelField reads the label field at the start of b as f says and
// returns the labels, nil for CompatibilityField, and the number of bytes
// the field takes.
func ReadLabelField(b []byte, f LabelField) ([]*Label, int, error) {
	if f == CompatibilityField {
		if len(b) < 3 {
			return nil, 0, fmt.Errorf("not enough bytes for compatibility field")
		}
		return nil, 3, nil
	}
	labels := make([]*Label, 0, 1)
	p := 0
	for {
		if p+3 > len(b) {
			return nil, 0, fmt.Errorf("not enough bytes for label at offset %d", p)
		}
		l, err := MakeLabel(b[p:p+3], f == SRv6Label)
		if err != nil {
			return nil, 0, err
		}
		labels = append(labels, l)
		p += 3
		if f != LabelStack || l.BoS {
			return labels, p, nil
		}
	}
}

// DecodeLabeledNLRI decodes announced RFC 8277 NLRI with parse, trying the
// label field readings in an order chosen by the Multiple Labels Capability
// state m, and returns the first valid result or else the first error:
//   - Confirmed: LabelStack only (RFC 8277 §2.3).
//   - Absent: SingleLabel (RFC 8277 §2.2: one label, S bit ignored), then
//     LabelStack if that parse is invalid.
//   - Unknown: LabelStack, then SingleLabel.
//
// A passive collector must stay correct when its view of the capability is
// stale or shared between sessions, hence the fallbacks; for a compliant
// router both readings agree. SingleLabel goes first when the capability is
// known absent because the S bit walk can produce a valid looking but wrong
// parse when the bytes after an S=0 label read as a label with S set.
// Withdrawals (CompatibilityField) and SRv6Label have no stack to choose and
// call parse directly.
func DecodeLabeledNLRI(m MultiLabel, parse func(LabelField) (*MPNLRI, error)) (*MPNLRI, error) {
	if m == MultiLabelConfirmed {
		return parse(LabelStack)
	}
	first, second := LabelStack, SingleLabel
	if m == MultiLabelAbsent {
		first, second = SingleLabel, LabelStack
	}
	mp, err := parse(first)
	if err == nil {
		return mp, nil
	}
	if mp, ferr := parse(second); ferr == nil {
		return mp, nil
	}
	return nil, err
}
