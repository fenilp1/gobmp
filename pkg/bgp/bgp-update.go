package bgp

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bgpls"
	"github.com/sbezverk/gobmp/pkg/prefixsid"
	"github.com/sbezverk/tools"
)

const (
	MP_REACH_NLRI   = 14
	MP_UNREACH_NLRI = 15
	BGP4_NLRI       = 0
)

// Update defines a structure of BGP Update message
type Update struct {
	WithdrawnRoutesLength    uint16
	WithdrawnRoutes          []byte
	TotalPathAttributeLength uint16
	PathAttributes           []PathAttribute
	NLRI                     []byte
	BaseAttributes           *BaseAttributes
}

// GetAllAttributeID returns a slice of uint8 with all attribute type codes found in BGP Update
func (up *Update) GetAllAttributeID() []uint8 {
	attrs := make([]uint8, 0, len(up.PathAttributes))
	for _, attr := range up.PathAttributes {
		attrs = append(attrs, attr.AttributeType)
	}

	return attrs
}

// GetBaseAttrHash calculates 16 bytes MD5 Hash of all available base attributes.
func (up *Update) GetBaseAttrHash() string {
	h := md5.New()
	for _, attr := range up.PathAttributes {
		h.Write(attr.Attribute)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetBGPLSAttribute returns the parsed BGP-LS Attribute (BGP path attribute
// type 29 per RFC 9552 §5.3), or NewAttributeNotFoundError when the update
// carries no such attribute. The attribute payload is a stream of BGP-LS TLVs;
// see RFC 9552 §9 Table 18 for the codepoint registry.
func (up *Update) GetBGPLSAttribute() (*bgpls.NLRI, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 29 {
			if up.BaseAttributes != nil && up.BaseAttributes.bgplsParsed != nil {
				return up.BaseAttributes.bgplsParsed, nil
			}
			ls, err := bgpls.UnmarshalBGPLSNLRI(attr.Attribute)
			if err != nil {
				return nil, err
			}
			if up.BaseAttributes != nil {
				up.BaseAttributes.bgplsParsed = ls
			}
			return ls, nil
		}
	}
	return nil, NewAttributeNotFoundError(29, "BGP-LS")
}

// Deprecated: use GetBGPLSAttribute. Kept for API compatibility.
func (up *Update) GetNLRI29() (*bgpls.NLRI, error) { return up.GetBGPLSAttribute() }

// GetAttrPrefixSID check for presence of BGP Attribute Prefix SID (40) and instantiates it
func (up *Update) GetAttrPrefixSID() (*prefixsid.PSid, error) {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 40 {
			psid, err := prefixsid.UnmarshalBGPAttrPrefixSID(attr.Attribute)
			if err != nil {
				return nil, err
			}
			return psid, nil
		}
	}
	return nil, NewAttributeNotFoundError(40, "Prefix SID")
}

// HasPrefixSID check for presence of BGP Attribute Prefix SID (40) and returns true is found
func (up *Update) HasPrefixSID() bool {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 40 {
			return true
		}
	}

	return false
}

// HasSRv6Transposition reports whether the label fields of this update's L3
// service NLRI carry SRv6 SID bits under the Transposition Scheme (RFC 9252
// §4). The decision is taken from the first Prefix-SID attribute (RFC 8669
// §6), its first SRv6 L3 Service TLV (type 5; RFC 9252 §7), that TLV's
// first SRv6 SID Information Sub-TLV (§3.1) and its SRv6 SID Structure
// Sub-Sub-TLV: the Transposition Length must be non-zero (§3.2.1). A
// Prefix-SID with only SR-MPLS TLVs (RFC 8669), or with an SRv6 SID sent
// whole, leaves an MPLS label in the label field (§5.1, §5.2). The SRv6 L2
// Service TLV (type 6) does not apply to L3 routes and is only checked for
// framing. A Prefix-SID whose TLV framing or RFC 8669 TLV lengths are
// malformed anywhere is not used (RFC 9252 §7, RFC 8669 §6), so it reports
// false.
func (up *Update) HasSRv6Transposition() bool {
	for _, attr := range up.PathAttributes {
		if attr.AttributeType == 40 {
			return prefixSIDHasTransposition(attr.Attribute)
		}
	}
	return false
}

// prefixSIDHasTransposition validates the TLV framing of a whole Prefix-SID
// attribute value (Type, 2-octet Length, Value; RFC 8669 §3), the lengths of
// the Label-Index and Originator SRGB TLVs and the nested framing of every
// SRv6 Service TLV, and reports the transposition state of the first SRv6 L3
// Service TLV.
func prefixSIDHasTransposition(b []byte) bool {
	transposed, seenL3 := false, false
	for p := 0; p < len(b); {
		if p+3 > len(b) {
			return false
		}
		t, l := b[p], int(binary.BigEndian.Uint16(b[p+1:p+3]))
		p += 3
		if p+l > len(b) {
			return false
		}
		// RFC 8669 §6: a TLV length outside the TLV's constraints makes the
		// attribute malformed. Label-Index (§3.1) "Length: 7"; Originator
		// SRGB (§3.2) "Length: ... 2 + (non-zero multiple of 6)".
		if (t == 1 && l != 7) || (t == 3 && (l < 8 || (l-2)%6 != 0)) {
			return false
		}
		if t == 5 || t == 6 {
			ok, tr := srv6ServiceCheck(b[p : p+l])
			if !ok {
				return false
			}
			if t == 5 && !seenL3 {
				seenL3, transposed = true, tr
			}
		}
		p += l
	}
	return transposed
}

// srv6ServiceCheck walks an SRv6 Service TLV value: Reserved, then Sub-TLVs
// (RFC 9252 §2). ok is false when the TLV is malformed (§7). transposed is
// the state of the first SRv6 SID Information Sub-TLV (type 1, §3.1).
func srv6ServiceCheck(b []byte) (ok, transposed bool) {
	if len(b) < 1 {
		return false, false
	}
	seenInfo := false
	for p := 1; p < len(b); {
		if p+3 > len(b) {
			return false, false
		}
		t, l := b[p], int(binary.BigEndian.Uint16(b[p+1:p+3]))
		p += 3
		if p+l > len(b) {
			return false, false
		}
		if t == 1 {
			ok, tr := sidInformationCheck(b[p : p+l])
			if !ok {
				return false, false
			}
			if !seenInfo {
				seenInfo, transposed = true, tr
			}
		}
		p += l
	}
	return true, transposed
}

// sidInformationCheck walks an SRv6 SID Information Sub-TLV value: Reserved1,
// SID, Flags, Endpoint Behavior and Reserved2 (21 octets), then Sub-Sub-TLVs
// (RFC 9252 §3.1). ok is false when it is malformed (§7). transposed is set
// when its first SRv6 SID Structure Sub-Sub-TLV (type 1, §3.2.1) has a
// non-zero Transposition Length, the fifth octet of its value.
func sidInformationCheck(b []byte) (ok, transposed bool) {
	if len(b) < 21 {
		return false, false
	}
	seenStructure := false
	for q := 21; q < len(b); {
		if q+3 > len(b) {
			return false, false
		}
		t, l := b[q], int(binary.BigEndian.Uint16(b[q+1:q+3]))
		q += 3
		if q+l > len(b) {
			return false, false
		}
		if t == 1 && !seenStructure {
			seenStructure, transposed = true, l >= 6 && b[q+4] != 0
		}
		q += l
	}
	return true, transposed
}

func (up *Update) GetNLRIType() (uint8, int) {
	if len(up.PathAttributes) == 0 {
		// Fall back to default NLRI
		return BGP4_NLRI, 0
	}
	for i, p := range up.PathAttributes {
		switch p.AttributeType {
		case MP_REACH_NLRI:
			return MP_REACH_NLRI, i
		case MP_UNREACH_NLRI:
			return MP_UNREACH_NLRI, i
		}
	}

	return BGP4_NLRI, 0
}

// UnmarshalBGPUpdate builds a BGP Update object from the byte slice provided.
// AS_PATH width (2-byte vs 4-byte) is inferred by heuristic; use
// UnmarshalBGPUpdateWithAS4Hint when the caller has an authoritative indicator.
func UnmarshalBGPUpdate(b []byte) (*Update, error) {
	return unmarshalBGPUpdate(b, nil)
}

// UnmarshalBGPUpdateWithAS4Hint is UnmarshalBGPUpdate with an authoritative
// 4-byte-ASN indicator (typically PeerHeader.Is4ByteASN() per RFC 7854 §4.2,
// i.e. !A): true = 4-byte, false = 2-byte. Do not pass the raw A bit.
func UnmarshalBGPUpdateWithAS4Hint(b []byte, as4 bool) (*Update, error) {
	return unmarshalBGPUpdate(b, &as4)
}

func unmarshalBGPUpdate(b []byte, as4hint *bool) (*Update, error) {
	if glog.V(6) {
		glog.Infof("BGPUpdate Raw: %s", tools.MessageHex(b))
	}
	p := 0
	u := Update{}
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Withdrawn Routes Length: need 2 bytes, have %d", len(b)-p)
	}
	u.WithdrawnRoutesLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+int(u.WithdrawnRoutesLength) > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Withdrawn Routes: need %d bytes, have %d", u.WithdrawnRoutesLength, len(b)-p)
	}
	u.WithdrawnRoutes = make([]byte, u.WithdrawnRoutesLength)
	copy(u.WithdrawnRoutes, b[p:p+int(u.WithdrawnRoutesLength)])
	p += int(u.WithdrawnRoutesLength)
	if p+2 > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Total Path Attribute Length: need 2 bytes, have %d", len(b)-p)
	}
	u.TotalPathAttributeLength = binary.BigEndian.Uint16(b[p : p+2])
	p += 2
	if p+int(u.TotalPathAttributeLength) > len(b) {
		return nil, fmt.Errorf("not enough bytes to unmarshal Path Attributes: need %d bytes, have %d", u.TotalPathAttributeLength, len(b)-p)
	}
	// Single pass: parse path attributes and populate base attributes simultaneously
	attrs, baseAttrs, err := unmarshalBGPPathAttributes(b[p:p+int(u.TotalPathAttributeLength)], as4hint)
	if err != nil {
		return nil, err
	}
	u.PathAttributes = attrs
	u.BaseAttributes = baseAttrs
	p += int(u.TotalPathAttributeLength)
	u.NLRI = make([]byte, len(b)-p)
	copy(u.NLRI, b[p:])

	return &u, nil
}
