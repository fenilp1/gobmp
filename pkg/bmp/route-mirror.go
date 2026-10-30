package bmp

import (
	"encoding/binary"
	"fmt"

	"github.com/golang/glog"
	"github.com/sbezverk/tools"
)

// Route Mirroring TLV types per RFC 7854 §4.7
const (
	// RouteMirrorTLVBGPMessage carries a complete BGP PDU, including the 19-byte BGP header.
	// If present, it MUST be the last TLV of the message.
	RouteMirrorTLVBGPMessage = 0
	// RouteMirrorTLVInformation carries a 2-byte Information code
	RouteMirrorTLVInformation = 1
)

// Route Mirroring Information codes per RFC 7854 §4.7
const (
	// RouteMirrorInfoErroredPDU indicates the BGP Message TLV in the same message was found to
	// have an error that made it unusable (treated-as-withdraw, RFC 7606)
	RouteMirrorInfoErroredPDU = 0
	// RouteMirrorInfoMessagesLost indicates one or more messages were lost, e.g. due to resource exhaustion
	RouteMirrorInfoMessagesLost = 1
)

// bgpHeaderLength is the length of the BGP message header: 16-byte marker, 2-byte length, 1-byte type (RFC 4271 §4.1)
const bgpHeaderLength = 19

// RouteMirror defines BMP Route Mirroring message per RFC 7854 §4.7.
// TLVs are kept in wire order; unknown TLV types are retained raw.
// RFC 7854 makes every TLV optional, so TLVs may be empty.
type RouteMirror struct {
	TLVs []RouteMirrorTLV
}

// RouteMirrorTLV defines a single Route Mirroring TLV.
type RouteMirrorTLV struct {
	Type uint16
	// Value is the raw TLV value. For a BGP Message TLV it is the complete BGP PDU,
	// kept verbatim because it may be the errored PDU.
	Value []byte
	// Malformed is set when a BGP Message or Information TLV is too short to decode;
	// only Value is then meaningful.
	Malformed bool
	// BGPLength and BGPType are the BGP header's length and type fields;
	// set only for BGP Message TLVs. BGPLength is reported as found on the wire
	// and is not required to match len(Value).
	BGPLength uint16
	BGPType   uint8
	// InfoCode is the Information code; set only for Information TLVs.
	InfoCode uint16
}

// UnmarshalRouteMirrorMessage builds a BMP Route Mirroring object from the message body,
// that is the bytes following the Common Header and the Per-Peer Header.
// The mirrored BGP PDU is not decoded beyond its header, since it may be the errored one.
// An error is returned only when the TLV framing is truncated. A TLV too short to decode
// is kept raw and marked Malformed, and RFC 7854 §4.7 violations are logged, so that
// the rest of the message is still reported.
func UnmarshalRouteMirrorMessage(b []byte) (*RouteMirror, error) {
	if glog.V(6) {
		glog.Infof("BMP Route Mirroring Message Raw: %s", tools.MessageHex(b))
	}
	tlvs, err := UnmarshalTLV(b)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Route Mirroring TLVs: %w", err)
	}
	rm := &RouteMirror{TLVs: make([]RouteMirrorTLV, 0, len(tlvs))}
	for _, tlv := range tlvs {
		t := RouteMirrorTLV{Type: tlv.InformationType, Value: tlv.Information}
		switch tlv.InformationType {
		case RouteMirrorTLVBGPMessage:
			if len(tlv.Information) < bgpHeaderLength {
				t.Malformed = true
				break
			}
			t.BGPLength = binary.BigEndian.Uint16(tlv.Information[16:18])
			t.BGPType = tlv.Information[18]
		case RouteMirrorTLVInformation:
			if len(tlv.Information) < 2 {
				t.Malformed = true
				break
			}
			t.InfoCode = binary.BigEndian.Uint16(tlv.Information[:2])
		}
		rm.TLVs = append(rm.TLVs, t)
	}
	for _, w := range routeMirrorWarnings(rm.TLVs) {
		glog.Warningf("route mirroring: %s", w)
	}
	return rm, nil
}

// routeMirrorWarnings lists the RFC 7854 §4.7 violations in tlvs that do not prevent publishing.
func routeMirrorWarnings(tlvs []RouteMirrorTLV) []string {
	var warnings []string
	hasBGPMessage, hasErroredPDU := false, false
	for i, t := range tlvs {
		switch t.Type {
		case RouteMirrorTLVBGPMessage:
			hasBGPMessage = true
			if t.Malformed {
				warnings = append(warnings, fmt.Sprintf("BGP Message TLV of %d bytes is shorter than the %d-byte BGP header", len(t.Value), bgpHeaderLength))
			}
			if i != len(tlvs)-1 {
				warnings = append(warnings, "BGP Message TLV is not the last TLV")
			}
		case RouteMirrorTLVInformation:
			if len(t.Value) != 2 {
				warnings = append(warnings, fmt.Sprintf("Information TLV length is %d, want 2", len(t.Value)))
			}
			if !t.Malformed && t.InfoCode == RouteMirrorInfoErroredPDU {
				hasErroredPDU = true
			}
		}
	}
	if hasErroredPDU && !hasBGPMessage {
		warnings = append(warnings, "Errored PDU Information TLV without a BGP Message TLV")
	}
	return warnings
}
