package message

import (
	"strconv"
	"strings"

	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// classfulTransport processes a BGP Classful Transport (AFI 1/2, SAFI 76,
// RFC 9832) MP_REACH/MP_UNREACH update. The NLRI is decoded and built like
// L3VPN (RFC 9832 §6.1); each prefix additionally carries the route's
// Transport Class IDs.
func (p *producer) classfulTransport(nlri bgp.MPNLRI, op int, ph *bmp.PerPeerHeader, update *bgp.Update) ([]ClassfulTransportPrefix, error) {
	prfxs, err := p.rdLabeledPrefixes(nlri.GetNLRICT, nlri, op, ph, update)
	if err != nil {
		return nil, err
	}
	tcIDs := extractTransportClassIDs(update.BaseAttributes)
	ov := extractOriginValidation(update.BaseAttributes)
	msgs := make([]ClassfulTransportPrefix, len(prfxs))
	for i := range prfxs {
		msgs[i] = ClassfulTransportPrefix{L3VPNPrefix: prfxs[i], TransportClassIDs: tcIDs}
		msgs[i].OriginValidation = ov
	}
	return msgs, nil
}

// extractTransportClassIDs returns the Transport Class IDs of the Transport
// Class Route Targets in attrs (RFC 9832 §4.3). The non-transitive variant is
// equivalent to the transitive one (§4.3), but when both are present only the
// transitive ones are used (§7.14). Returns nil if there are none.
func extractTransportClassIDs(attrs *bgp.BaseAttributes) []uint32 {
	if attrs == nil {
		return nil
	}
	ids := transportClassIDs(attrs.ExtCommunityList, bgp.ECPTransportTarget)
	if ids == nil {
		ids = transportClassIDs(attrs.ExtCommunityList, bgp.ECPNonTransitiveTransportTarget)
	}
	return ids
}

// transportClassIDs parses the ID from each "<prefix><reserved>:<id>"
// community in ecs.
func transportClassIDs(ecs []string, prefix string) []uint32 {
	var ids []uint32
	for _, ec := range ecs {
		v, ok := strings.CutPrefix(ec, prefix)
		if !ok {
			continue
		}
		id, err := strconv.ParseUint(v[strings.LastIndexByte(v, ':')+1:], 10, 32)
		if err != nil {
			continue
		}
		ids = append(ids, uint32(id))
	}
	return ids
}
