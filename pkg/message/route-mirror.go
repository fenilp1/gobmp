package message

import (
	"encoding/hex"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// produceRouteMirrorMessage publishes one message per BMP Route Mirroring message.
func (p *producer) produceRouteMirrorMessage(msg bmp.Message) {
	if msg.PeerHeader == nil {
		glog.Errorf("perPeerHeader is missing, cannot construct Route Mirroring message")
		return
	}
	rm, ok := msg.Payload.(*bmp.RouteMirror)
	if !ok || rm == nil {
		glog.Errorf("got invalid Payload type in bmp.RouteMirror %+v", msg.Payload)
		return
	}
	ph := msg.PeerHeader
	m := RouteMirror{
		RouterHash:  ph.Identity.RouterHash,
		RouterIP:    ph.Identity.RouterIP,
		PeerHash:    ph.GetPeerHash(),
		RemoteBGPID: ph.GetPeerBGPIDString(),
		PeerIP:      ph.GetPeerAddrString(),
		PeerType:    uint8(ph.PeerType),
		PeerASN:     ph.PeerAS,
		PeerRD:      ph.GetPeerDistinguisherString(),
		Timestamp:   ph.GetPeerTimestamp(),
		TLVs:        make([]RouteMirrorTLV, 0, len(rm.TLVs)),
	}
	if f, err := ph.IsAdjRIBOut(); err == nil {
		m.IsAdjRIBOut = f
	}
	// An Errored PDU code refers to the BGP Message TLV of the same message (RFC 7854 §4.7).
	errored := false
	for _, tlv := range rm.TLVs {
		if tlv.Type == bmp.RouteMirrorTLVInformation && !tlv.Malformed && tlv.InfoCode == bmp.RouteMirrorInfoErroredPDU {
			errored = true
			break
		}
	}
	for _, tlv := range rm.TLVs {
		t := RouteMirrorTLV{Type: tlv.Type}
		switch {
		case tlv.Malformed:
			t.Value = hex.EncodeToString(tlv.Value)
			t.Malformed = true
		case tlv.Type == bmp.RouteMirrorTLVBGPMessage:
			t.BGPMessage = &RouteMirrorBGPMessage{
				Type:      tlv.BGPType,
				Length:    tlv.BGPLength,
				PDU:       hex.EncodeToString(tlv.Value),
				IsErrored: errored,
			}
		case tlv.Type == bmp.RouteMirrorTLVInformation:
			t.Information = &RouteMirrorInformation{Code: tlv.InfoCode, Name: routeMirrorInfoName(tlv.InfoCode)}
		default:
			t.Value = hex.EncodeToString(tlv.Value)
		}
		m.TLVs = append(m.TLVs, t)
	}
	if err := p.marshalAndPublish(&m, bmp.RouteMirroringMsg, []byte(m.RouterHash)); err != nil {
		glog.Errorf("failed to process Route Mirroring message with error: %+v", err)
	}
}

// routeMirrorInfoName returns the name of a known Information code, or "" otherwise.
func routeMirrorInfoName(code uint16) string {
	switch code {
	case bmp.RouteMirrorInfoErroredPDU:
		return "errored_pdu"
	case bmp.RouteMirrorInfoMessagesLost:
		return "messages_lost"
	}
	return ""
}
