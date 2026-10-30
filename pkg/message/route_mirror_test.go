package message

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// mirrorKeepalive is a 19-byte BGP KEEPALIVE PDU.
var mirrorKeepalive = append(bytes.Repeat([]byte{0xff}, 16), 0x00, 0x13, 0x04)

// mirrorTLV encodes a Route Mirroring TLV (RFC 7854 §4.7).
func mirrorTLV(t uint16, v []byte) []byte {
	b := make([]byte, 4, 4+len(v))
	binary.BigEndian.PutUint16(b[0:], t)
	binary.BigEndian.PutUint16(b[2:], uint16(len(v)))
	return append(b, v...)
}

// decodeRouteMirror unmarshals the single message recorded by publisher and checks its topic.
func decodeRouteMirror(t *testing.T, publisher *recordingPublisher) RouteMirror {
	t.Helper()
	if len(publisher.msgs) != 1 {
		t.Fatalf("published %d messages, want 1", len(publisher.msgs))
	}
	if got := publisher.msgs[0].msgType; got != bmp.RouteMirroringMsg {
		t.Fatalf("published message type = %d, want %d", got, bmp.RouteMirroringMsg)
	}
	var m RouteMirror
	if err := json.Unmarshal(publisher.msgs[0].payload, &m); err != nil {
		t.Fatalf("published RouteMirror JSON: %v", err)
	}
	return m
}

// publishWire decodes a Route Mirroring body from wire bytes and publishes it.
func publishWire(t *testing.T, body []byte) RouteMirror {
	t.Helper()
	rm, err := bmp.UnmarshalRouteMirrorMessage(body)
	if err != nil {
		t.Fatalf("UnmarshalRouteMirrorMessage() error = %v", err)
	}
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	p.produceRouteMirrorMessage(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0), Payload: rm})
	return decodeRouteMirror(t, publisher)
}

func TestProduceRouteMirrorMessage(t *testing.T) {
	rm := &bmp.RouteMirror{TLVs: []bmp.RouteMirrorTLV{
		{Type: bmp.RouteMirrorTLVInformation, Value: []byte{0, 0}, InfoCode: bmp.RouteMirrorInfoErroredPDU},
		{Type: 0x8000, Value: []byte{0xde, 0xad}},
		{Type: bmp.RouteMirrorTLVBGPMessage, Value: mirrorKeepalive, BGPLength: 19, BGPType: 4},
	}}
	publisher := &recordingPublisher{}
	p := &producer{publisher: publisher}
	// O flag set: Adj-RIB-Out (RFC 8671).
	p.produceRouteMirrorMessage(bmp.Message{PeerHeader: makePeerHeader(t, bmp.PeerType0, 0x10), Payload: rm})

	m := decodeRouteMirror(t, publisher)
	if m.RouterHash != defaultTestRouterHash || m.RouterIP != defaultTestRouterIP || m.PeerASN != 65000 ||
		m.RemoteBGPID != "10.0.0.1" || m.PeerHash == "" || m.Timestamp == "" || !m.IsAdjRIBOut {
		t.Errorf("unexpected peer identity: %+v", m)
	}
	if len(m.TLVs) != 3 {
		t.Fatalf("got %d TLVs, want 3: %+v", len(m.TLVs), m.TLVs)
	}
	if info := m.TLVs[0].Information; m.TLVs[0].Type != 1 || info == nil || info.Code != 0 || info.Name != "errored_pdu" {
		t.Errorf("TLV 0 = %+v, want Errored PDU information", m.TLVs[0])
	}
	if m.TLVs[1].Type != 0x8000 || m.TLVs[1].Value != "dead" || m.TLVs[1].BGPMessage != nil || m.TLVs[1].Information != nil {
		t.Errorf("TLV 1 = %+v, want unknown TLV retained as hex", m.TLVs[1])
	}
	bgp := m.TLVs[2].BGPMessage
	if m.TLVs[2].Type != 0 || bgp == nil || bgp.Type != 4 || bgp.Length != 19 || !bgp.IsErrored ||
		bgp.PDU != "ffffffffffffffffffffffffffffffff001304" {
		t.Errorf("TLV 2 = %+v (%+v), want errored KEEPALIVE", m.TLVs[2], bgp)
	}
}

func TestProduceRouteMirrorMessageWithoutErroredPDU(t *testing.T) {
	tests := []struct {
		name string
		tlvs []bmp.RouteMirrorTLV
	}{
		{name: "BGP message only", tlvs: []bmp.RouteMirrorTLV{
			{Type: bmp.RouteMirrorTLVBGPMessage, Value: mirrorKeepalive, BGPLength: 19, BGPType: 4},
		}},
		{name: "messages lost alone", tlvs: []bmp.RouteMirrorTLV{
			{Type: bmp.RouteMirrorTLVInformation, Value: []byte{0, 1}, InfoCode: bmp.RouteMirrorInfoMessagesLost},
		}},
		{name: "malformed Information TLV does not mark the PDU errored", tlvs: []bmp.RouteMirrorTLV{
			{Type: bmp.RouteMirrorTLVInformation, Value: []byte{0}, Malformed: true},
			{Type: bmp.RouteMirrorTLVBGPMessage, Value: mirrorKeepalive, BGPLength: 19, BGPType: 4},
		}},
		{name: "no TLVs", tlvs: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &recordingPublisher{}
			p := &producer{publisher: publisher}
			p.produceRouteMirrorMessage(bmp.Message{
				PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
				Payload:    &bmp.RouteMirror{TLVs: tt.tlvs},
			})
			m := decodeRouteMirror(t, publisher)
			if m.TLVs == nil || len(m.TLVs) != len(tt.tlvs) {
				t.Fatalf("got TLVs %+v, want %d", m.TLVs, len(tt.tlvs))
			}
			for _, tlv := range m.TLVs {
				if tlv.BGPMessage != nil && tlv.BGPMessage.IsErrored {
					t.Errorf("BGP message marked errored without an Errored PDU TLV: %+v", tlv.BGPMessage)
				}
				if tlv.Information != nil && tlv.Information.Name != "messages_lost" {
					t.Errorf("information = %+v, want messages_lost", tlv.Information)
				}
			}
		})
	}
}

// TestProduceRouteMirrorMessageFromWire checks that unusual but parseable messages
// are still published.
func TestProduceRouteMirrorMessageFromWire(t *testing.T) {
	t.Run("malformed BGP Message next to Messages Lost", func(t *testing.T) {
		m := publishWire(t, []byte{0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0xff, 0xff})
		if len(m.TLVs) != 2 {
			t.Fatalf("got TLVs %+v, want 2", m.TLVs)
		}
		if info := m.TLVs[0].Information; info == nil || info.Name != "messages_lost" {
			t.Errorf("TLV 0 = %+v, want messages_lost", m.TLVs[0])
		}
		if got := m.TLVs[1]; got.Type != 0 || !got.Malformed || got.Value != "ffff" || got.BGPMessage != nil {
			t.Errorf("TLV 1 = %+v, want malformed BGP Message kept as hex", got)
		}
	})
	t.Run("extended BGP message longer than 4096 bytes", func(t *testing.T) {
		pdu := make([]byte, 5000)
		copy(pdu, bytes.Repeat([]byte{0xff}, 16))
		binary.BigEndian.PutUint16(pdu[16:], 5000)
		pdu[18] = 2
		m := publishWire(t, mirrorTLV(bmp.RouteMirrorTLVBGPMessage, pdu))
		if len(m.TLVs) != 1 || m.TLVs[0].BGPMessage == nil {
			t.Fatalf("got TLVs %+v, want one BGP message", m.TLVs)
		}
		if got := m.TLVs[0].BGPMessage; got.Length != 5000 || got.Type != 2 || got.PDU != hex.EncodeToString(pdu) {
			t.Errorf("BGP message type %d length %d PDU %d hex chars, want type 2 length 5000 PDU 10000 hex chars",
				got.Type, got.Length, len(got.PDU))
		}
	})
	t.Run("marker not all ones", func(t *testing.T) {
		pdu := append(make([]byte, 16), 0x00, 0x13, 0x04)
		m := publishWire(t, mirrorTLV(bmp.RouteMirrorTLVBGPMessage, pdu))
		if len(m.TLVs) != 1 || m.TLVs[0].BGPMessage == nil || m.TLVs[0].BGPMessage.PDU != hex.EncodeToString(pdu) {
			t.Errorf("got TLVs %+v, want the PDU published verbatim", m.TLVs)
		}
	})
}

// chanPublisher forwards each published message to a channel.
type chanPublisher chan recordedMsg

func (c chanPublisher) PublishMessage(msgType int, _ []byte, msg []byte) error {
	c <- recordedMsg{msgType: msgType, payload: append([]byte(nil), msg...)}
	return nil
}

func (c chanPublisher) Stop() {}

// TestProducerRouteMirrorOrder verifies Route Mirroring received before the
// first PeerUp is dropped like Route Monitoring (RFC 7854 §4.7), and later
// messages are published in arrival order under the PeerUp's router identity.
func TestProducerRouteMirrorOrder(t *testing.T) {
	const n = 50
	const speakerIP = "10.2.1.3" // TCP source, differs from the PeerUp local address
	publisher := make(chanPublisher, n+2)
	queue := make(chan bmp.Message)
	done := make(chan struct{})
	go func() {
		NewProducer(publisher, true).Producer(queue, make(chan struct{}))
		close(done)
	}()

	ph := makePeerHeader(t, bmp.PeerType0, 0)
	mirror := func(code int) bmp.Message {
		return bmp.Message{
			PeerHeader: ph,
			Payload: &bmp.RouteMirror{TLVs: []bmp.RouteMirrorTLV{
				{Type: bmp.RouteMirrorTLVInformation, Value: []byte{0, byte(code)}, InfoCode: uint16(code)},
			}},
			SpeakerIP: speakerIP,
		}
	}
	queue <- mirror(n) // before PeerUp: dropped
	queue <- bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.10"), SpeakerIP: speakerIP}
	for i := 0; i < n; i++ {
		queue <- mirror(i)
	}
	close(queue)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("producer did not stop")
	}
	close(publisher)

	rec, ok := <-publisher
	if !ok || rec.msgType != bmp.PeerStateChangeMsg {
		t.Fatalf("first message type = %d (ok %v), want the PeerUp (%d)", rec.msgType, ok, bmp.PeerStateChangeMsg)
	}
	var up PeerStateChange
	if err := json.Unmarshal(rec.payload, &up); err != nil {
		t.Fatalf("PeerUp: %v", err)
	}
	if up.RouterIP != "192.0.2.10" || up.RouterHash == "" {
		t.Fatalf("PeerUp router identity = %q/%q, want the local address 192.0.2.10", up.RouterIP, up.RouterHash)
	}
	i := 0
	for rec := range publisher {
		var m RouteMirror
		if err := json.Unmarshal(rec.payload, &m); err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if rec.msgType != bmp.RouteMirroringMsg || len(m.TLVs) != 1 || m.TLVs[0].Information == nil {
			t.Fatalf("message %d = type %d %+v, want a Route Mirroring message", i, rec.msgType, m)
		}
		if got := m.TLVs[0].Information.Code; got != uint16(i) {
			t.Fatalf("message %d carries code %d: published out of order or before PeerUp", i, got)
		}
		if m.RouterIP != up.RouterIP || m.RouterHash != up.RouterHash {
			t.Errorf("message %d router identity = %q/%q, want the PeerUp's %q/%q", i, m.RouterIP, m.RouterHash, up.RouterIP, up.RouterHash)
		}
		i++
	}
	if i != n {
		t.Fatalf("published %d Route Mirroring messages, want %d", i, n)
	}
}
