package message

import (
	"net"
	"sync"
	"testing"

	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bgp"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// locRIBHeader returns a Loc-RIB Instance Peer header (RFC 9069 §5.1) with
// the given Peer BGP ID and Peer Distinguisher.
func locRIBHeader(bgpID string, rd []byte) *bmp.PerPeerHeader {
	return &bmp.PerPeerHeader{
		PeerType:          bmp.PeerType3,
		PeerDistinguisher: rd,
		PeerAddress:       make([]byte, 16),
		PeerBGPID:         net.ParseIP(bgpID).To4(),
		PeerTimestamp:     make([]byte, 8),
	}
}

// globalHeader returns a Global Instance Peer header (RFC 7854 §4.2) for the
// peer at addr, an IPv4 or IPv6 address, with BGP ID bgpID.
func globalHeader(addr, bgpID string) *bmp.PerPeerHeader {
	return globalHeaderFlags(addr, bgpID, 0)
}

// globalHeaderFlags is globalHeader with the Peer Flags flags; the V flag is
// set for an IPv6 addr.
func globalHeaderFlags(addr, bgpID string, flags byte) *bmp.PerPeerHeader {
	b := []byte{byte(bmp.PeerType0), flags}
	ip := net.ParseIP(addr)
	if ip.To4() == nil {
		b[1] |= 0x80 // V flag
	}
	b = append(b, make([]byte, 8)...)
	if v4 := ip.To4(); v4 != nil {
		b = append(b, make([]byte, 12)...)
		b = append(b, v4...)
	} else {
		b = append(b, ip.To16()...)
	}
	b = append(b, 0x00, 0x00, 0xfd, 0xe8) // AS 65000
	b = append(b, net.ParseIP(bgpID).To4()...)
	b = append(b, make([]byte, 8)...)
	ph, err := bmp.UnmarshalPerPeerHeader(b)
	if err != nil {
		panic(err)
	}
	return attachDefaultTestIdentity(ph)
}

// TestSessionStateIsolation checks that ADD-PATH and Multiple Labels state
// is kept per session (RFC 7911 §3, RFC 8277 §2.1).
func TestSessionStateIsolation(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	v4uni := bgp.NLRIMessageType(1, 1)
	evpn := bgp.NLRIMessageType(25, 70)
	ph1 := globalHeader("192.0.2.1", "10.0.0.1")
	ph2 := globalHeader("192.0.2.2", "10.0.0.2")
	p.storeSession(ph1, sessionState{
		addPathSent: map[int]uint8{v4uni: 3},
		addPathRecv: map[int]uint8{v4uni: 3},
		multiLabel:  map[int]bool{v4uni: true},
	})
	p.storeSession(ph2, sessionState{
		addPathSent: map[int]uint8{evpn: 3},
		addPathRecv: map[int]uint8{evpn: 3},
	})
	tests := []struct {
		ph       *bmp.PerPeerHeader
		nlriType int
		wantIDs  base.PathIDState
		wantML   base.MultiLabel
	}{
		{ph1, v4uni, base.PathIDExpectPresent, base.MultiLabelConfirmed},
		{ph1, evpn, base.PathIDExpectAbsent, base.MultiLabelAbsent},
		{ph2, v4uni, base.PathIDExpectAbsent, base.MultiLabelAbsent},
		{ph2, evpn, base.PathIDExpectPresent, base.MultiLabelAbsent},
	}
	for _, tt := range tests {
		ids, ml := p.nlriState(tt.ph, tt.nlriType)
		if ids != tt.wantIDs || ml != tt.wantML {
			t.Errorf("session %s type %d: state %d, %d, want %d, %d", tt.ph.SessionKey(), tt.nlriType, ids, ml, tt.wantIDs, tt.wantML)
		}
	}
}

// TestMissingSession checks that a session with no Peer Up has unknown state.
func TestMissingSession(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	if ids, ml := p.nlriState(ph, bgp.NLRIMessageType(1, 1)); ids != base.PathIDUnknown || ml != base.MultiLabelUnknown {
		t.Errorf("state %d, %d, want unknown", ids, ml)
	}
	if tn := p.GetTableName(ph); tn != "" {
		t.Errorf("GetTableName() = %q, want empty", tn)
	}
}

// TestSessionLifecycle checks that a Peer Up creates the session state and
// its Peer Down removes it.
func TestSessionLifecycle(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	ph := locRIBHeader("10.0.0.1", make([]byte, 8))
	p.storeSession(ph, sessionState{
		addPathSent:   map[int]uint8{65537: 1},
		addPathRecv:   map[int]uint8{65537: 1},
		tableInfoTLVs: []bmp.InformationalTLV{{InformationType: 3, Information: []byte("VRF-CUSTOMER-A")}},
	})
	if ids, _ := p.nlriState(ph, 65537); ids != base.PathIDExpectPresent {
		t.Errorf("state after Peer Up %d, want present", ids)
	}
	if tn := p.GetTableName(ph); tn != "VRF-CUSTOMER-A" {
		t.Errorf("GetTableName() = %q, want VRF-CUSTOMER-A", tn)
	}
	p.deleteSession(ph)
	if ids, _ := p.nlriState(ph, 65537); ids != base.PathIDUnknown {
		t.Errorf("state after Peer Down %d, want unknown", ids)
	}
	if tn := p.GetTableName(ph); tn != "" {
		t.Errorf("GetTableName() after Peer Down = %q, want empty", tn)
	}
}

// TestConcurrentSessionAccess checks that the session map is safe for
// concurrent use.
func TestConcurrentSessionAccess(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	const numGoroutines = 10
	const numOperations = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			ph := globalHeader(net.IPv4(192, 0, 2, byte(id+1)).String(), "10.0.0.1")
			for j := 0; j < numOperations; j++ {
				p.storeSession(ph, sessionState{
					addPathSent: map[int]uint8{65537: 3},
					addPathRecv: map[int]uint8{65537: 3},
				})
				if ids, _ := p.nlriState(ph, 65537); ids != base.PathIDExpectPresent {
					t.Errorf("state %d, want present", ids)
				}
				p.deleteSession(ph)
				if ids, _ := p.nlriState(ph, 65537); ids != base.PathIDUnknown {
					t.Errorf("state %d after delete, want unknown", ids)
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestGetTableName verifies table name extraction from TLVs
func TestGetTableName(t *testing.T) {
	mockPub := &mockPublisher{}
	p := NewProducer(mockPub, false).(*producer)

	tests := []struct {
		name     string
		bgpID    string
		rd       []byte
		tlvs     []bmp.InformationalTLV
		expected string
	}{
		{
			name:  "Single table name TLV",
			bgpID: "10.0.0.1",
			rd:    make([]byte, 8),
			tlvs: []bmp.InformationalTLV{
				{InformationType: 3, Information: []byte("VRF-CUSTOMER-A")},
			},
			expected: "VRF-CUSTOMER-A",
		},
		{
			name:  "Multiple TLVs including table name",
			bgpID: "192.168.1.1",
			rd:    []byte{0, 0, 0xfd, 0xe8, 0, 0, 0, 100}, // 65000:100
			tlvs: []bmp.InformationalTLV{
				{InformationType: 1, Information: []byte("String TLV")},
				{InformationType: 3, Information: []byte("VRF-INTERNET")},
				{InformationType: 2, Information: []byte("SysDescr")},
			},
			expected: "VRF-INTERNET",
		},
		{
			name:     "No table name TLV",
			bgpID:    "10.0.0.2",
			rd:       make([]byte, 8),
			tlvs:     []bmp.InformationalTLV{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ph := locRIBHeader(tt.bgpID, tt.rd)
			p.storeSession(ph, sessionState{tableInfoTLVs: tt.tlvs})

			got := p.GetTableName(ph)
			if got != tt.expected {
				t.Errorf("GetTableName() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// Note: mockPublisher already defined in bmpstats_test.go, reusing it
