package message

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/base"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

const (
	peerUP = iota
	peerDown
)

// sessionState holds what the Peer Up of one monitored session, keyed by
// bmp.PerPeerHeader.SessionKey, says about decoding its Route Monitoring
// messages. The maps are not changed once stored, so a copy may be read
// without the lock.
type sessionState struct {
	// addPathSent and addPathRecv hold the ADD-PATH Send/Receive value per
	// NLRI type (RFC 7911 §4) of the Peer Up sent OPEN, the monitored
	// router's, and received OPEN, the peer's (RFC 7854 §4.10).
	addPathSent, addPathRecv map[int]uint8
	// multiLabel holds the NLRI types for which the Multiple Labels
	// Capability was both sent and received (RFC 8277 §2.3).
	multiLabel map[int]bool
	// tableInfoTLVs holds the Peer Up Information TLVs, which include the
	// VRF/Table Name (RFC 9069 §5.2.1).
	tableInfoTLVs []bmp.InformationalTLV
	// peerUps counts the Peer Ups of a Loc-RIB's emulated peers that no
	// Peer Down has ended yet (RFC 9069 §6.1.1).
	peerUps int
}

// sessionSnapshot is the state of a session as the producer dispatched a
// message of it, attached to the message's per-peer header, so a message
// decoded later is not decoded with the state of a later Peer Up or Down.
type sessionSnapshot struct {
	s  sessionState
	ok bool
}

// ADD-PATH Send/Receive bits (RFC 7911 §4).
const (
	addPathReceive = 1
	addPathSend    = 2
)

// newSessionState returns the state a Peer Up sets up.
func newSessionState(peerUp *bmp.PeerUpMessage) sessionState {
	s := sessionState{
		addPathSent: peerUp.SentOpen.AddPathSendReceive(),
		addPathRecv: peerUp.ReceivedOpen.AddPathSendReceive(),
		multiLabel:  make(map[int]bool),
	}
	recv := peerUp.ReceivedOpen.MultiLabelCapability()
	for t, capable := range peerUp.SentOpen.MultiLabelCapability() {
		if capable && recv[t] {
			s.multiLabel[t] = true
		}
	}
	s.tableInfoTLVs = make([]bmp.InformationalTLV, len(peerUp.Information))
	copy(s.tableInfoTLVs, peerUp.Information)
	return s
}

// mergeLocRIB returns the state of a Loc-RIB instance conveyed by more than
// one emulated peer, each with its own Peer Up for some address families
// (RFC 9069 §6.1.1): the capabilities of both, and their Information TLVs
// as an ordered set (RFC 9069 §5.2.1).
func mergeLocRIB(old, s sessionState) sessionState {
	union := func(a, b map[int]uint8) map[int]uint8 {
		m := make(map[int]uint8, len(a)+len(b))
		for t, v := range a {
			m[t] |= v
		}
		for t, v := range b {
			m[t] |= v
		}
		return m
	}
	s.addPathSent = union(old.addPathSent, s.addPathSent)
	s.addPathRecv = union(old.addPathRecv, s.addPathRecv)
	multiLabel := make(map[int]bool, len(old.multiLabel)+len(s.multiLabel))
	for _, m := range []map[int]bool{old.multiLabel, s.multiLabel} {
		for t := range m {
			multiLabel[t] = true
		}
	}
	s.multiLabel = multiLabel
	tlvs := append([]bmp.InformationalTLV(nil), old.tableInfoTLVs...)
	for _, tlv := range s.tableInfoTLVs {
		dup := false
		for _, o := range tlvs {
			if o.InformationType == tlv.InformationType && bytes.Equal(o.Information, tlv.Information) {
				dup = true
				break
			}
		}
		if !dup {
			tlvs = append(tlvs, tlv)
		}
	}
	s.tableInfoTLVs = tlvs
	s.peerUps = old.peerUps + s.peerUps
	return s
}

// pathIDs returns whether NLRI of type nlriType in a Route Monitoring message
// with per-peer header ph carry ADD-PATH Path Identifiers. They do on routes
// from a speaker that advertised Send to one that advertised Receive (RFC
// 7911 §5): an Adj-RIB-In holds routes from the peer to the monitored router,
// an Adj-RIB-Out (O flag, RFC 8671 §4) routes from the router to the peer.
// For a Loc-RIB the capability's presence is enough (RFC 9069 §5.2).
//
// The encoding is fixed for pre-policy Adj-RIB-In, as received (RFC 7854
// §2, RFC 7911 §5), post-policy Adj-RIB-Out, as sent (RFC 8671 §5.1), and
// Loc-RIB (RFC 9069 §5.2). No RFC fixes it for post-policy Adj-RIB-In or
// pre-policy Adj-RIB-Out, which therefore get an expected state only.
func (s sessionState) pathIDs(ph *bmp.PerPeerHeader, nlriType int) base.PathIDState {
	router, peer := s.addPathSent[nlriType], s.addPathRecv[nlriType]
	var present bool
	if ph.PeerType == bmp.PeerType3 {
		present = router != 0 || peer != 0
	} else if out, _ := ph.IsAdjRIBOut(); out {
		present = router&addPathSend != 0 && peer&addPathReceive != 0
	} else {
		present = peer&addPathSend != 0 && router&addPathReceive != 0
	}
	post, _ := ph.IsPostPolicy()
	out, _ := ph.IsAdjRIBOut()
	if ph.PeerType != bmp.PeerType3 && post != out {
		if present {
			return base.PathIDExpectPresent
		}
		return base.PathIDExpectAbsent
	}
	if present {
		return base.PathIDPresent
	}
	return base.PathIDAbsent
}

// Config holds producer configuration options
type Config struct {
	// AdminID is the collector identifier for RAW messages
	// Used to generate collector hash for OpenBMP compatibility
	AdminID string
}

// Producer defines methods to act as a message producer
type Producer interface {
	Producer(queue chan bmp.Message, stop chan struct{})
	SetConfig(config *Config) error
}

type producer struct {
	publisher pub.Publisher

	// speakerReady is closed once the first valid PeerUp has established the
	// initial identity cache. RouteMonitor and StatsReport workers wait on it so
	// active-mode initial routes do not race ahead of their PeerUp identity.
	speakerReady     chan struct{}
	speakerReadyOnce sync.Once
	// stopCh is set to the stop channel passed to Producer() before the dispatch
	// loop starts.  producingWorker goroutines select on it alongside speakerReady
	// so they can exit cleanly if the producer is shut down before any PeerUp
	// arrives (e.g. the connection drops before BGP session establishment).
	stopCh chan struct{}
	// sessions holds the state of each monitored session, keyed by
	// bmp.PerPeerHeader.SessionKey, from its Peer Up to its Peer Down.
	sessionLock sync.RWMutex
	sessions    map[string]sessionState
	// pathIDWarned holds when a Path ID flip was last logged per session
	// and AFI/SAFI, to rate limit the warning.
	pathIDWarnLock sync.Mutex
	pathIDWarned   map[string]time.Time
	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// collectorAdminID is the collector identifier string for OpenBMP binary header
	collectorAdminID string
	// adminHash is the MD5 hash of the admin ID for RAW messages
	adminHash    string
	identityLock sync.RWMutex
	identities   map[string]bmp.PeerIdentity
	speakerID    bmp.PeerIdentity
}

// Producer dispatches kafka workers upon request received from the channel
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	// Store stop before spawning any goroutine.  The Go memory model guarantees
	// that all goroutines created inside the loop below observe this write.
	p.stopCh = stop
	for {
		select {
		case msg := <-queue:
			switch msg.Payload.(type) {
			case *bmp.PeerUpMessage, *bmp.PeerDownMessage:
				// State changes update identity cache and publish in input order.
				p.producingWorker(msg)
			default:
				// Other message types carry an identity and session state
				// snapshot and can fan out.
				p.attachIdentitySnapshot(&msg)
				p.attachSessionSnapshot(&msg)
				go p.producingWorker(msg)
			}
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
	}
}

// attachSessionSnapshot attaches the current state of the message's session
// to its per-peer header, which attachIdentitySnapshot has made a copy of.
func (p *producer) attachSessionSnapshot(msg *bmp.Message) {
	if msg == nil || msg.PeerHeader == nil {
		return
	}
	s, ok := p.session(msg.PeerHeader)
	msg.PeerHeader.Session = &sessionSnapshot{s: s, ok: ok}
}

func (p *producer) attachIdentitySnapshot(msg *bmp.Message) {
	if msg == nil || msg.PeerHeader == nil {
		return
	}

	var peer bmp.PeerIdentity
	var peerExists bool
	peerKey := msg.PeerHeader.PeerIdentity()
	if peerKey != "" {
		p.identityLock.RLock()
		peer, peerExists = p.identities[peerKey]
		p.identityLock.RUnlock()
	}
	if !peerExists {
		peer = p.identityFromHeaderFallback(*msg)
	}
	ph := *msg.PeerHeader
	ph.Identity = peer
	msg.PeerHeader = &ph
}

func (p *producer) identityFromHeaderFallback(msg bmp.Message) bmp.PeerIdentity {
	peer := bmp.IdentityFromPeerHeader(msg)

	p.identityLock.RLock()
	speakerID := p.speakerID
	p.identityLock.RUnlock()

	if speakerID.RouterIP == "" && speakerID.RouterHash == "" {
		return peer
	}

	peer.SpeakerIP = speakerID.SpeakerIP
	peer.SpeakerHash = speakerID.SpeakerHash
	peer.RouterIP = speakerID.RouterIP
	peer.RouterHash = speakerID.RouterHash
	return peer
}

func (p *producer) producingWorker(msg bmp.Message) {
	switch obj := msg.Payload.(type) {
	case *bmp.PeerUpMessage:
		var peer bmp.PeerIdentity
		var peerExists bool
		if msg.PeerHeader != nil {
			peerID := msg.PeerHeader.PeerIdentity()
			peer = bmp.IdentityFromPeerUp(msg)
			if peerID != "" {
				p.identityLock.Lock()
				if p.identities == nil {
					p.identities = make(map[string]bmp.PeerIdentity)
				}
				cachedPeer, ok := p.identities[peerID]
				peerExists = ok
				if !peerExists {
					p.identities[peerID] = peer
					glog.V(5).Infof("New peer identity stored for peer %s: %s", peerID, peer)
				} else if !cachedPeer.IsEqual(peer) {
					glog.Warningf("Peer identity changed for peer %s: old=%s, new=%s", peerID, cachedPeer, peer)
					p.identities[peerID] = peer
				} else {
					glog.V(5).Infof("Duplicate PeerUP message for peer %s: %s", peerID, peer)
				}
				if p.speakerID.RouterIP == "" || !isSpecificAddress(p.speakerID.RouterIP) {
					p.speakerID = peer
				}
				p.identityLock.Unlock()
			}
		}
		if m, err := p.producePeerMessage(peerUP, msg, peer); err != nil {
			glog.Errorf("failed to produce peer message: %+v", err)
		} else {
			if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
				glog.Errorf("failed to process peer message with error: %+v", err)
			}
		}
	case *bmp.PeerDownMessage:
		var m *PeerStateChange
		var err error
		if msg.PeerHeader == nil {
			glog.Errorf("perPeerHeader is missing, cannot construct PeerStateChange message")
			return
		}
		var peer bmp.PeerIdentity
		var peerExists bool
		peerID := msg.PeerHeader.PeerIdentity()
		if peerID != "" {
			p.identityLock.RLock()
			peer, peerExists = p.identities[peerID]
			p.identityLock.RUnlock()
		}

		if !peerExists {
			peer = p.identityFromHeaderFallback(msg)
		}
		if m, err = p.producePeerMessage(peerDown, msg, peer); err != nil {
			glog.Errorf("failed to produce peer message: %+v", err)
			return
		}
		// Remove the peer identity from the cache if it exists, since the peer is now down
		if peerExists {
			p.identityLock.Lock()
			delete(p.identities, peerID)
			p.identityLock.Unlock()
		}
		// Publish using the identity snapshot captured before cache removal.
		if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
			glog.Errorf("failed to process peer message with error: %+v", err)
		}
	case *bmp.RouteMonitor:
		// Wait for the first identity before processing initial route messages.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
			return
		}
		p.attachIdentitySnapshot(&msg)
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		// Same cancellable wait as RouteMonitor above.
		select {
		case <-p.speakerReady:
		case <-p.stopCh:
			return
		}
		p.attachIdentitySnapshot(&msg)
		p.produceStatsMessage(msg)
	case *bmp.RawMessage:
		p.produceRawMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to the producer, ignoring it...", obj)
	}
}

// SetConfig configures the producer with the given configuration
// Must be called before starting the producer if RAW message support is needed
func (p *producer) SetConfig(config *Config) error {
	if config == nil {
		return nil
	}

	if config.AdminID != "" {
		// Store collector admin ID for OpenBMP binary header
		p.collectorAdminID = config.AdminID
		// Generate MD5 hash of admin ID for OpenBMP collector hash
		hash := md5.Sum([]byte(config.AdminID))
		p.adminHash = hex.EncodeToString(hash[:])
	}

	return nil
}

// storeSession records the state set up by the Peer Up with header ph,
// replacing that of an earlier Peer Up for the session, or for a Loc-RIB
// adding to it (RFC 9069 §6.1.1).
func (p *producer) storeSession(ph *bmp.PerPeerHeader, s sessionState) {
	key := ph.SessionKey()
	s.peerUps = 1
	p.sessionLock.Lock()
	defer p.sessionLock.Unlock()
	if old, ok := p.sessions[key]; ok && ph.PeerType == bmp.PeerType3 {
		s = mergeLocRIB(old, s)
	}
	p.sessions[key] = s
}

// deleteSession removes the state of the session that the Peer Down with
// header ph ends. The emulated peers of a Loc-RIB share the header, and a
// Peer Down carries no OPEN to tell which one it ends (RFC 9069 §5.3,
// §6.1.1), so a Loc-RIB's state is kept, capabilities of all, until the Peer
// Down of the last one.
func (p *producer) deleteSession(ph *bmp.PerPeerHeader) {
	key := ph.SessionKey()
	deleted := func() bool {
		p.sessionLock.Lock()
		defer p.sessionLock.Unlock()
		if s, ok := p.sessions[key]; ok && s.peerUps > 1 {
			s.peerUps--
			p.sessions[key] = s
			return false
		}
		delete(p.sessions, key)
		return true
	}()
	if !deleted {
		return
	}
	p.pathIDWarnLock.Lock()
	defer p.pathIDWarnLock.Unlock()
	for k := range p.pathIDWarned {
		if strings.HasPrefix(k, key+"/") {
			delete(p.pathIDWarned, k)
		}
	}
}

// session returns the state of the session a message with header ph belongs
// to, and false if no Peer Up was seen for it: the snapshot attached when the
// message was dispatched, if any, else the current state.
func (p *producer) session(ph *bmp.PerPeerHeader) (sessionState, bool) {
	if snap, ok := ph.Session.(*sessionSnapshot); ok {
		return snap.s, snap.ok
	}
	key := ph.SessionKey()
	p.sessionLock.RLock()
	defer p.sessionLock.RUnlock()
	s, ok := p.sessions[key]
	return s, ok
}

// nlriState returns the ADD-PATH and Multiple Labels Capability state of NLRI
// type nlriType in a Route Monitoring message with header ph, both unknown if
// no Peer Up was seen for the session.
func (p *producer) nlriState(ph *bmp.PerPeerHeader, nlriType int) (base.PathIDState, base.MultiLabel) {
	s, ok := p.session(ph)
	if !ok {
		return base.PathIDUnknown, base.MultiLabelUnknown
	}
	ml := base.MultiLabelAbsent
	if s.multiLabel[nlriType] {
		ml = base.MultiLabelConfirmed
	}
	return s.pathIDs(ph, nlriType), ml
}

// pathIDWarnInterval is the least time between two warnings about Path ID
// flips for one session and AFI/SAFI.
const pathIDWarnInterval = time.Minute

// nlriContext describes where NLRI of AFI afi SAFI safi in a message with
// header ph come from, for logs.
func nlriContext(ph *bmp.PerPeerHeader, afi uint16, safi uint8) string {
	view := "Loc-RIB"
	peer := "BGP ID " + ph.GetPeerBGPIDString()
	if ph.PeerType != bmp.PeerType3 {
		view = "Adj-RIB-In"
		if out, _ := ph.IsAdjRIBOut(); out {
			view = "Adj-RIB-Out"
		}
		if post, _ := ph.IsPostPolicy(); post {
			view += " post-policy"
		} else {
			view += " pre-policy"
		}
		peer = ph.GetPeerAddrString()
	}
	return fmt.Sprintf("router %s peer %s distinguisher %s %s AFI/SAFI %d/%d",
		ph.Identity.RouterIP, peer, ph.GetPeerDistinguisherString(), view, afi, safi)
}

// checkDecoded adds the session context to err, the error of decoding NLRI
// of AFI afi SAFI safi in a message with header ph, and warns, rate limited,
// when mp was read with the Path ID setting opposite to the expected one.
func (p *producer) checkDecoded(ph *bmp.PerPeerHeader, afi uint16, safi uint8, mp *base.MPNLRI, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", nlriContext(ph, afi, safi), err)
	}
	if mp == nil || !mp.PathIDsFlipped {
		return nil
	}
	key := fmt.Sprintf("%s/%d/%d", ph.SessionKey(), afi, safi)
	now := time.Now()
	warn := func() bool {
		p.pathIDWarnLock.Lock()
		defer p.pathIDWarnLock.Unlock()
		if last, ok := p.pathIDWarned[key]; ok && now.Sub(last) < pathIDWarnInterval {
			return false
		}
		if p.pathIDWarned == nil {
			p.pathIDWarned = make(map[string]time.Time)
		}
		p.pathIDWarned[key] = now
		return true
	}()
	if warn {
		glog.Warningf("%s: NLRI decoded with the ADD-PATH Path ID setting opposite to the negotiated one; further warnings for this session and AFI/SAFI suppressed for %s",
			nlriContext(ph, afi, safi), pathIDWarnInterval)
	}
	return nil
}

// GetTableName returns the VRF/Table Name of the Loc-RIB instance a message
// with header ph belongs to, from its Peer Up Information TLVs (RFC 9069
// §5.2.1), concatenated if there are several.
func (p *producer) GetTableName(ph *bmp.PerPeerHeader) string {
	s, _ := p.session(ph)
	tn := ""
	for _, tlv := range s.tableInfoTLVs {
		if tlv.InformationType == bmp.PeerUpTLVVRFTableName {
			tn += string(tlv.Information)
		}
	}
	return tn
}

// NewProducer instantiates a new instance of a producer with Publisher interface
func NewProducer(publisher pub.Publisher, splitAF bool) Producer {
	return &producer{
		publisher:    publisher,
		splitAF:      splitAF,
		sessions:     make(map[string]sessionState),
		speakerReady: make(chan struct{}),
		identities:   make(map[string]bmp.PeerIdentity),
	}
}
