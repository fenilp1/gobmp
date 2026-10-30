package message

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	// families holds the NLRI types the Peer Up OPENs list in their
	// Multiprotocol capabilities (RFC 4760 §8).
	families map[int]bool
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
		families:    peerUp.SentOpen.MultiprotocolFamilies(),
	}
	for t := range peerUp.ReceivedOpen.MultiprotocolFamilies() {
		s.families[t] = true
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
// one emulated peer, each with its own Peer Up whose OPEN lists its address
// families (RFC 9069 §6.1.1). The new Peer Up s sets the ADD-PATH and
// Multiple Labels state of the families it lists, so an emulated peer
// bounced with new capabilities (RFC 9069 §6.1.3) is not left with the old
// ones; the other families keep the union of both. The Information TLVs of
// both are kept as an ordered set (RFC 9069 §5.2.1).
func mergeLocRIB(old, s sessionState) sessionState {
	addPath := func(a, b map[int]uint8) map[int]uint8 {
		m := make(map[int]uint8, len(a)+len(b))
		for t, v := range a {
			if !s.families[t] {
				m[t] = v
			}
		}
		for t, v := range b {
			m[t] |= v
		}
		return m
	}
	s.addPathSent = addPath(old.addPathSent, s.addPathSent)
	s.addPathRecv = addPath(old.addPathRecv, s.addPathRecv)
	multiLabel := make(map[int]bool, len(old.multiLabel)+len(s.multiLabel))
	for t := range old.multiLabel {
		if !s.families[t] {
			multiLabel[t] = true
		}
	}
	for t := range s.multiLabel {
		multiLabel[t] = true
	}
	s.multiLabel = multiLabel
	families := make(map[int]bool, len(old.families)+len(s.families))
	for _, m := range []map[int]bool{old.families, s.families} {
		for t := range m {
			families[t] = true
		}
	}
	s.families = families
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

// producer publishes what the messages of one BMP connection produce.
//
// Jobs run on shallow copies of the producer (see runJob), so every field
// but producerState must not change once Producer starts: SetConfig is
// called before, and all mutable state lives in producerState.
type producer struct {
	publisher pub.Publisher

	// If splitAF is set to true, ipv4 and ipv6 messages will go into separate topics
	splitAF bool
	// collectorAdminID is the collector identifier string for OpenBMP binary header
	collectorAdminID string
	// adminHash is the MD5 hash of the admin ID for RAW messages
	adminHash string

	// producerState is the state the producer's jobs share. It is held by
	// pointer so that a job can run on a shallow copy of the producer with
	// its own publisher (see runJob).
	*producerState
}

// producerState holds the mutable state of a producer, shared by all copies
// of it.
type producerState struct {
	// sessions holds the state of each monitored session, keyed by
	// bmp.PerPeerHeader.SessionKey, from its Peer Up to its Peer Down.
	sessionLock sync.RWMutex
	sessions    map[string]sessionState
	// pathIDWarned holds when a Path ID flip was last logged per session
	// and AFI/SAFI, to rate limit the warning.
	pathIDWarnLock sync.Mutex
	pathIDWarned   map[string]time.Time
	identityLock   sync.RWMutex
	identities     map[string]bmp.PeerIdentity
	speakerID      bmp.PeerIdentity
	// panicked is set once a job's panic was logged with its stack.
	panicked atomic.Bool
}

func newProducerState() *producerState {
	return &producerState{
		sessions:   make(map[string]sessionState),
		identities: make(map[string]bmp.PeerIdentity),
	}
}

// state returns the producer's shared state, setting it up for a producer
// not made by NewProducer, such as a test's &producer{} literal. The first
// call must come before the producer is shared between goroutines, as the
// set up is not synchronized; Producer makes it before starting any.
func (p *producer) state() *producerState {
	if p.producerState == nil {
		p.producerState = newProducerState()
	}
	return p.producerState
}

// Producer reads the messages of one BMP connection from queue and publishes
// what they produce in the order they arrive. Peer Up and Peer Down messages,
// which change the state later messages are decoded with, are processed as
// they are read; the other messages are decoded concurrently, at most window
// at a time, with the state attached as they are read. When window messages
// wait to be published, Producer stops reading queue, which in turn holds up
// the parser and the BMP connection.
//
// A Route Monitoring or Stats message read before any Peer Up of the
// connection, which RFC 7854 §3.3 does not allow but a Peer Up the parser
// dropped causes, is published at once with the router identity of the TCP
// source (identityFromHeaderFallback). Earlier versions held such messages
// until the first Peer Up and gave them its router identity, so their
// router_hash differs now. Holding them leaked their goroutines for ever
// when no Peer Up came, and with publishing in arrival order it would stall
// the whole connection behind them.
//
// Once queue is closed, Producer publishes all it has read and returns. Once
// stop is closed, it stops reading and dispatching and drops what waits to
// be published, but it still waits for the jobs in progress and for a
// PublishMessage call in progress to return, which a stuck publisher may
// never do. The server always drains, by closing queue, rather than closing
// stop, so a stuck publisher is bounded only by the shutdown deadline in
// main.
func (p *producer) Producer(queue chan bmp.Message, stop chan struct{}) {
	p.state()
	slots := make(chan *slot, window)
	outDone := make(chan struct{})
	go func() {
		defer close(outDone)
		p.output(slots, stop)
	}()
	var jobs sync.WaitGroup
	defer func() {
		close(slots)
		jobs.Wait()
		<-outDone
	}()
	for {
		var msg bmp.Message
		var ok bool
		select {
		case msg, ok = <-queue:
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
		if !ok {
			return
		}
		s := newSlot()
		select {
		case slots <- s:
		case <-stop:
			glog.Infof("received interrupt, stopping.")
			return
		}
		switch msg.Payload.(type) {
		case *bmp.PeerUpMessage, *bmp.PeerDownMessage:
			// State changes update the identity and session state before
			// the next message is read.
			p.runJob(s, msg)
		default:
			// Other message types carry an identity and session state
			// snapshot and are decoded concurrently.
			p.snapshot(&msg)
			jobs.Add(1)
			go func() {
				defer jobs.Done()
				p.runJob(s, msg)
			}()
		}
	}
}

// snapshot attaches the current identity and session state to the per-peer
// header of msg, which it makes a copy of.
func (p *producer) snapshot(msg *bmp.Message) {
	p.attachIdentitySnapshot(msg)
	p.attachSessionSnapshot(msg)
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
		st := p.state()
		st.identityLock.RLock()
		peer, peerExists = st.identities[peerKey]
		st.identityLock.RUnlock()
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

	st := p.state()
	st.identityLock.RLock()
	speakerID := st.speakerID
	st.identityLock.RUnlock()

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
				st := p.state()
				// Unlock in a defer: a panic is recovered (see runJob), and
				// a lock left held would block the connection for ever.
				func() {
					st.identityLock.Lock()
					defer st.identityLock.Unlock()
					cachedPeer, ok := st.identities[peerID]
					peerExists = ok
					if !peerExists {
						st.identities[peerID] = peer
						glog.V(5).Infof("New peer identity stored for peer %s: %s", peerID, peer)
					} else if !cachedPeer.IsEqual(peer) {
						glog.Warningf("Peer identity changed for peer %s: old=%s, new=%s", peerID, cachedPeer, peer)
						st.identities[peerID] = peer
					} else {
						glog.V(5).Infof("Duplicate PeerUP message for peer %s: %s", peerID, peer)
					}
					if st.speakerID.RouterIP == "" || !isSpecificAddress(st.speakerID.RouterIP) {
						st.speakerID = peer
					}
				}()
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
		st := p.state()
		peerID := msg.PeerHeader.PeerIdentity()
		if peerID != "" {
			st.identityLock.RLock()
			peer, peerExists = st.identities[peerID]
			st.identityLock.RUnlock()
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
			st.identityLock.Lock()
			delete(st.identities, peerID)
			st.identityLock.Unlock()
		}
		// Publish using the identity snapshot captured before cache removal.
		if err := p.marshalAndPublish(m, bmp.PeerStateChangeMsg, []byte(m.RouterHash)); err != nil {
			glog.Errorf("failed to process peer message with error: %+v", err)
		}
	case *bmp.RouteMonitor:
		p.snapshotOnce(&msg)
		p.produceRouteMonitorMessage(msg)
	case *bmp.StatsReport:
		p.snapshotOnce(&msg)
		p.produceStatsMessage(msg)
	case *bmp.RawMessage:
		p.produceRawMessage(msg)
	default:
		glog.Warningf("got Unknown message %T to push to the producer, ignoring it...", obj)
	}
}

// snapshotOnce attaches the current identity and session state to msg unless
// Producer did as it read it.
func (p *producer) snapshotOnce(msg *bmp.Message) {
	if msg.PeerHeader != nil && msg.PeerHeader.Session == nil {
		p.snapshot(msg)
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
	st := p.state()
	st.sessionLock.Lock()
	defer st.sessionLock.Unlock()
	if old, ok := st.sessions[key]; ok && ph.PeerType == bmp.PeerType3 {
		s = mergeLocRIB(old, s)
	}
	st.sessions[key] = s
}

// deleteSession removes the state of the session that the Peer Down with
// header ph ends. The emulated peers of a Loc-RIB share the header, and a
// Peer Down carries no OPEN to tell which one it ends (RFC 9069 §5.3,
// §6.1.1), so a Loc-RIB's state is kept, capabilities of all, until the Peer
// Down of the last one.
func (p *producer) deleteSession(ph *bmp.PerPeerHeader) {
	key := ph.SessionKey()
	st := p.state()
	deleted := func() bool {
		st.sessionLock.Lock()
		defer st.sessionLock.Unlock()
		if s, ok := st.sessions[key]; ok && s.peerUps > 1 {
			s.peerUps--
			st.sessions[key] = s
			return false
		}
		delete(st.sessions, key)
		return true
	}()
	if !deleted {
		return
	}
	st.pathIDWarnLock.Lock()
	defer st.pathIDWarnLock.Unlock()
	for k := range st.pathIDWarned {
		if strings.HasPrefix(k, key+"/") {
			delete(st.pathIDWarned, k)
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
	st := p.state()
	st.sessionLock.RLock()
	defer st.sessionLock.RUnlock()
	s, ok := st.sessions[key]
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
	st := p.state()
	warn := func() bool {
		st.pathIDWarnLock.Lock()
		defer st.pathIDWarnLock.Unlock()
		if last, ok := st.pathIDWarned[key]; ok && now.Sub(last) < pathIDWarnInterval {
			return false
		}
		if st.pathIDWarned == nil {
			st.pathIDWarned = make(map[string]time.Time)
		}
		st.pathIDWarned[key] = now
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
		publisher:     publisher,
		splitAF:       splitAF,
		producerState: newProducerState(),
	}
}
