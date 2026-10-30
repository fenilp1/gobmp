package nats

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/pub"
)

// Define constants for each topic name
const (
	peerTopic              = "gobmp.parsed.peer"
	unicastMessageTopic    = "gobmp.parsed.unicast_prefix"
	unicastMessageV4Topic  = "gobmp.parsed.unicast_prefix_v4"
	unicastMessageV6Topic  = "gobmp.parsed.unicast_prefix_v6"
	lsNodeMessageTopic     = "gobmp.parsed.ls_node"
	lsLinkMessageTopic     = "gobmp.parsed.ls_link"
	l3vpnMessageTopic      = "gobmp.parsed.l3vpn"
	l3vpnMessageV4Topic    = "gobmp.parsed.l3vpn_v4"
	l3vpnMessageV6Topic    = "gobmp.parsed.l3vpn_v6"
	lsPrefixMessageTopic   = "gobmp.parsed.ls_prefix"
	lsSRv6SIDMessageTopic  = "gobmp.parsed.ls_srv6_sid"
	lsOpaqueMessageTopic   = "gobmp.parsed.ls_opaque"
	evpnMessageTopic       = "gobmp.parsed.evpn"
	srPolicyMessageTopic   = "gobmp.parsed.sr_policy"
	srPolicyMessageV4Topic = "gobmp.parsed.sr_policy_v4"
	srPolicyMessageV6Topic = "gobmp.parsed.sr_policy_v6"
	flowspecMessageTopic   = "gobmp.parsed.flowspec"
	flowspecMessageV4Topic = "gobmp.parsed.flowspec_v4"
	flowspecMessageV6Topic = "gobmp.parsed.flowspec_v6"
	vplsMessageTopic       = "gobmp.parsed.vpls"
	mupMessageTopic        = "gobmp.parsed.mup"
	mupMessageV4Topic      = "gobmp.parsed.mup_v4"
	mupMessageV6Topic      = "gobmp.parsed.mup_v6"
	bgpCTMessageTopic      = "gobmp.parsed.bgp_ct"
	bgpCTMessageV4Topic    = "gobmp.parsed.bgp_ct_v4"
	bgpCTMessageV6Topic    = "gobmp.parsed.bgp_ct_v6"
	statsMessageTopic      = "gobmp.parsed.statistics"
	rawMessageTopic        = "gobmp.raw"
	parsedWildcardSubject  = "gobmp.parsed.*"
)

var (
	natsTimeout   = time.Second
	waitReconnect = time.Second
	// maxPendingAcks bounds the publishes awaiting their JetStream
	// acknowledgement; at the bound a publish waits for one.
	maxPendingAcks = 4096
	// ackTimeout is how long a publish waits for its acknowledgement before
	// it is reported failed.
	ackTimeout = 30 * time.Second
	// stopTimeout bounds how long Stop waits for outstanding
	// acknowledgements.
	stopTimeout = 10 * time.Second
)

// errStopped is returned by a publish after Stop.
var errStopped = errors.New("nats publisher is stopped")

// jetStreamClient is the subset of nats.JetStreamContext used by publisher.
// Defining a narrow interface lets tests inject a fake without a full NATS server.
type jetStreamClient interface {
	PublishMsgAsync(m *nats.Msg, opts ...nats.PubOpt) (nats.PubAckFuture, error)
	PublishAsyncComplete() <-chan struct{}
	PublishAsyncPending() int
	AddStream(cfg *nats.StreamConfig, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	StreamInfo(stream string, opts ...nats.JSOpt) (*nats.StreamInfo, error)
	UpdateStream(cfg *nats.StreamConfig, opts ...nats.JSOpt) (*nats.StreamInfo, error)
}

type publisher struct {
	nc *nats.Conn
	js jetStreamClient
	// stopCh is closed as Stop begins: a publish waiting for an
	// acknowledgement slot then returns errStopped, its message dropped,
	// once its current stalled attempt (up to 200 ms in nats.go) ends, so
	// that Stop can take mu. The server stops publishing before it calls
	// Stop, so this only matters for a publish racing Stop.
	stopCh chan struct{}
	// mu is held shared by a publish and exclusively by Stop to set
	// stopped, so that Stop waits only for acknowledgements of publishes
	// that have returned.
	mu       sync.RWMutex
	stopped  bool
	stopOnce sync.Once
}

func newPublisher(nc *nats.Conn, js jetStreamClient) *publisher {
	return &publisher{nc: nc, js: js, stopCh: make(chan struct{})}
}

// errorLog logs failed publishes at most once a second, as a server outage
// fails every outstanding one at once.
type errorLog struct {
	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (l *errorLog) log(m *nats.Msg, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.last) >= time.Second {
		glog.Errorf("NATS JetStream publish to %s failed: %v (%d more failures not logged)", m.Subject, err, l.suppressed)
		l.last, l.suppressed = now, 0
		return
	}
	l.suppressed++
}

// topicForMessage maps a BMP message type to its NATS subject.
// Returns ("", false) for unknown types.
func topicForMessage(t int) (string, bool) {
	switch t {
	case bmp.PeerStateChangeMsg:
		return peerTopic, true
	case bmp.UnicastPrefixMsg:
		return unicastMessageTopic, true
	case bmp.UnicastPrefixV4Msg:
		return unicastMessageV4Topic, true
	case bmp.UnicastPrefixV6Msg:
		return unicastMessageV6Topic, true
	case bmp.LSNodeMsg:
		return lsNodeMessageTopic, true
	case bmp.LSLinkMsg:
		return lsLinkMessageTopic, true
	case bmp.L3VPNMsg:
		return l3vpnMessageTopic, true
	case bmp.L3VPNV4Msg:
		return l3vpnMessageV4Topic, true
	case bmp.L3VPNV6Msg:
		return l3vpnMessageV6Topic, true
	case bmp.LSPrefixMsg:
		return lsPrefixMessageTopic, true
	case bmp.LSSRv6SIDMsg:
		return lsSRv6SIDMessageTopic, true
	case bmp.LSOpaqueMsg:
		return lsOpaqueMessageTopic, true
	case bmp.EVPNMsg:
		return evpnMessageTopic, true
	case bmp.SRPolicyMsg:
		return srPolicyMessageTopic, true
	case bmp.SRPolicyV4Msg:
		return srPolicyMessageV4Topic, true
	case bmp.SRPolicyV6Msg:
		return srPolicyMessageV6Topic, true
	case bmp.FlowspecMsg:
		return flowspecMessageTopic, true
	case bmp.FlowspecV4Msg:
		return flowspecMessageV4Topic, true
	case bmp.FlowspecV6Msg:
		return flowspecMessageV6Topic, true
	case bmp.VPLSMsg:
		return vplsMessageTopic, true
	case bmp.MUPMsg:
		return mupMessageTopic, true
	case bmp.MUPV4Msg:
		return mupMessageV4Topic, true
	case bmp.MUPV6Msg:
		return mupMessageV6Topic, true
	case bmp.ClassfulTransportMsg:
		return bgpCTMessageTopic, true
	case bmp.ClassfulTransportV4Msg:
		return bgpCTMessageV4Topic, true
	case bmp.ClassfulTransportV6Msg:
		return bgpCTMessageV6Topic, true
	case bmp.StatsReportMsg:
		return statsMessageTopic, true
	case bmp.BMPRawMsg:
		return rawMessageTopic, true
	}
	return "", false
}

func (p *publisher) PublishMessage(t int, key []byte, msg []byte) error {
	topic, ok := topicForMessage(t)
	if !ok {
		return fmt.Errorf("nats publisher: unsupported BMP message type %d", t)
	}
	return p.produceMessage(topic, key, msg)
}

func (p *publisher) produceMessage(subject string, key []byte, data []byte) error {
	// use the header to pass the hash key
	header := nats.Header{}
	header.Set("Hash", string(key))

	msg := &nats.Msg{
		Subject: subject,
		Header:  header,
		Data:    data,
	}

	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.stopped {
		return errStopped
	}
	// Publishing asynchronously keeps the order of the publishes; the
	// acknowledgements arrive later, failures go to the error handler.
	for {
		_, err := p.js.PublishMsgAsync(msg)
		if !errors.Is(err, nats.ErrTooManyStalledMsgs) {
			return err
		}
		// maxPendingAcks publishes await acknowledgement: keep waiting,
		// which holds up the BMP connection being published.
		select {
		case <-p.stopCh:
			return errStopped
		default:
		}
	}
}

// Stop waits up to stopTimeout for the acknowledgements of the messages
// published before, then closes the connection. Publishing after Stop
// returns an error. Stop may be called more than once.
func (p *publisher) Stop() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.mu.Lock()
		p.stopped = true
		p.mu.Unlock()
		if p.js != nil {
			t := time.NewTimer(stopTimeout)
			select {
			case <-p.js.PublishAsyncComplete():
			case <-t.C:
				glog.Errorf("NATS publisher stopping with %d JetStream acknowledgements outstanding after %s", p.js.PublishAsyncPending(), stopTimeout)
			}
			t.Stop()
		}
		if p.nc != nil {
			p.nc.Close()
		}
	})
}

// mergeSubjects returns a new slice containing all elements of existing plus
// any elements from required that are not already present, and a bool
// indicating whether any subjects were added. existing is not modified.
func mergeSubjects(existing, required []string) ([]string, bool) {
	set := make(map[string]struct{}, len(existing))
	for _, s := range existing {
		set[s] = struct{}{}
	}
	result := append([]string(nil), existing...)
	changed := false
	for _, s := range required {
		if _, ok := set[s]; !ok {
			result = append(result, s)
			set[s] = struct{}{}
			changed = true
		}
	}
	return result, changed
}

func (p *publisher) createStreams() error {
	// Define the stream configuration
	streamConfig := &nats.StreamConfig{
		Name:      "goBMP",
		Subjects:  []string{parsedWildcardSubject, rawMessageTopic},
		Storage:   nats.FileStorage,
		Retention: nats.InterestPolicy,
		MaxMsgs:   -1, // No limit
		MaxBytes:  -1, // No limit
		MaxAge:    15 * time.Minute,
		Replicas:  1,
	}

	_, err := p.js.AddStream(streamConfig)
	if errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		info, infoErr := p.js.StreamInfo(streamConfig.Name)
		if infoErr != nil {
			return fmt.Errorf("failed to get stream info for %q: %w", streamConfig.Name, infoErr)
		}
		existingConfig := info.Config
		merged, updated := mergeSubjects(existingConfig.Subjects, streamConfig.Subjects)
		if updated {
			existingConfig.Subjects = merged
			if _, err = p.js.UpdateStream(&existingConfig); err != nil {
				return fmt.Errorf("failed to update stream subjects for %q: %w", streamConfig.Name, err)
			}
		}
	} else if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	return nil
}

// NewPublisher instantiates a new instance of a NATS publisher
func NewPublisher(natsSrv string) (pub.Publisher, error) {
	glog.Infof("Initializing NATS producer client")

	opts := []nats.Option{
		nats.Name("gobmp-producer"),
		// Keep reconnecting however long the server is away: a closed
		// connection would fail every publish while gobmp keeps running.
		nats.MaxReconnects(-1),
		nats.ReconnectWait(waitReconnect),
		nats.Timeout(natsTimeout),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				glog.Warningf("NATS connection lost: %v, reconnecting", err)
			}
		}),
		nats.ReconnectHandler(func(nc *nats.Conn) {
			glog.Infof("NATS connection reestablished to %s", nc.ConnectedUrlRedacted())
		}),
		nats.ClosedHandler(func(*nats.Conn) {
			glog.Infof("NATS connection closed")
		}),
	}

	nc, err := nats.Connect(natsSrv, opts...)
	if err != nil {
		return nil, err
	}

	// Create a JetStream context
	errs := &errorLog{}
	js, err := nc.JetStream(
		nats.PublishAsyncMaxPending(maxPendingAcks),
		nats.PublishAsyncTimeout(ackTimeout),
		nats.PublishAsyncErrHandler(func(_ nats.JetStream, m *nats.Msg, err error) {
			errs.log(m, err)
		}),
	)
	if err != nil {
		nc.Close()
		return nil, err
	}

	p := newPublisher(nc, js)

	// Create the streams
	if err := p.createStreams(); err != nil {
		nc.Close()
		return nil, err
	}

	return p, nil
}
