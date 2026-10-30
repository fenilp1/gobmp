package message

import (
	"bytes"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// setWindow sets window to n for the test.
func setWindow(t *testing.T, n int) {
	t.Helper()
	old := window
	window = n
	t.Cleanup(func() { window = old })
}

// goroutineBaseline returns a function that fails t unless the number of
// goroutines falls back to what it is now.
func goroutineBaseline(t *testing.T) func() {
	t.Helper()
	base := runtime.NumGoroutine()
	return func() {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for runtime.NumGoroutine() > base {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				t.Fatalf("%d goroutines, want at most %d:\n%s", runtime.NumGoroutine(), base, buf[:runtime.Stack(buf, true)])
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// pipelineStream returns a Peer Up, Route Monitoring messages of very
// different decode cost, and a Peer Down, for one peer. Each group of four
// is a large update and an announce, withdraw and announce again of one
// prefix, so that an update published out of order changes the outcome.
func pipelineStream(t *testing.T, groups int) []bmp.Message {
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	msgs := []bmp.Message{pipelinePeerUp(ph)}
	rm := func(withdrawn, nlri []byte) bmp.Message {
		return bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{Update: pipelineUpdate(t, withdrawn, nlri)},
			SpeakerIP:  "10.2.1.3",
		}
	}
	for g := 0; g < groups; g++ {
		one := []byte{24, 172, 16, byte(g)} // 172.16.g.0/24
		msgs = append(msgs,
			rm(nil, pipelinePrefixes(1+g%8, 250)),
			rm(nil, one),
			rm(one, nil),
			rm(nil, one),
		)
	}
	return append(msgs, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}, SpeakerIP: "10.2.1.3"})
}

// sequential returns what msgs produce when each is processed before the
// next, the order Producer must publish in.
func sequential(msgs []bmp.Message) []recordedMsg {
	rec := &recordingPublisher{}
	p := NewProducer(rec, false).(*producer)
	for _, m := range msgs {
		p.producingWorker(m)
	}
	return rec.msgs
}

// runProducer feeds msgs through p.Producer, closes the queue and waits for
// Producer to return.
func runProducer(t *testing.T, p *producer, msgs []bmp.Message) {
	t.Helper()
	queue := make(chan bmp.Message)
	returned := make(chan struct{})
	go func() {
		p.Producer(queue, make(chan struct{}))
		close(returned)
	}()
	for _, m := range msgs {
		queue <- m
	}
	close(queue)
	select {
	case <-returned:
	case <-time.After(30 * time.Second):
		t.Fatal("Producer did not return after its queue was closed")
	}
}

func equalRecorded(t *testing.T, got, want []recordedMsg) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("published %d messages, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].msgType != want[i].msgType || !bytes.Equal(got[i].payload, want[i].payload) {
			t.Fatalf("message %d is type %d %.300s, want type %d %.300s", i, got[i].msgType, got[i].payload, want[i].msgType, want[i].payload)
		}
	}
}

// TestProducerPublishesInOrder checks that Producer publishes what the
// messages of a connection produce in the order they arrive, whatever their
// decode cost, and returns once all is published after its queue is closed.
func TestProducerPublishesInOrder(t *testing.T) {
	for _, w := range []int{1, 4, defaultWindow(), 16} {
		t.Run("", func(t *testing.T) {
			setWindow(t, w)
			check := goroutineBaseline(t)
			msgs := pipelineStream(t, 24)
			want := sequential(msgs)
			rec := &recordingPublisher{}
			runProducer(t, NewProducer(rec, false).(*producer), msgs)
			rec.mu.Lock()
			got := rec.msgs
			rec.mu.Unlock()
			equalRecorded(t, got, want)
			check()
		})
	}
}

// TestProducerPeerDownAfterRoutes checks that a Peer Down, processed as it
// is read, is published after the routes read before it.
func TestProducerPeerDownAfterRoutes(t *testing.T) {
	setWindow(t, 16)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	msgs := []bmp.Message{pipelinePeerUp(ph)}
	for i := 0; i < 8; i++ {
		msgs = append(msgs, bmp.Message{
			PeerHeader: ph,
			Payload:    &bmp.RouteMonitor{Update: pipelineUpdate(t, nil, pipelinePrefixes(i, 250))},
			SpeakerIP:  "10.2.1.3",
		})
	}
	msgs = append(msgs, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerDownMessage{Reason: 1}, SpeakerIP: "10.2.1.3"})
	rec := &recordingPublisher{}
	runProducer(t, NewProducer(rec, false).(*producer), msgs)

	if n := len(rec.msgs); n != 2+8*250 {
		t.Fatalf("published %d messages, want %d", n, 2+8*250)
	}
	for i, m := range rec.msgs {
		peer := m.msgType == bmp.PeerStateChangeMsg
		if (i == 0 || i == len(rec.msgs)-1) != peer {
			t.Fatalf("message %d is of type %d, want the Peer Up first and the Peer Down last", i, m.msgType)
		}
	}
	var down PeerStateChange
	if err := json.Unmarshal(rec.msgs[len(rec.msgs)-1].payload, &down); err != nil {
		t.Fatal(err)
	}
	if down.Action != "down" {
		t.Errorf("last message action %q, want down", down.Action)
	}
}

// TestProducerRouteAfterPeerUpGetsItsIdentity checks that a route read after
// a Peer Up is produced with the router identity of that Peer Up, which is
// not the connection address the route would fall back to.
func TestProducerRouteAfterPeerUpGetsItsIdentity(t *testing.T) {
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	rec := &recordingPublisher{}
	runProducer(t, NewProducer(rec, false).(*producer), []bmp.Message{
		pipelinePeerUp(ph),
		{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: pipelineUpdate(t, nil, pipelinePrefixes(1, 1))}, SpeakerIP: "10.2.1.3"},
	})
	if len(rec.msgs) != 2 {
		t.Fatalf("published %d messages, want 2", len(rec.msgs))
	}
	var up PeerStateChange
	var route UnicastPrefix
	if err := json.Unmarshal(rec.msgs[0].payload, &up); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(rec.msgs[1].payload, &route); err != nil {
		t.Fatal(err)
	}
	if up.RouterIP != "192.168.1.1" {
		t.Fatalf("Peer Up router %q, want its local address 192.168.1.1", up.RouterIP)
	}
	if route.RouterIP != up.RouterIP || route.RouterHash != up.RouterHash {
		t.Errorf("route router %q/%q, want the Peer Up's %q/%q", route.RouterIP, route.RouterHash, up.RouterIP, up.RouterHash)
	}
}

// gatePublisher records the messages published once gate is closed.
type gatePublisher struct {
	gate chan struct{}
	recordingPublisher
}

func (g *gatePublisher) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	<-g.gate
	return g.recordingPublisher.PublishMessage(msgType, msgHash, msg)
}

func statsMessage(ph *bmp.PerPeerHeader, v byte) bmp.Message {
	return bmp.Message{
		PeerHeader: ph,
		Payload: &bmp.StatsReport{StatsTLV: []bmp.InformationalTLV{
			{InformationType: 0, InformationLength: 4, Information: []byte{0, 0, 0, v}},
		}},
		SpeakerIP: "10.2.1.3",
	}
}

// TestProducerBackpressure checks that while the publisher blocks, Producer
// reads at most window messages, and a few in hand, from its queue.
func TestProducerBackpressure(t *testing.T) {
	setWindow(t, 4)
	check := goroutineBaseline(t)
	pub := &gatePublisher{gate: make(chan struct{})}
	p := NewProducer(pub, false).(*producer)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	const total = 100
	queue := make(chan bmp.Message)
	returned := make(chan struct{})
	go func() {
		p.Producer(queue, make(chan struct{}))
		close(returned)
	}()
	var sent atomic.Int64
	fed := make(chan struct{})
	go func() {
		defer close(fed)
		for i := 0; i < total; i++ {
			queue <- statsMessage(ph, byte(i))
			sent.Add(1)
		}
		close(queue)
	}()

	// Wait until the producer stops reading.
	last, stable := int64(-1), 0
	for stable < 20 {
		time.Sleep(10 * time.Millisecond)
		if n := sent.Load(); n == last {
			stable++
		} else {
			last, stable = n, 0
		}
	}
	// The output goroutine holds one message, the slots window more, and
	// the dispatcher one it cannot enqueue.
	if limit := int64(window + 2); last > limit {
		t.Errorf("producer read %d messages while its publisher blocked, want at most %d", last, limit)
	}
	if last < int64(window) {
		t.Errorf("producer read %d messages while its publisher blocked, want at least %d", last, window)
	}

	close(pub.gate)
	<-fed
	<-returned
	if len(pub.msgs) != total {
		t.Fatalf("published %d messages, want %d", len(pub.msgs), total)
	}
	for i, m := range pub.msgs {
		var s Stats
		if err := json.Unmarshal(m.payload, &s); err != nil {
			t.Fatal(err)
		}
		if s.PrefixesRejectedInbound != uint32(byte(i)) {
			t.Fatalf("message %d carries stat %d, want %d", i, s.PrefixesRejectedInbound, byte(i))
		}
	}
	check()
}

// TestProducerJobPanic checks that a message whose processing panics is
// dropped and the messages after it are still published, in order.
func TestProducerJobPanic(t *testing.T) {
	setWindow(t, 4)
	check := goroutineBaseline(t)
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	bad := *ph
	bad.PeerTimestamp = nil // GetPeerTimestamp panics on it
	var msgs []bmp.Message
	for i := 0; i < 30; i++ {
		if i%3 == 1 {
			msgs = append(msgs, statsMessage(&bad, byte(i)))
			continue
		}
		msgs = append(msgs, statsMessage(ph, byte(i)))
	}
	rec := &recordingPublisher{}
	runProducer(t, NewProducer(rec, false).(*producer), msgs)

	if len(rec.msgs) != 20 {
		t.Fatalf("published %d messages, want 20", len(rec.msgs))
	}
	i := 0
	for _, m := range rec.msgs {
		if i%3 == 1 {
			i++
		}
		var s Stats
		if err := json.Unmarshal(m.payload, &s); err != nil {
			t.Fatal(err)
		}
		if s.PrefixesRejectedInbound != uint32(i) {
			t.Fatalf("published stat %d, want %d", s.PrefixesRejectedInbound, i)
		}
		i++
	}
	check()
}

// slowPublisher records messages, taking delay over each.
type slowPublisher struct {
	delay time.Duration
	recordingPublisher
}

func (s *slowPublisher) PublishMessage(msgType int, msgHash []byte, msg []byte) error {
	time.Sleep(s.delay)
	return s.recordingPublisher.PublishMessage(msgType, msgHash, msg)
}

func (s *slowPublisher) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

// TestProducerDrain checks that once its queue is closed, Producer returns
// only after everything it read is published.
func TestProducerDrain(t *testing.T) {
	setWindow(t, 8)
	check := goroutineBaseline(t)
	msgs := pipelineStream(t, 2)
	want := sequential(msgs)
	pub := &slowPublisher{delay: 20 * time.Microsecond}
	runProducer(t, NewProducer(pub, false).(*producer), msgs)
	pub.mu.Lock()
	got := pub.msgs
	pub.mu.Unlock()
	equalRecorded(t, got, want)
	check()
}

// TestProducerAbort checks that once stop is closed, Producer returns
// promptly, publishes nothing more and leaves no goroutine behind.
func TestProducerAbort(t *testing.T) {
	setWindow(t, 8)
	check := goroutineBaseline(t)
	pub := &slowPublisher{delay: time.Millisecond}
	p := NewProducer(pub, false).(*producer)
	msgs := pipelineStream(t, 20)
	queue := make(chan bmp.Message)
	stop := make(chan struct{})
	returned := make(chan struct{})
	go func() {
		p.Producer(queue, stop)
		close(returned)
	}()
	var feeder sync.WaitGroup
	feeder.Add(1)
	go func() {
		defer feeder.Done()
		for _, m := range msgs {
			select {
			case queue <- m:
			case <-stop:
				return
			}
		}
	}()
	for pub.count() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(stop)
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("Producer did not return promptly after stop was closed")
	}
	feeder.Wait()
	n := pub.count()
	time.Sleep(50 * time.Millisecond)
	if pub.count() != n {
		t.Errorf("published %d messages after Producer returned", pub.count()-n)
	}
	if n >= len(sequential(msgs)) {
		t.Errorf("published all %d messages, want the abort to drop some", n)
	}
	check()
}

// TestProducerRouteBeforePeerUpUsesConnectionIdentity checks that a route
// read before any Peer Up is published at once, ahead of the Peer Up after
// it, with the router identity of the TCP source.
func TestProducerRouteBeforePeerUpUsesConnectionIdentity(t *testing.T) {
	ph := globalHeader("192.0.2.1", "10.0.0.1")
	rec := &recordingPublisher{}
	runProducer(t, NewProducer(rec, false).(*producer), []bmp.Message{
		{PeerHeader: ph, Payload: &bmp.RouteMonitor{Update: pipelineUpdate(t, nil, pipelinePrefixes(1, 1))}, SpeakerIP: "10.2.1.3"},
		pipelinePeerUp(ph),
	})
	if len(rec.msgs) != 2 || rec.msgs[0].msgType == bmp.PeerStateChangeMsg {
		t.Fatalf("published %d messages, want the route then the Peer Up", len(rec.msgs))
	}
	var route UnicastPrefix
	if err := json.Unmarshal(rec.msgs[0].payload, &route); err != nil {
		t.Fatal(err)
	}
	if route.RouterIP != "10.2.1.3" || route.RouterHash != md5Hex("10.2.1.3") {
		t.Errorf("route router %q/%q, want the connection's 10.2.1.3/%s", route.RouterIP, route.RouterHash, md5Hex("10.2.1.3"))
	}
}
