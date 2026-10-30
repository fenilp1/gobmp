package nats

import (
	"errors"
	"sync"
	"testing"
	"time"

	natsgo "github.com/nats-io/nats.go"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestStop_WaitsForAcks checks that Stop returns only once the outstanding
// acknowledgements are in.
func TestStop_WaitsForAcks(t *testing.T) {
	acked := make(chan struct{})
	p := newPublisher(nil, &fakeJetStream{completeFn: func() <-chan struct{} { return acked }})
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("k"), []byte("{}")); err != nil {
		t.Fatalf("PublishMessage: %v", err)
	}
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("Stop returned with acknowledgements outstanding")
	case <-time.After(50 * time.Millisecond):
	}
	close(acked)
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return once the acknowledgements were in")
	}
	p.Stop() // a second Stop is a no-op
}

// TestStop_AckTimeout checks that Stop gives up on acknowledgements after
// stopTimeout.
func TestStop_AckTimeout(t *testing.T) {
	old := stopTimeout
	stopTimeout = 20 * time.Millisecond
	defer func() { stopTimeout = old }()
	p := newPublisher(nil, &fakeJetStream{completeFn: func() <-chan struct{} { return make(chan struct{}) }})
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not give up on the acknowledgements")
	}
}

func TestPublishAfterStop_ReturnsError(t *testing.T) {
	published := 0
	p := newPublisher(nil, &fakeJetStream{publishFn: func(*natsgo.Msg) error {
		published++
		return nil
	}})
	p.Stop()
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")); !errors.Is(err, errStopped) {
		t.Errorf("PublishMessage after Stop: error = %v, want %v", err, errStopped)
	}
	if published != 0 {
		t.Errorf("%d messages reached JetStream after Stop", published)
	}
}

// TestPublish_WaitsWhileStalled checks that a publish keeps waiting while
// too many acknowledgements are outstanding, publishes once there is room,
// and gives up when Stop is called.
func TestPublish_WaitsWhileStalled(t *testing.T) {
	var mu sync.Mutex
	stalls, subjects := 3, []string{}
	p := newPublisher(nil, &fakeJetStream{publishFn: func(m *natsgo.Msg) error {
		mu.Lock()
		defer mu.Unlock()
		if stalls > 0 {
			stalls--
			return natsgo.ErrTooManyStalledMsgs
		}
		subjects = append(subjects, m.Subject)
		return nil
	}})
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")); err != nil {
		t.Fatalf("PublishMessage: %v", err)
	}
	mu.Lock()
	if len(subjects) != 1 || subjects[0] != peerTopic {
		t.Fatalf("published to %v, want [%s]", subjects, peerTopic)
	}
	stalls = 1 << 30
	mu.Unlock()
	done := make(chan error)
	go func() { done <- p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")) }()
	time.Sleep(10 * time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errStopped) {
			t.Errorf("stalled PublishMessage: error = %v, want %v", err, errStopped)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled publish did not give up on Stop")
	}
	<-stopped
}
