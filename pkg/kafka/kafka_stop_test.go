package kafka

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/IBM/sarama/mocks"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

func mockConfig() *sarama.Config {
	c := sarama.NewConfig()
	c.Producer.Return.Successes = true
	c.Producer.Return.Errors = true
	return c
}

// TestStop_FlushesBufferedMessages checks that Stop returns only once every
// message published before it is delivered or failed.
func TestStop_FlushesBufferedMessages(t *testing.T) {
	const count = 50
	c := mockConfig()
	mp := mocks.NewAsyncProducer(t, c)
	slow := func(*sarama.ProducerMessage) error {
		time.Sleep(time.Millisecond)
		return nil
	}
	for i := 0; i < count; i++ {
		if i%10 == 9 {
			mp.ExpectInputAndFail(errors.New("broker down"))
			continue
		}
		mp.ExpectInputWithMessageCheckerFunctionAndSucceed(slow)
	}
	sa := &stubAdmin{}
	p := newPublisher(mp, sa, c, "")
	for i := 0; i < count; i++ {
		if err := p.PublishMessage(bmp.PeerStateChangeMsg, []byte("k"), []byte("{}")); err != nil {
			t.Fatalf("PublishMessage[%d]: %v", i, err)
		}
	}
	p.Stop()
	if d, f := p.delivered.Load(), p.failed.Load(); d != count-count/10 || f != count/10 {
		t.Errorf("Stop returned with %d messages delivered and %d failed, want %d and %d", d, f, count-count/10, count/10)
	}
	if !sa.closed {
		t.Error("Stop did not close the cluster admin")
	}
	p.Stop() // a second Stop is a no-op
}

// TestPublishAfterStop_ReturnsError checks that publishing after Stop
// returns an error instead of panicking on the closed producer input.
func TestPublishAfterStop_ReturnsError(t *testing.T) {
	c := mockConfig()
	p := newPublisher(mocks.NewAsyncProducer(t, c), nil, c, "")
	p.Stop()
	if err := p.PublishMessage(bmp.PeerStateChangeMsg, nil, []byte("{}")); !errors.Is(err, errStopped) {
		t.Errorf("PublishMessage after Stop: error = %v, want %v", err, errStopped)
	}
}

// fakeProducer is a sarama.AsyncProducer that reports every input as
// delivered, without expectations.
type fakeProducer struct {
	sarama.AsyncProducer
	input     chan *sarama.ProducerMessage
	successes chan *sarama.ProducerMessage
	errors    chan *sarama.ProducerError
}

func newFakeProducer() *fakeProducer {
	f := &fakeProducer{
		input:     make(chan *sarama.ProducerMessage),
		successes: make(chan *sarama.ProducerMessage),
		errors:    make(chan *sarama.ProducerError),
	}
	go func() {
		defer close(f.errors)
		defer close(f.successes)
		for m := range f.input {
			f.successes <- m
		}
	}()
	return f
}

func (f *fakeProducer) Input() chan<- *sarama.ProducerMessage     { return f.input }
func (f *fakeProducer) Successes() <-chan *sarama.ProducerMessage { return f.successes }
func (f *fakeProducer) Errors() <-chan *sarama.ProducerError      { return f.errors }
func (f *fakeProducer) AsyncClose()                               { close(f.input) }

// TestStop_ConcurrentPublish checks that Stop racing publishes neither
// panics nor deadlocks, and every publish that succeeded is delivered.
func TestStop_ConcurrentPublish(t *testing.T) {
	p := newPublisher(newFakeProducer(), nil, nil, "")
	var wg sync.WaitGroup
	var mu sync.Mutex
	published := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if err := p.PublishMessage(bmp.UnicastPrefixMsg, nil, []byte("{}")); err != nil {
					if !errors.Is(err, errStopped) {
						t.Errorf("PublishMessage: %v", err)
					}
					return
				}
				mu.Lock()
				published++
				mu.Unlock()
			}
		}()
	}
	time.Sleep(10 * time.Millisecond)
	stopped := make(chan struct{})
	go func() {
		p.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not return while publishes raced it")
	}
	wg.Wait()
	if d := p.delivered.Load(); d != int64(published) {
		t.Errorf("%d messages delivered, want the %d published", d, published)
	}
}
