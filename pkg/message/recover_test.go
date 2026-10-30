package message

import (
	"testing"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// producingWorker must contain a panic to the message that caused it. A PeerUp
// without OPEN messages dereferences nil, standing in for any producer bug.
// The second panic takes the path that logs without a stack trace.
func TestProducingWorkerRecoversPanic(t *testing.T) {
	p := NewProducer(&mockPublisher{}, false).(*producer)
	for i := 0; i < 2; i++ {
		p.producingWorker(bmp.Message{
			PeerHeader: makePeerHeader(t, bmp.PeerType0, 0),
			Payload:    &bmp.PeerUpMessage{},
		})
	}
	if !p.panicked.Load() {
		t.Fatal("recovered panic not recorded")
	}
}

// The Producer loop calls producingWorker inline, so a contained panic must
// leave it running: the next message on the connection is still published.
func TestProducerContinuesAfterPanic(t *testing.T) {
	pub := &orderedPublisher{messages: make(chan int, 8)}
	p := NewProducer(pub, false)
	queue := make(chan bmp.Message)
	done := make(chan struct{})
	go func() { p.Producer(queue, make(chan struct{})); close(done) }()

	ph := makePeerHeader(t, bmp.PeerType0, 0)
	sendOrderedMessage(t, queue, bmp.Message{PeerHeader: ph, Payload: &bmp.PeerUpMessage{}})
	sendOrderedMessage(t, queue, bmp.Message{PeerHeader: ph, Payload: buildPeerUpMessage(t, "192.0.2.1")})
	close(queue)
	awaitOrderedProducer(t, done)

	if n := len(pub.messages); n != 1 {
		t.Fatalf("published %d messages, want 1", n)
	}
	if got := <-pub.messages; got != bmp.PeerStateChangeMsg {
		t.Fatalf("published message type %d, want %d", got, bmp.PeerStateChangeMsg)
	}
}
