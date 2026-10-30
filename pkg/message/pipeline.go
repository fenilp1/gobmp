package message

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/golang/glog"
	"github.com/sbezverk/gobmp/pkg/bmp"
)

// window is the most messages of one BMP connection that Producer holds
// between reading them and publishing what they produce. It bounds the
// messages decoded at once and, by message count, the memory their output
// takes: the JSON of one 4096-byte UPDATE can reach about 0.76 MB, and far
// more for an RFC 8654 extended message, so the cap is kept low; 16
// concurrent jobs per connection are ample. It is a var so tests can change
// it.
var window = defaultWindow()

func defaultWindow() int {
	return min(max(2*runtime.GOMAXPROCS(0), 4), 16)
}

// slot holds what one message produces until its turn to be published.
type slot struct {
	// done is closed once the message is processed and buf is final.
	done chan struct{}
	buf  slotBuffer
}

type slotMessage struct {
	msgType int
	key     []byte
	msg     []byte
}

// slotBuffer is the pub.Publisher a job publishes to: it keeps the messages
// for the output goroutine to publish in order.
type slotBuffer struct {
	msgs []slotMessage
}

func (b *slotBuffer) PublishMessage(msgType int, key []byte, msg []byte) error {
	b.msgs = append(b.msgs, slotMessage{msgType: msgType, key: key, msg: msg})
	return nil
}

func (b *slotBuffer) Stop() {}

// slotPool keeps published slots, so the buffer of a large update is reused
// rather than grown again for the next one.
var slotPool = sync.Pool{New: func() any { return new(slot) }}

func newSlot() *slot {
	s := slotPool.Get().(*slot)
	s.done = make(chan struct{})
	return s
}

// freeSlot returns s, published, to slotPool.
func freeSlot(s *slot) {
	clear(s.buf.msgs)
	s.buf.msgs = s.buf.msgs[:0]
	slotPool.Put(s)
}

// runJob processes msg into slot s on a copy of the producer whose publisher
// is the slot's buffer, and marks s done even if processing panics.
func (p *producer) runJob(s *slot, msg bmp.Message) {
	defer close(s.done)
	defer p.recoverJob(msg)
	jp := *p
	jp.publisher = &s.buf
	jp.producingWorker(msg)
}

// recoverJob logs a panic of the job processing msg, so a message the
// decoders cannot handle neither stops the process nor the messages after
// it. What the job published before it panicked is kept.
func (p *producer) recoverJob(msg bmp.Message) {
	r := recover()
	if r == nil {
		return
	}
	glog.Errorf("recovered from panic producing %T from speaker %s %s: %v", msg.Payload, msg.SpeakerIP, panicContext(msg), r)
	if p.state().panicked.CompareAndSwap(false, true) || bool(glog.V(5)) {
		glog.Errorf("panic stack: %s", debug.Stack())
	}
}

// panicContext describes the peer of msg for the log of a panic.
func panicContext(msg bmp.Message) (s string) {
	defer func() {
		if recover() != nil {
			s = "peer unknown"
		}
	}()
	ph := msg.PeerHeader
	if ph == nil {
		return "peer unknown"
	}
	return fmt.Sprintf("peer %s BGP ID %s type %d distinguisher %s",
		ph.GetPeerAddrString(), ph.GetPeerBGPIDString(), ph.PeerType, ph.GetPeerDistinguisherString())
}

// output publishes the messages of each slot read from slots, in order, once
// the slot is done, until slots is closed or stop is.
func (p *producer) output(slots <-chan *slot, stop <-chan struct{}) {
	for s := range slots {
		select {
		case <-s.done:
		case <-stop:
			return
		}
		select {
		case <-stop:
			return
		default:
		}
		for _, m := range s.buf.msgs {
			if err := p.publisher.PublishMessage(m.msgType, m.key, m.msg); err != nil {
				glog.Errorf("failed to publish a message of type %d with error: %+v", m.msgType, err)
			}
		}
		freeSlot(s)
	}
}
