package parser

import (
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

// TestStartDrainsOnQueueClose checks that once its queue is closed, Start
// passes on the messages it read, closes the producer queue and returns.
func TestStartDrainsOnQueueClose(t *testing.T) {
	queue := make(chan []byte)
	producerQueue := make(chan bmp.Message)
	p := NewParser(queue, producerQueue, make(chan struct{}), nil)
	returned := make(chan struct{})
	go func() {
		p.Start()
		close(returned)
	}()
	const count = 5
	go func() {
		for i := 0; i < count; i++ {
			queue <- buildPeerDownMsg(make([]byte, bmp.PerPeerHeaderLength), byte(i+1), nil)
		}
		close(queue)
	}()
	var got []bmp.Message
	timeout := time.After(5 * time.Second)
	for {
		select {
		case m, ok := <-producerQueue:
			if !ok {
				if len(got) != count {
					t.Fatalf("got %d messages before the producer queue was closed, want %d", len(got), count)
				}
				for i, m := range got {
					if r := m.Payload.(*bmp.PeerDownMessage).Reason; r != uint8(i+1) {
						t.Errorf("message %d has reason %d, want %d", i, r, i+1)
					}
				}
				select {
				case <-returned:
				case <-time.After(5 * time.Second):
					t.Fatal("Start did not return after closing the producer queue")
				}
				return
			}
			got = append(got, m)
		case <-timeout:
			t.Fatal("the producer queue was not closed after the queue was")
		}
	}
}
