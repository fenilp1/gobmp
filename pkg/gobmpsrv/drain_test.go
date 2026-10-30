package gobmpsrv

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
	"github.com/sbezverk/gobmp/pkg/config"
)

// strictPublisher takes delay over each message and records any message
// published after Stop.
type strictPublisher struct {
	delay time.Duration

	mu        sync.Mutex
	count     int
	stopped   bool
	afterStop int
}

func (s *strictPublisher) PublishMessage(int, []byte, []byte) error {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		s.afterStop++
	}
	s.count++
	return nil
}

func (s *strictPublisher) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = true
}

func (s *strictPublisher) published() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// TestBMPWorker_DrainsBeforeReturn checks that once the router closes the
// connection, bmpWorker returns only after every message it read is
// published.
func TestBMPWorker_DrainsBeforeReturn(t *testing.T) {
	const count = 30
	pub := &strictPublisher{delay: time.Millisecond}
	serverConn, clientConn := net.Pipe()
	done := workerDone(&bmpServer{publisher: pub}, serverConn)

	msg := makePeerDownMessage()
	for i := 0; i < count; i++ {
		if _, err := clientConn.Write(msg); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	_ = clientConn.Close()
	assertWorkerExits(t, done)
	if n := pub.published(); n != count {
		t.Errorf("bmpWorker returned after %d of %d messages were published", n, count)
	}
}

// TestBMPServer_Stop_PublisherStoppedAfterLastPublish checks that Stop stops
// the publisher only after the last message the server read is published.
func TestBMPServer_Stop_PublisherStoppedAfterLastPublish(t *testing.T) {
	pub := &strictPublisher{delay: 2 * time.Millisecond}
	srv, err := NewBMPServer(&config.Config{Publisher: pub})
	if err != nil {
		t.Fatalf("NewBMPServer: %v", err)
	}
	srv.Start()
	port := srv.(*bmpServer).incoming.Addr().(*net.TCPAddr).Port
	c, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	msg := makePeerDownMessage()
	for i := 0; i < 50; i++ {
		if _, err := c.Write(msg); err != nil {
			t.Fatalf("Write[%d]: %v", i, err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for pub.published() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no message reached the publisher")
		}
		time.Sleep(time.Millisecond)
	}

	stopped := make(chan struct{})
	go func() {
		srv.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop() did not return within 5s")
	}
	time.Sleep(20 * time.Millisecond)
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if !pub.stopped {
		t.Error("Stop() did not stop the publisher")
	}
	if pub.afterStop != 0 {
		t.Errorf("%d messages were published after the publisher was stopped", pub.afterStop)
	}
}

// gatePublisher blocks every publish until gate is closed, and signals
// entered as one starts.
type gatePublisher struct {
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
}

func (g *gatePublisher) PublishMessage(int, []byte, []byte) error {
	g.once.Do(func() { close(g.entered) })
	<-g.gate
	return nil
}

func (g *gatePublisher) Stop() {}

// TestBMPWorker_ProtocolErrorClosesConnectionWhileDraining checks that on a
// protocol error the connection is closed at once, though a blocked
// publisher holds up the drain.
func TestBMPWorker_ProtocolErrorClosesConnectionWhileDraining(t *testing.T) {
	pub := &gatePublisher{gate: make(chan struct{}), entered: make(chan struct{})}
	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	done := workerDone(&bmpServer{publisher: pub}, serverConn)

	if _, err := clientConn.Write(makePeerDownMessage()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	select {
	case <-pub.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no message reached the publisher")
	}
	// Version byte must be 3; 1 is a protocol error.
	hdr := make([]byte, bmp.CommonHeaderLength)
	hdr[0] = 1
	binary.BigEndian.PutUint32(hdr[1:5], uint32(bmp.CommonHeaderLength+10))
	hdr[5] = bmp.TerminationMsg
	if _, err := clientConn.Write(hdr); err != nil {
		t.Fatalf("Write: %v", err)
	}

	read := make(chan error, 1)
	go func() {
		_, err := clientConn.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		if !errors.Is(err, io.EOF) {
			t.Errorf("client Read: error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Error("the connection stayed open while the publisher blocked the drain")
	}
	close(pub.gate)
	assertWorkerExits(t, done)
}
