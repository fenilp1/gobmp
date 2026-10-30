package gobmpsrv

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sbezverk/gobmp/pkg/bmp"
)

type drainPublisher struct {
	mu        sync.Mutex
	started   int
	messages  []orderedPublication
	stoppedAt int
	release   chan struct{}
}

func (p *drainPublisher) PublishMessage(kind int, _, data []byte) error {
	p.mu.Lock()
	p.started++
	last := p.started == 3
	p.mu.Unlock()
	if last {
		<-p.release
	}
	p.mu.Lock()
	p.messages = append(p.messages, orderedPublication{kind, append([]byte(nil), data...)})
	p.mu.Unlock()
	return nil
}

func (p *drainPublisher) Stop() {
	p.mu.Lock()
	p.stoppedAt = len(p.messages)
	p.mu.Unlock()
}

// The next socket read starts only after the final complete frame has been
// handed to the parser. A successful peer Write alone does not prove acceptance.
type drainAcceptedConn struct {
	net.Conn
	read, frameBytes int
	accepted         chan struct{}
}

func (c *drainAcceptedConn) Read(b []byte) (int, error) {
	if c.accepted != nil && c.read >= c.frameBytes {
		close(c.accepted)
		c.accepted = nil
	}
	n, err := c.Conn.Read(b)
	c.read += n
	return n, err
}

func TestBMPWorkerDrainsAcceptedFramesBeforePublisherStop(t *testing.T) {
	for _, raw := range []bool{false, true} {
		for _, ending := range []string{"eof", "stop", "partial-header", "partial-payload"} {
			t.Run(fmt.Sprintf("raw=%t/%s", raw, ending), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					pub := &drainPublisher{release: make(chan struct{}), stoppedAt: -1}
					var releaseOnce sync.Once
					unblock := func() { releaseOnce.Do(func() { close(pub.release) }) }
					defer unblock()
					server, client := net.Pipe()
					defer func() { _ = client.Close() }()
					frames := [][]byte{
						orderBMPFrame(bmp.PeerDownMsg, 1, []byte{4}),
						orderBMPFrame(bmp.PeerDownMsg, 2, []byte{4}),
						orderBMPFrame(bmp.PeerDownMsg, 3, []byte{4}),
					}
					wire := bytes.Join(frames, nil)
					accepted := make(chan struct{})
					conn := &drainAcceptedConn{Conn: wrapAddr(server, "192.0.2.1:5000"), frameBytes: len(wire), accepted: accepted}
					switch ending {
					case "partial-header":
						wire = append(wire, 3, 0, 0)
					case "partial-payload":
						tail := orderBMPFrame(bmp.PeerDownMsg, 4, []byte{4})
						wire = append(wire, tail[:len(tail)-1]...)
					}
					srv := &bmpServer{publisher: pub, bmpRaw: raw, incoming: newMockListener(), clients: make(map[net.Conn]struct{})}
					srv.startWorker(conn, false)
					workerDone := make(chan struct{})
					go func() { srv.wg.Wait(); close(workerDone) }()
					written := make(chan error, 1)
					go func() { _, err := client.Write(wire); written <- err }()
					<-accepted
					if err := <-written; err != nil {
						t.Fatal(err)
					}
					if ending != "stop" {
						if err := client.Close(); err != nil {
							t.Fatal(err)
						}
						synctest.Wait()
						select {
						case <-workerDone:
							t.Error("worker returned before its accepted publications completed")
						default:
						}
					}
					stopped := make(chan struct{})
					go func() { srv.Stop(); close(stopped) }()
					synctest.Wait()
					select {
					case <-stopped:
						t.Error("server Stop returned while accepted publication was pending")
					default:
					}
					pub.mu.Lock()
					if pub.started != 3 || len(pub.messages) != 2 || pub.stoppedAt != -1 {
						t.Errorf("before release: started=%d completed=%d stoppedAt=%d, want 3/2/-1", pub.started, len(pub.messages), pub.stoppedAt)
					}
					pub.mu.Unlock()
					unblock()
					synctest.Wait()
					<-workerDone
					<-stopped
					pub.mu.Lock()
					defer pub.mu.Unlock()
					if len(pub.messages) != 3 || pub.stoppedAt != 3 {
						t.Fatalf("completed=%d stoppedAt=%d, want 3/3", len(pub.messages), pub.stoppedAt)
					}
					for i, record := range pub.messages {
						if raw {
							if record.kind != bmp.BMPRawMsg || len(record.data) < 8 {
								t.Fatalf("RAW record %d: type=%d length=%d", i, record.kind, len(record.data))
							}
							headerLen := int(binary.BigEndian.Uint16(record.data[6:8]))
							if headerLen > len(record.data) || !bytes.Equal(record.data[headerLen:], frames[i]) {
								t.Fatalf("RAW record %d does not preserve the accepted frame", i)
							}
							continue
						}
						var event struct{ Timestamp string }
						if err := json.Unmarshal(record.data, &event); err != nil {
							t.Fatal(err)
						}
						if record.kind != bmp.PeerStateChangeMsg || event.Timestamp != fmt.Sprintf("1970-01-01T00:00:0%dZ", i+1) {
							t.Fatalf("parsed record %d: type=%d timestamp=%s", i, record.kind, event.Timestamp)
						}
					}
				})
			})
		}
	}
}

// blockingPublisher blocks every publication until release is closed.
type blockingPublisher struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *blockingPublisher) PublishMessage(int, []byte, []byte) error {
	p.once.Do(func() { close(p.started) })
	<-p.release
	return nil
}

func (p *blockingPublisher) Stop() {}

// After a protocol error the router's connection is closed at once, not only
// once the accepted frames have drained through a slow publisher, so an
// active-mode collector can redial meanwhile.
func TestBMPWorkerClosesConnectionBeforeDraining(t *testing.T) {
	pub := &blockingPublisher{started: make(chan struct{}), release: make(chan struct{})}
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	srv := &bmpServer{publisher: pub}
	done := workerDone(srv, wrapAddr(server, "192.0.2.1:5000"))
	defer func() { assertWorkerExits(t, done) }()
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(pub.release) }) }
	defer release()

	// A valid Peer Down, whose publication blocks, then a Peer Down header
	// with no payload, which ends the connection as malformed.
	go func() {
		_, _ = client.Write(orderBMPFrame(bmp.PeerDownMsg, 1, []byte{4}))
		_, _ = client.Write([]byte{3, 0, 0, 0, bmp.CommonHeaderLength, bmp.PeerDownMsg})
	}()
	select {
	case <-pub.started:
	case <-time.After(time.Second):
		t.Fatal("the Peer Down was not published")
	}
	read := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		read <- err
	}()
	select {
	case err := <-read:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("client read error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("the connection was still open after 1s while the publisher was blocked")
	}
	release()
}
