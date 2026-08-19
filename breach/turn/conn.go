package turn

import (
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// NetConn adapts an Alloc to net.Conn so a DTLS handshake can run over the TURN
// channel: Write -> ChannelData out, Read -> next relayed datagram in. Closing
// this conn (e.g. when DTLS finishes and we switch to raw SRTP) stops its reader
// WITHOUT closing the underlying allocation, so a.In() is freed for the SRTP
// reader and the allocation keeps living.
func (a *Alloc) NetConn() net.Conn {
	return &allocConn{a: a, done: make(chan struct{})}
}

type allocConn struct {
	a    *Alloc
	mu   sync.Mutex
	rdl  time.Time
	done chan struct{}
	once sync.Once
}

func (c *allocConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	dl := c.rdl
	c.mu.Unlock()

	var timer <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, os.ErrDeadlineExceeded
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}

	select {
	case p, ok := <-c.a.In():
		if !ok {
			return 0, io.EOF
		}
		return copy(b, p), nil
	case <-timer:
		return 0, os.ErrDeadlineExceeded
	case <-c.done:
		return 0, io.EOF
	}
}

func (c *allocConn) Write(b []byte) (int, error) {
	if err := c.a.Send(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close stops the DTLS reader; the allocation itself stays open.
func (c *allocConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return nil
}

func (c *allocConn) LocalAddr() net.Addr  { return c.a.tr.localAddr() }
func (c *allocConn) RemoteAddr() net.Addr { return c.a.tr.remoteAddr() }

func (c *allocConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.rdl = t
	c.mu.Unlock()
	return nil
}

func (c *allocConn) SetWriteDeadline(time.Time) error { return nil }

func (c *allocConn) SetDeadline(t time.Time) error { return c.SetReadDeadline(t) }
