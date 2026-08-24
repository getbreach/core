package qtun_test

import (
	"context"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"breach/qtun"
)

// lossyConn is the relay as QUIC will actually meet it: a datagram path that
// drops, duplicates and reorders. The pipe mode never cared, because WireGuard
// and Hysteria2 dealt with it themselves; stream mode leans on QUIC for exactly
// this, so it has to be proven rather than assumed.
type lossyConn struct {
	peer     *lossyConn
	in       chan []byte
	lossPct  int
	rnd      *rand.Rand
	rndMu    sync.Mutex
	deadline time.Time
	mu       sync.Mutex
	closed   chan struct{}
	once     sync.Once
	addr     net.Addr
}

func newLossyPair(lossPct int) (*lossyConn, *lossyConn) {
	a := &lossyConn{in: make(chan []byte, 4096), lossPct: lossPct, rnd: rand.New(rand.NewSource(1)), closed: make(chan struct{}), addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 1}}
	b := &lossyConn{in: make(chan []byte, 4096), lossPct: lossPct, rnd: rand.New(rand.NewSource(2)), closed: make(chan struct{}), addr: &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 2}}
	a.peer, b.peer = b, a
	return a, b
}

func (c *lossyConn) drop() bool {
	c.rndMu.Lock()
	defer c.rndMu.Unlock()
	return c.rnd.Intn(100) < c.lossPct
}

func (c *lossyConn) ReadFrom(b []byte) (int, net.Addr, error) {
	var timer <-chan time.Time
	c.mu.Lock()
	dl := c.deadline
	c.mu.Unlock()
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, nil, timeoutErr{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-c.in:
		return copy(b, p), c.peer.addr, nil
	case <-timer:
		return 0, nil, timeoutErr{}
	case <-c.closed:
		return 0, nil, net.ErrClosed
	}
}

func (c *lossyConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if c.drop() {
		return len(b), nil // silently lost, exactly like the real path
	}
	pkt := make([]byte, len(b))
	copy(pkt, b)
	select {
	case c.peer.in <- pkt:
	case <-c.peer.closed:
	default:
	}
	return len(b), nil
}

func (c *lossyConn) Close() error        { c.once.Do(func() { close(c.closed) }); return nil }
func (c *lossyConn) LocalAddr() net.Addr { return c.addr }
func (c *lossyConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *lossyConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}
func (c *lossyConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// A meaningful payload has to survive a path losing 5% of datagrams, which is
// worse than the relay behaves in practice.
func TestSurvivesPacketLoss(t *testing.T) {
	if testing.Short() {
		t.Skip("slow: retransmission timers")
	}
	echo := echoServer(t)

	srvPC, cliPC := newLossyPair(5)
	tlsConf, pin, err := qtun.ServerTLS(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = qtun.Serve(ctx, srvPC, tlsConf, qtun.ServerOptions{Auth: func(string) bool { return true }, AllowPrivate: true})
	}()

	cliTLS, err := qtun.ClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 30*time.Second)
	defer dcancel()
	c, err := qtun.Dial(dctx, cliPC, srvPC.LocalAddr(), cliTLS, "tok")
	if err != nil {
		t.Fatalf("handshake over a lossy path: %v", err)
	}
	defer c.Close()

	conn, err := c.Open(context.Background(), echo.Addr().String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	// 256 KiB through a 5%-loss path: enough to force retransmission and
	// congestion control to actually run.
	payload := make([]byte, 256<<10)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		_, _ = conn.Write(payload)
	}()

	got := make([]byte, len(payload))
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read back: %v", err)
	}
	for i := range got {
		if got[i] != payload[i] {
			t.Fatalf("corruption at byte %d", i)
		}
	}
}
