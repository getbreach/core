package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"breach/media"
	"breach/qtun"
	"breach/socks5"
)

// Stream mode on the client: instead of shuttling datagrams between a local UDP
// mouth and the relay (which needs WireGuard or sing-box on top, and a tun —
// hence root), the client speaks QUIC over the relay itself and offers a plain
// SOCKS5 port. One binary, no privileges.
//
// The relay pool already behaves like a datagram socket, so it is exposed to
// quic-go as a net.PacketConn rather than being restructured.

// tunnelConn presents the allocation pool as a single PacketConn.
//
// Reads come from the shared downstream path (startReader hands payloads to
// socksIn); writes are sharded across allocations exactly as the pipe mode
// shards WireGuard traffic. Addresses are nominal: there is one peer, the exit,
// and QUIC only needs something stable to key its state on.
type tunnelConn struct {
	p    *pool
	in   <-chan []byte
	peer net.Addr

	mu       sync.Mutex
	deadline time.Time
	// dlChanged is closed and replaced whenever the deadline moves, so a read
	// already parked notices. quic-go's teardown sets a deadline in the PAST to
	// wake its read loop; a conn that samples the deadline only on entry ignores
	// that and Transport.Close() blocks forever — a failed handshake then hangs
	// the whole client instead of returning an error.
	dlChanged chan struct{}
	closed    chan struct{}
	once      sync.Once
}

func newTunnelConn(p *pool, in <-chan []byte, peer net.Addr) *tunnelConn {
	return &tunnelConn{p: p, in: in, peer: peer, closed: make(chan struct{}), dlChanged: make(chan struct{})}
}

func (c *tunnelConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		c.mu.Lock()
		dl := c.deadline
		changed := c.dlChanged
		c.mu.Unlock()

		var timer <-chan time.Time
		if !dl.IsZero() {
			d := time.Until(dl)
			if d <= 0 {
				return 0, nil, timeoutError{}
			}
			t := time.NewTimer(d)
			defer t.Stop()
			timer = t.C
		}
		select {
		case pkt, ok := <-c.in:
			if !ok {
				return 0, nil, net.ErrClosed
			}
			return copy(b, pkt), c.peer, nil
		case <-timer:
			return 0, nil, timeoutError{}
		case <-c.closed:
			return 0, nil, net.ErrClosed
		case <-changed:
			// Deadline moved under us; re-evaluate rather than keep waiting.
		}
	}
}

func (c *tunnelConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	s := c.p.pick()
	if s == nil {
		// No allocation right now (a re-mint is in flight). Report success: QUIC
		// treats a datagram as lossy anyway and will retransmit, whereas an error
		// here tears the whole connection down for a transient condition.
		return len(b), nil
	}
	// Tag every packet, not just the first. The relay decides a client's backend
	// from the first byte it sees, and this path loses packets — a one-shot
	// announcement that got dropped would strand us on the Hysteria2 backend,
	// which our QUIC is otherwise indistinguishable from.
	msg := make([]byte, len(clientID)+1+len(b))
	copy(msg, clientID[:])
	msg[len(clientID)] = qtun.RelayMarker
	copy(msg[len(clientID)+1:], b)
	wire, err := s.sess.Protect(media.PTData, msg)
	if err != nil {
		// Report success: quic-go treats a write error as fatal and destroys the
		// connection, whereas one allocation misbehaving is a transient event on
		// this path. Losing the datagram is what QUIC already handles.
		return len(b), nil
	}
	if err := s.a.Send(wire); err != nil {
		return len(b), nil
	}
	upCount.Add(1)
	return len(b), nil
}

func (c *tunnelConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *tunnelConn) LocalAddr() net.Addr { return &net.UDPAddr{IP: net.IPv4zero} }
func (c *tunnelConn) SetDeadline(t time.Time) error {
	return c.SetReadDeadline(t)
}
func (c *tunnelConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	close(c.dlChanged) // wake any parked read so it re-reads the deadline
	c.dlChanged = make(chan struct{})
	c.mu.Unlock()
	return nil
}
func (c *tunnelConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

// runSocksMode dials the exit over the relay and serves SOCKS5 locally. It
// blocks until the listener fails.
func runSocksMode(p *pool, peer net.Addr, listen, token, certSha256, proxyUser, proxyPass string) error {
	if token == "" {
		return errors.New("stream mode needs a token (the client's password from the exit)")
	}
	if certSha256 == "" {
		log.Printf("WARNING: no exit certificate pin configured — the exit's identity is NOT verified. " +
			"Set socksCertSha256 from the exit's /etc/breach/qtun-pin.")
	}

	tlsConf, err := qtun.ClientTLS(certSha256)
	if err != nil {
		return err
	}

	// A fresh PacketConn per attempt: quic-go closes the one it was given when a
	// connection ends, so reusing it across re-dials would hand the next attempt
	// a dead socket.
	dial := func(ctx context.Context) (*qtun.Client, error) {
		dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return qtun.Dial(dctx, newTunnelConn(p, socksIn, peer), peer, tlsConf, token)
	}

	d := &qtunDialer{dial: dial}
	// Connect once up front so a bad token or pin is reported at startup rather
	// than on the first browser request.
	if _, err := d.client(context.Background()); err != nil {
		return err
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	log.Printf("breach-client: SOCKS5 on %s (stream mode, no tun, no root)", listen)

	srv := &socks5.Server{
		Dialer:    d,
		UDPDialer: d,
		User:      proxyUser,
		Pass:      proxyPass,
		Logf:      log.Printf,
	}
	return srv.Serve(context.Background(), ln)
}

// qtunDialer keeps the tunnel usable across connection loss.
//
// The QUIC connection dies for ordinary reasons: the exit is redeployed, the
// laptop sleeps past MaxIdleTimeout, or a re-mint leaves the pool empty long
// enough for the connection to time out. Without re-dialling, breach-client
// keeps its SOCKS5 port open and fails every request forever while looking
// perfectly healthy — the worst possible failure, because nothing says restart me.
type qtunDialer struct {
	mu   sync.Mutex
	c    *qtun.Client
	dial func(ctx context.Context) (*qtun.Client, error)
}

// client returns a live connection, re-dialling if the current one is gone.
func (d *qtunDialer) client(ctx context.Context) (*qtun.Client, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.c != nil {
		select {
		case <-d.c.Done():
			log.Printf("breach-client: tunnel connection lost, reconnecting")
			d.c = nil
		default:
			return d.c, nil
		}
	}
	c, err := d.dial(ctx)
	if err != nil {
		return nil, err
	}
	d.c = c
	return c, nil
}

func (d *qtunDialer) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	c, err := d.client(ctx)
	if err != nil {
		return nil, err
	}
	// Bound the wait. Opening a stream can block on the exit's stream credit,
	// and an unbounded wait shows up as a browser tab that spins forever instead
	// of a page that fails.
	octx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return c.Open(octx, target)
}

func (d *qtunDialer) DialUDP(ctx context.Context) (socks5.UDPConn, error) {
	c, err := d.client(ctx)
	if err != nil {
		return nil, err
	}
	return c.OpenUDP(ctx)
}
