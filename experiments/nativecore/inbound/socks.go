// Package inbound exposes a local proxy backed only by the selected outbound.
package inbound

import (
	"context"
	"net"
	"sync"

	"breach-nativecore/outbound"
	"breach/socks5"
)

type socksDialer struct{ outbound.Outbound }

func (d socksDialer) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	return d.DialTCP(ctx, target)
}
func (d socksDialer) DialUDP(ctx context.Context) (socks5.UDPConn, error) { return d.OpenUDP(ctx) }

// ServeSOCKS owns ln and closes accepted connections on cancellation, including
// clients stalled during SOCKS negotiation. DNS names go to the Hy2 exit.
func ServeSOCKS(ctx context.Context, ln net.Listener, out outbound.Outbound) error {
	l := &trackedListener{Listener: ln, conns: make(map[*trackedConn]struct{})}
	stop := context.AfterFunc(ctx, func() { l.Close() })
	defer stop()
	defer l.Close()
	d := socksDialer{out}
	err := (&socks5.Server{Dialer: d, UDPDialer: d}).Serve(ctx, l)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

type trackedListener struct {
	net.Listener
	mu     sync.Mutex
	closed bool
	conns  map[*trackedConn]struct{}
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		c.Close()
		return nil, net.ErrClosed
	}
	w := &trackedConn{Conn: c, owner: l}
	l.conns[w] = struct{}{}
	return w, nil
}

func (l *trackedListener) Close() error {
	err := l.Listener.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for c := range l.conns {
		c.Conn.Close()
	}
	return err
}

type trackedConn struct {
	net.Conn
	owner *trackedListener
}

func (c *trackedConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.conns, c)
	c.owner.mu.Unlock()
	return err
}
func (c *trackedConn) CloseWrite() error {
	if w, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return w.CloseWrite()
	}
	return c.Close()
}
