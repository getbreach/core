// Package transport connects Hy2 to a lab backend or breach-client's UDP pipe.
package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"syscall"
	"time"
)

type Conn struct {
	// Do not expose UDP fast paths that would bypass peer filtering.
	socket *net.UDPConn
	peer   netip.AddrPort
	meter  *Meter
}

// Traffic counts accepted Hy2 datagrams, including protocol overhead. TURN's
// outer SRTP/relay framing and direct routing-policy traffic are not included.
type Traffic struct{ UpBytes, DownBytes, UpPackets, DownPackets uint64 }
type Meter struct{ up, down, upPackets, downPackets atomic.Uint64 }

func (m *Meter) Snapshot() Traffic {
	return Traffic{m.up.Load(), m.down.Load(), m.upPackets.Load(), m.downPackets.Load()}
}

// SetMeter must be called before the connection is handed to Hy2.
func (c *Conn) SetMeter(m *Meter) { c.meter = m }

// Open requires an IP literal. Pipe mode is loopback-only, since breach-client's
// UDP input has no authentication of its own. Hy2 is unmodified in BOTH modes:
// the legacy qtun marker would select the wrong backend on the Breach server.
func Open(remote, mode string) (*Conn, net.Addr, error) {
	return OpenControlled(remote, mode, nil)
}

// OpenControlled protects only real outbound sockets. The private loopback pipe
// must stay on loopback even when a physical interface is bound for TUN mode.
func OpenControlled(remote, mode string, control func(string, string, syscall.RawConn) error) (*Conn, net.Addr, error) {
	peer, err := netip.ParseAddrPort(remote)
	if err != nil || peer.Port() == 0 {
		return nil, nil, errors.New("remote must be an IP literal with a nonzero port")
	}
	if mode != "pipe" && mode != "direct" {
		return nil, nil, errors.New("mode must be pipe or direct")
	}
	if mode == "pipe" && !peer.Addr().IsLoopback() {
		return nil, nil, errors.New("pipe remote must be loopback")
	}
	network := "udp4"
	if peer.Addr().Is6() {
		network = "udp6"
	}
	if mode == "pipe" {
		control = nil
	}
	lc := net.ListenConfig{Control: control}
	pc, err := lc.ListenPacket(context.Background(), network, ":0")
	if err != nil {
		return nil, nil, err
	}
	return &Conn{socket: pc.(*net.UDPConn), peer: peer}, net.UDPAddrFromAddrPort(peer), nil
}

func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if addr == nil || addr.String() != c.peer.String() {
		return 0, errors.New("unexpected Hy2 peer")
	}
	wire := p
	n, err := c.socket.WriteToUDPAddrPort(wire, c.peer)
	if err != nil {
		return 0, err
	}
	if n != len(wire) {
		return 0, io.ErrShortWrite
	}
	if c.meter != nil {
		c.meter.up.Add(uint64(n))
		c.meter.upPackets.Add(1)
	}
	return len(p), nil
}

func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, from, err := c.socket.ReadFromUDPAddrPort(p)
		if err != nil {
			return 0, nil, err
		}
		if from == c.peer {
			if c.meter != nil {
				c.meter.down.Add(uint64(n))
				c.meter.downPackets.Add(1)
			}
			return n, net.UDPAddrFromAddrPort(from), nil
		}
	}
}

func (c *Conn) Close() error                       { return c.socket.Close() }
func (c *Conn) LocalAddr() net.Addr                { return c.socket.LocalAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.socket.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.socket.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.socket.SetWriteDeadline(t) }
