package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"breach-nativecore/outbound"
)

// Control runs before connect/bind. Android MUST supply VpnService.protect.
// A refusal aborts the socket; there is no fallback to an unprotected socket.
type Control func(network, address string, c syscall.RawConn) error
type Direct struct{ Control Control }

func (d Direct) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	if _, e := netip.ParseAddrPort(target); e != nil {
		return nil, errors.New("direct outbound requires a resolved IP")
	}
	return (&net.Dialer{Control: d.Control}).DialContext(ctx, "tcp", target)
}

type directUDP struct{ conn *net.UDPConn }

func (d *directUDP) WriteTo(p []byte, target string) error {
	a, e := netip.ParseAddrPort(target)
	if e != nil {
		return e
	}
	if d.conn == nil {
		return errors.New("direct UDP must be opened for a destination")
	}
	_, e = d.conn.WriteToUDPAddrPort(p, a)
	return e
}
func (d *directUDP) ReadFrom(ctx context.Context) ([]byte, string, error) {
	if d.conn == nil {
		return nil, "", net.ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { d.conn.Close() })
	defer stop()
	b := make([]byte, 65535)
	n, a, e := d.conn.ReadFromUDPAddrPort(b)
	if e != nil {
		return nil, "", e
	}
	return b[:n], a.String(), nil
}
func (d *directUDP) Close() error {
	if d.conn != nil {
		return d.conn.Close()
	}
	return nil
}
func (d Direct) openUDP(ctx context.Context, target string) (outbound.Datagrams, error) {
	a, e := netip.ParseAddrPort(target)
	if e != nil {
		return nil, e
	}
	network, bind := "udp4", "0.0.0.0:0"
	if a.Addr().Is6() {
		network, bind = "udp6", "[::]:0"
	}
	pc, e := (&net.ListenConfig{Control: d.Control}).ListenPacket(ctx, network, bind)
	if e != nil {
		return nil, e
	}
	return &directUDP{conn: pc.(*net.UDPConn)}, nil
}
