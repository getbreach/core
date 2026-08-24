package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// UDP ASSOCIATE. Without it a SOCKS5 proxy carries TCP only, so DNS is resolved
// on the local network (a leak, and often a block) and HTTP/3 either bypasses
// the tunnel or stalls.
//
// Shape per RFC 1928: the association is requested over the TCP control
// connection, which then stays open purely as a lifetime handle — when it
// closes, the relay socket goes with it. Datagrams themselves travel over a
// separate local UDP socket, each carrying its own destination:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
//
// FRAG is not supported (nothing sane emits it, and it is a known amplification
// footgun); such datagrams are dropped rather than mishandled.

// UDPDialer opens a relayed UDP socket on the exit.
type UDPDialer interface {
	DialUDP(ctx context.Context) (UDPConn, error)
}

// UDPConn is one relayed socket: it may address many destinations.
type UDPConn interface {
	WriteTo(payload []byte, target string) error
	ReadFrom(ctx context.Context) (payload []byte, from string, err error)
	Close() error
}

const cmdUDPAssociate = 0x03

// handleUDPAssociate serves one association until its control connection ends.
func (s *Server) handleUDPAssociate(ctx context.Context, ctrl net.Conn) error {
	if s.UDPDialer == nil {
		reply(ctrl, repCmdNotSup)
		return errors.New("UDP ASSOCIATE requested but the tunnel has no UDP support")
	}

	// Bind the local relay socket on the same interface the control connection
	// arrived on, so a proxy on loopback stays on loopback.
	host, _, err := net.SplitHostPort(ctrl.LocalAddr().String())
	if err != nil {
		host = "127.0.0.1"
	}
	local, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		reply(ctrl, repGeneral)
		return fmt.Errorf("bind local udp: %w", err)
	}
	defer local.Close()

	remote, err := s.UDPDialer.DialUDP(ctx)
	if err != nil {
		reply(ctrl, repGeneral)
		return fmt.Errorf("open relayed udp: %w", err)
	}
	defer remote.Close()

	if err := replyAddr(ctrl, local.LocalAddr().(*net.UDPAddr)); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// The client's datagram source is learned from its first packet: RFC 1928
	// lets it announce 0.0.0.0:0, and most clients do. Once learned it is also
	// the ONLY source accepted — otherwise anyone who can reach the relay port
	// (trivially, when the proxy is not on loopback) relays through the tunnel
	// with no credential check at all, and steals the real client's replies.
	// Guarded by a mutex: the two goroutines below share it.
	var (
		addrMu     sync.Mutex
		clientAddr *net.UDPAddr
	)
	addrKnown := make(chan struct{})
	var once sync.Once

	go func() { // exit -> client
		for {
			payload, from, err := remote.ReadFrom(ctx)
			if err != nil {
				cancel()
				return
			}
			select {
			case <-addrKnown:
			case <-ctx.Done():
				return
			}
			pkt, err := encodeUDPReply(from, payload)
			if err != nil {
				continue
			}
			addrMu.Lock()
			dst := clientAddr
			addrMu.Unlock()
			if _, err := local.WriteToUDP(pkt, dst); err != nil {
				cancel()
				return
			}
		}
	}()

	go func() { // client -> exit
		buf := make([]byte, 65535)
		for {
			n, src, err := local.ReadFromUDP(buf)
			if err != nil {
				cancel()
				return
			}
			once.Do(func() {
				addrMu.Lock()
				clientAddr = src
				addrMu.Unlock()
				close(addrKnown)
			})
			addrMu.Lock()
			owner := clientAddr
			addrMu.Unlock()
			if owner == nil || src.String() != owner.String() {
				continue // not this association's client
			}
			target, payload, err := decodeUDPRequest(buf[:n])
			if err != nil {
				continue // malformed or fragmented: drop, as UDP allows
			}
			if err := remote.WriteTo(payload, target); err != nil {
				cancel()
				return
			}
		}
	}()

	// The control connection is the association's lifetime. Reading it also
	// notices the client going away.
	_ = ctrl.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(io.Discard, ctrl)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
	return nil
}

// decodeUDPRequest parses a client datagram into its destination and payload.
func decodeUDPRequest(b []byte) (target string, payload []byte, err error) {
	if len(b) < 4 {
		return "", nil, errors.New("short udp request")
	}
	if b[2] != 0 {
		return "", nil, errors.New("fragmented SOCKS5 datagrams are not supported")
	}
	var host string
	i := 4
	switch b[3] {
	case atypIPv4:
		if len(b) < i+4+2 {
			return "", nil, errors.New("short ipv4 request")
		}
		host = net.IP(b[i : i+4]).String()
		i += 4
	case atypIPv6:
		if len(b) < i+16+2 {
			return "", nil, errors.New("short ipv6 request")
		}
		host = net.IP(b[i : i+16]).String()
		i += 16
	case atypDomain:
		if len(b) < i+1 {
			return "", nil, errors.New("short domain request")
		}
		n := int(b[i])
		i++
		if len(b) < i+n+2 {
			return "", nil, errors.New("short domain request")
		}
		host = string(b[i : i+n])
		i += n
	default:
		return "", nil, fmt.Errorf("unsupported address type %d", b[3])
	}
	port := binary.BigEndian.Uint16(b[i : i+2])
	i += 2
	return net.JoinHostPort(host, strconv.Itoa(int(port))), b[i:], nil
}

// encodeUDPReply wraps a reply so the client can see who sent it.
func encodeUDPReply(from string, payload []byte) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(from)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	out := []byte{0, 0, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, atypIPv4)
			out = append(out, v4...)
		} else {
			out = append(out, atypIPv6)
			out = append(out, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("host too long")
		}
		out = append(out, atypDomain, byte(len(host)))
		out = append(out, host...)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(port))
	return append(out, payload...), nil
}

// replyAddr tells the client where to send its datagrams.
func replyAddr(c net.Conn, addr *net.UDPAddr) error {
	out := []byte{verSocks5, repOK, 0x00}
	if v4 := addr.IP.To4(); v4 != nil {
		out = append(out, atypIPv4)
		out = append(out, v4...)
	} else if addr.IP != nil {
		out = append(out, atypIPv6)
		out = append(out, addr.IP.To16()...)
	} else {
		out = append(out, atypIPv4, 127, 0, 0, 1)
	}
	out = binary.BigEndian.AppendUint16(out, uint16(addr.Port))
	_, err := c.Write(out)
	return err
}
