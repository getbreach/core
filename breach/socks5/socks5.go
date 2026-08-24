// Package socks5 is the local entry point of the tunnel's stream mode: a
// minimal SOCKS5 server that hands every CONNECT to the exit instead of dialling
// it locally.
//
// It is deliberately small. Only CONNECT is implemented — BIND is a relic, and
// UDP ASSOCIATE is a separate piece of work (without it, DNS and QUIC-based
// sites bypass the proxy, so callers must route those explicitly or accept the
// leak). Authentication is optional because the listener belongs on loopback;
// bind it anywhere else and the proxy is open to that network.
package socks5

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Dialer is what the proxy forwards to — in practice the qtun client.
type Dialer interface {
	// DialTarget opens a connection to "host:port" through the tunnel.
	DialTarget(ctx context.Context, target string) (net.Conn, error)
}

// Server serves SOCKS5 on a listener.
type Server struct {
	Dialer Dialer
	// UDPDialer enables UDP ASSOCIATE. nil = TCP only, and DNS/HTTP-3 will go
	// around the proxy rather than through it.
	UDPDialer UDPDialer
	// User/Pass enable username/password auth (RFC 1929). Empty = no auth.
	User string
	Pass string
	Logf func(format string, args ...any)
}

const (
	verSocks5  = 0x05
	cmdConnect = 0x01

	authNone  = 0x00
	authUser  = 0x02
	authNone2 = 0xFF

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repOK          = 0x00
	repGeneral     = 0x01
	repUnreachable = 0x04
	repCmdNotSup   = 0x07
	repAtypNotSup  = 0x08

	greetTimeout = 15 * time.Second
)

// Serve accepts connections until ln fails.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Dialer == nil {
		return errors.New("socks5: Dialer is required")
	}
	// A password with no username used to select "no auth" silently, so a proxy
	// the operator believed was protected was wide open.
	if s.Pass != "" && s.User == "" {
		return errors.New("socks5: a password was set without a username — refusing to serve an unauthenticated proxy")
	}
	if s.Logf == nil {
		s.Logf = func(string, ...any) {}
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			// A transient accept error (EMFILE under a browser opening hundreds of
			// connections) must cost one connection, not the whole client.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			if isTemporaryAccept(err) {
				s.Logf("socks5: accept: %v (retrying)", err)
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go func() {
			defer c.Close()
			if err := s.handle(ctx, c); err != nil {
				s.Logf("socks5: %v", err)
			}
		}()
	}
}

func (s *Server) handle(ctx context.Context, c net.Conn) error {
	// The whole SOCKS5 negotiation is a handful of small reads; bound them so a
	// silent client cannot pin a goroutine.
	_ = c.SetDeadline(time.Now().Add(greetTimeout))

	if err := s.negotiate(c); err != nil {
		return err
	}
	cmd, target, err := readRequest(c)
	if err != nil {
		return err
	}
	if cmd == cmdUDPAssociate {
		return s.handleUDPAssociate(ctx, c)
	}

	// Clear the deadline before proxying: the negotiation budget must not become
	// a limit on how long a tunnelled connection may live.
	_ = c.SetDeadline(time.Time{})

	out, err := s.Dialer.DialTarget(ctx, target)
	if err != nil {
		reply(c, repUnreachable)
		return fmt.Errorf("connect %s: %w", target, err)
	}
	defer out.Close()

	if err := reply(c, repOK); err != nil {
		return err
	}
	pipe(c, out)
	return nil
}

// negotiate runs the method-selection (and, if configured, RFC 1929 auth).
func (s *Server) negotiate(c net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != verSocks5 {
		return fmt.Errorf("not SOCKS5 (version %d)", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}

	want := byte(authNone)
	if s.User != "" {
		want = authUser
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		_, _ = c.Write([]byte{verSocks5, authNone2})
		return errors.New("no acceptable auth method")
	}
	if _, err := c.Write([]byte{verSocks5, want}); err != nil {
		return err
	}
	if want == authNone {
		return nil
	}
	return s.checkUserPass(c)
}

func (s *Server) checkUserPass(c net.Conn) error {
	var ver [1]byte
	if _, err := io.ReadFull(c, ver[:]); err != nil {
		return err
	}
	if ver[0] != 0x01 {
		return fmt.Errorf("bad auth subnegotiation version %d", ver[0])
	}
	readField := func() (string, error) {
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return "", err
		}
		return string(b), nil
	}
	user, err := readField()
	if err != nil {
		return err
	}
	pass, err := readField()
	if err != nil {
		return err
	}
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(s.User)) == 1
	okPass := subtle.ConstantTimeCompare([]byte(pass), []byte(s.Pass)) == 1
	if !okUser || !okPass {
		_, _ = c.Write([]byte{0x01, 0x01})
		return errors.New("bad proxy credentials")
	}
	_, err = c.Write([]byte{0x01, 0x00})
	return err
}

// readRequest parses a request and returns its command plus "host:port". For
// UDP ASSOCIATE the address is the one the client will send from, which we do
// not need — the datagrams announce their own source.
func readRequest(c net.Conn) (byte, string, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return 0, "", err
	}
	if head[0] != verSocks5 {
		return 0, "", fmt.Errorf("bad request version %d", head[0])
	}
	if head[1] != cmdConnect && head[1] != cmdUDPAssociate {
		reply(c, repCmdNotSup)
		return 0, "", fmt.Errorf("unsupported command %d (CONNECT and UDP ASSOCIATE only)", head[1])
	}

	var host string
	switch head[3] {
	case atypIPv4:
		b := make([]byte, 4)
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, "", err
		}
		host = net.IP(b).String()
	case atypIPv6:
		b := make([]byte, 16)
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, "", err
		}
		host = net.IP(b).String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return 0, "", err
		}
		b := make([]byte, n[0])
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, "", err
		}
		host = string(b)
	default:
		reply(c, repAtypNotSup)
		return 0, "", fmt.Errorf("unsupported address type %d", head[3])
	}

	var portB [2]byte
	if _, err := io.ReadFull(c, portB[:]); err != nil {
		return 0, "", err
	}
	port := binary.BigEndian.Uint16(portB[:])
	if head[1] == cmdConnect && (host == "" || port == 0) {
		reply(c, repGeneral)
		return 0, "", errors.New("empty target")
	}
	return head[1], net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// reply sends a SOCKS5 reply. The bound address is reported as 0.0.0.0:0 — the
// exit's real address is deliberately not disclosed, and no client needs it.
func reply(c net.Conn, code byte) error {
	_, err := c.Write([]byte{verSocks5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// isTemporaryAccept reports the exhaustion errors that clear on their own.
func isTemporaryAccept(err error) bool {
	return errors.Is(err, syscall.EMFILE) || errors.Is(err, syscall.ENFILE) ||
		errors.Is(err, syscall.ENOBUFS) || errors.Is(err, syscall.ECONNABORTED)
}

// pipe copies both ways until BOTH directions finish, propagating each end's
// half-close. Stopping at the first EOF discarded the response to any client
// that signals "request complete" by shutting down its write side — the whole
// of HTTP/1.0 through `nc -N`, for instance.
func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); closeWrite(a) }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); closeWrite(b) }()
	wg.Wait()
}

// closeWrite ends our sending half if the transport can, else the whole thing.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = c.Close()
}
