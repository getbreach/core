package qtun_test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"breach/qtun"
	"breach/socks5"
)

// endToEnd wires a qtun server and client over a real loopback UDP pair, the way
// breach-server and breach-client will (there the PacketConn is the relay pool).
func endToEnd(t *testing.T, auth func(string) bool, token string) *qtun.Client {
	t.Helper()

	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, pin, err := qtun.ServerTLS(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		_ = qtun.Serve(ctx, srvPC, tlsConf, qtun.ServerOptions{Auth: auth, AllowPrivate: true})
	}()

	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliTLS, err := qtun.ClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	c, err := qtun.Dial(dctx, cliPC, srvPC.LocalAddr(), cliTLS, token)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// echoServer is the "internet" the exit dials out to.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return ln
}

func TestStreamReachesTarget(t *testing.T) {
	echo := echoServer(t)
	c := endToEnd(t, func(tok string) bool { return tok == "s3cret" }, "s3cret")

	conn, err := c.Open(context.Background(), echo.Addr().String())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("hello breach")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 12)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "hello breach" {
		t.Fatalf("got %q", buf)
	}
}

// The exit is reachable by anyone who can talk to the relay, so a wrong token
// must be refused rather than proxied.
func TestBadTokenRejected(t *testing.T) {
	echo := echoServer(t)
	c := endToEnd(t, func(tok string) bool { return tok == "s3cret" }, "wrong")

	_, err := c.Open(context.Background(), echo.Addr().String())
	if !errors.Is(err, qtun.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestUnreachableTargetReported(t *testing.T) {
	c := endToEnd(t, func(string) bool { return true }, "tok")
	// Port 1 on loopback: refused fast, no DNS involved.
	_, err := c.Open(context.Background(), "127.0.0.1:1")
	if err == nil {
		t.Fatal("want an error for an unreachable target")
	}
	if errors.Is(err, qtun.ErrAuth) {
		t.Fatalf("misreported as auth failure: %v", err)
	}
}

// Many concurrent streams share one QUIC connection — that is the whole point of
// using it, and a browser opens dozens at once.
func TestManyConcurrentStreams(t *testing.T) {
	echo := echoServer(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	const n = 24
	errc := make(chan error, n)
	for i := 0; i < n; i++ {
		go func(i int) {
			conn, err := c.Open(context.Background(), echo.Addr().String())
			if err != nil {
				errc <- err
				return
			}
			defer conn.Close()
			msg := strings.Repeat("x", 64)
			if _, err := conn.Write([]byte(msg)); err != nil {
				errc <- err
				return
			}
			buf := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			if _, err := io.ReadFull(conn, buf); err != nil {
				errc <- err
				return
			}
			errc <- nil
		}(i)
	}
	for i := 0; i < n; i++ {
		if err := <-errc; err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
	}
}

// A pinned client must refuse an exit whose certificate is not the pinned one —
// that pin is the only thing authenticating the exit.
func TestWrongPinRefused(t *testing.T) {
	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, _, err := qtun.ServerTLS(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = qtun.Serve(ctx, srvPC, tlsConf, qtun.ServerOptions{Auth: func(string) bool { return true }, AllowPrivate: true})
	}()

	// A pin belonging to a DIFFERENT identity.
	_, otherPin, err := qtun.ServerTLS(t.TempDir()+"/o.pem", t.TempDir()+"/ok.pem")
	if err != nil {
		t.Fatal(err)
	}
	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliTLS, err := qtun.ClientTLS(otherPin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 8*time.Second)
	defer dcancel()
	if _, err := qtun.Dial(dctx, cliPC, srvPC.LocalAddr(), cliTLS, "tok"); err == nil {
		t.Fatal("connected to an exit with the wrong certificate")
	}
}

// The full local path: browser -> SOCKS5 -> qtun -> exit -> target.
func TestSocks5ThroughTunnel(t *testing.T) {
	echo := echoServer(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = (&socks5.Server{Dialer: dialerFunc(c.Open)}).Serve(ctx, ln)
	}()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	// greeting: SOCKS5, one method, no auth
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 5 || resp[1] != 0 {
		t.Fatalf("bad method selection %v", resp)
	}

	// CONNECT to the echo server by IPv4
	host, portStr, _ := net.SplitHostPort(echo.Addr().String())
	ip := net.ParseIP(host).To4()
	var port uint16
	_, _ = fmtSscan(portStr, &port)
	req := []byte{5, 1, 0, 1}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		t.Fatal(err)
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil {
		t.Fatal(err)
	}
	if rep[1] != 0 {
		t.Fatalf("SOCKS5 reply code %d", rep[1])
	}

	if _, err := conn.Write([]byte("through socks")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 13)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != "through socks" {
		t.Fatalf("got %q", buf)
	}
}

type dialerFunc func(ctx context.Context, target string) (net.Conn, error)

func (f dialerFunc) DialTarget(ctx context.Context, target string) (net.Conn, error) {
	return f(ctx, target)
}

func fmtSscan(s string, out *uint16) (int, error) {
	var v int
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("bad port")
		}
		v = v*10 + int(r-'0')
	}
	*out = uint16(v)
	return 1, nil
}
