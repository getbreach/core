package qtun_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// Regression: a stream abandoned after an error reply used to keep its
// MAX_STREAMS slot forever, because Close() ends only the send half. After the
// default 100 refused CONNECTs the client's OpenStreamSync blocked for good —
// and KeepAlivePeriod meant the idle timeout never cleared it. A hundred failed
// connects is an ordinary afternoon of browsing (blocked ad domains, blackholed
// hosts), so this has to keep working well past the ceiling.
func TestFailedDialsDoNotExhaustStreams(t *testing.T) {
	echo := echoServer(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	for i := 0; i < 150; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := c.Open(ctx, "127.0.0.1:1") // refused, fast
		took := time.Since(start)
		cancel()
		if err == nil {
			t.Fatalf("dial %d: expected a refusal", i)
		}
		// A refusal is microseconds; seconds means OpenStreamSync sat waiting for
		// a stream slot that was never returned.
		if took > 2*time.Second {
			t.Fatalf("dial %d took %v: the stream slot was not released", i, took)
		}
	}

	// The connection must still be usable afterwards.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := c.Open(ctx, echo.Addr().String())
	if err != nil {
		t.Fatalf("connection unusable after 150 failed dials: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "alive" {
		t.Fatalf("got %q, %v", buf, err)
	}
}

// The same leak on the auth-failure path, which an attacker could drive.
func TestRejectedAuthDoesNotExhaustStreams(t *testing.T) {
	c := endToEnd(t, func(tok string) bool { return tok == "right" }, "wrong")
	for i := 0; i < 150; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := c.Open(ctx, "127.0.0.1:1")
		took := time.Since(start)
		cancel()
		if err == nil {
			t.Fatalf("open %d: expected a rejection", i)
		}
		if took > 2*time.Second {
			t.Fatalf("open %d took %v: the stream slot was not released", i, took)
		}
	}
}

// A client that finishes its request and shuts down its write side must still
// receive the response: tearing both directions down on the first EOF silently
// truncated every such protocol (HTTP/1.0 via `nc -N`, for one).
func TestHalfClosedRequestStillGetsResponse(t *testing.T) {
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
			go func() {
				defer c.Close()
				req, _ := io.ReadAll(c) // waits for the client's write shutdown
				_, _ = c.Write([]byte("RESPONSE-TO-" + string(req)))
			}()
		}
	}()

	c := endToEnd(t, func(string) bool { return true }, "tok")
	conn, err := c.Open(context.Background(), ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	type writeCloser interface{ CloseWrite() error }
	if err := conn.(writeCloser).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "RESPONSE-TO-PING" {
		t.Fatalf("half-closed request lost its response: got %q", got)
	}
}
