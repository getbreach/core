package reconnect_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
	"breach-nativecore/reconnect"
	"breach-nativecore/transport"
)

func eventually(t *testing.T, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(40 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRetryCancellationAndPermanentError(t *testing.T) {
	var calls atomic.Int32
	r := reconnect.New(context.Background(), func(ctx context.Context) (reconnect.Session, error) { calls.Add(1); return nil, errors.New("offline") }, reconnect.Options{MinBackoff: 10 * time.Millisecond, MaxBackoff: 20 * time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Millisecond)
	defer cancel()
	if err := r.WaitReady(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait: %v", err)
	}
	r.Close()
	if calls.Load() < 2 {
		t.Fatal("no retry")
	}
	n := calls.Load()
	time.Sleep(30 * time.Millisecond)
	if calls.Load() != n {
		t.Fatal("retry after close")
	}
	sentinel := errors.New("bad password")
	calls.Store(0)
	r = reconnect.New(context.Background(), func(context.Context) (reconnect.Session, error) { calls.Add(1); return nil, sentinel }, reconnect.Options{Permanent: func(e error) bool { return errors.Is(e, sentinel) }})
	defer r.Close()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := r.WaitReady(ctx2); !errors.Is(err, sentinel) {
		t.Fatalf("permanent error: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatal("retried permanent failure")
	}
}

func TestCloseCancelsDialAndWaitingFlow(t *testing.T) {
	started := make(chan struct{})
	r := reconnect.New(context.Background(), func(ctx context.Context) (reconnect.Session, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}, reconnect.Options{})
	<-started
	done := make(chan error, 1)
	go func() { _, e := r.DialTCP(context.Background(), "test:443"); done <- e }()
	r.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unexpected success")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting flow not released")
	}
}

func TestRealServerRestartAndNetworkReset(t *testing.T) {
	s := hy2test.NewServer(t)
	// Copy immutable values: restarting the test server updates s.Addr.
	addr, tls := s.Addr.String(), s.TLS
	r := reconnect.New(context.Background(), func(ctx context.Context) (reconnect.Session, error) {
		pc, peer, e := transport.Open(addr, "direct")
		if e != nil {
			return nil, e
		}
		return hy2.Dial(ctx, pc, peer, "test-password", tls)
	}, reconnect.Options{MinBackoff: 20 * time.Millisecond, MaxBackoff: 50 * time.Millisecond, DialTimeout: 300 * time.Millisecond, Logf: t.Logf})
	defer r.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if e := r.WaitReady(ctx); e != nil {
		t.Fatal(e)
	}
	echo, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	udp, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			udp.WriteTo(buf[:n], from)
		}
	}()
	check := func() {
		c, e := r.DialTCP(ctx, echo.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(time.Second))
		if _, e = c.Write([]byte("hello")); e != nil {
			t.Fatal(e)
		}
		b := make([]byte, 5)
		if _, e = io.ReadFull(c, b); e != nil || string(b) != "hello" {
			t.Fatalf("echo=%q %v", b, e)
		}
		u, e := r.OpenUDP(ctx)
		if e != nil {
			t.Fatal(e)
		}
		defer u.Close()
		if e = u.WriteTo([]byte("udp"), udp.LocalAddr().String()); e != nil {
			t.Fatal(e)
		}
		uCtx, uCancel := context.WithTimeout(ctx, time.Second)
		defer uCancel()
		p, from, e := u.ReadFrom(uCtx)
		if e != nil || string(p) != "udp" || from != udp.LocalAddr().String() {
			t.Fatalf("UDP echo=%q from=%s: %v", p, from, e)
		}
	}
	check()
	s.Stop()
	eventually(t, func() bool { return !r.Status().Connected })
	eventually(t, func() bool { return r.Status().Attempts >= 2 })
	s.Start()
	if e = r.WaitReady(ctx); e != nil {
		t.Fatal(e)
	}
	check()
	before := r.Status().Reconnects
	r.Reset()
	if e = r.WaitReady(ctx); e != nil {
		t.Fatal(e)
	}
	if r.Status().Reconnects <= before {
		t.Fatal("network reset did not replace session")
	}
	check()
}

func TestResetCancelsInFlightDial(t *testing.T) {
	first := make(chan struct{})
	var calls atomic.Int32
	r := reconnect.New(context.Background(), func(ctx context.Context) (reconnect.Session, error) {
		if calls.Add(1) == 1 {
			close(first)
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return nil, errors.New("offline")
	}, reconnect.Options{MinBackoff: time.Second})
	defer r.Close()
	<-first
	r.Reset()
	eventually(t, func() bool { return calls.Load() >= 2 })
}
