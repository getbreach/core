package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"breach-nativecore/internal/hy2test"
	"golang.org/x/net/proxy"
)

func TestRuntimeKeepsHy2AcrossInboundReplacementAndFailure(t *testing.T) {
	server := hy2test.NewServer(t)
	cfg := testConfig()
	cfg.Remote = server.Addr.String()
	cfg.TLS = server.TLS
	rt := NewRuntime(context.Background())
	defer rt.Close()
	monitor := &Monitor{}
	var auth atomic.Int32
	logf := func(f string, args ...any) {
		if strings.HasPrefix(f, "Hy2 authenticated") {
			auth.Add(1)
		}
	}
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, err := echo.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	var before Snapshot
	for i := 0; i < 3; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- rt.RunObserved(ctx, cfg, logf, monitor) }()
		stop := func() {
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Errorf("inbound stop: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("inbound did not stop")
			}
		}
		var snap Snapshot
		err = func() error {
			defer stop()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				snap = monitor.Snapshot()
				if snap.Phase == "online" {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if snap.Phase != "online" {
				return errors.New("inbound not ready")
			}
			d, err := proxy.SOCKS5("tcp", snap.Device, nil, &net.Dialer{Timeout: time.Second})
			if err != nil {
				return err
			}
			request, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			c, err := d.(proxy.ContextDialer).DialContext(request, "tcp", echo.Addr().String())
			if err != nil {
				return err
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Second))
			if _, err = c.Write([]byte("alive")); err != nil {
				return err
			}
			b := make([]byte, 5)
			if _, err = io.ReadFull(c, b); err != nil {
				return err
			}
			if string(b) != "alive" {
				return errors.New("wrong echo")
			}
			return nil
		}()
		if err != nil {
			t.Fatal(err)
		}
		after := monitor.Snapshot()
		if !after.Hy2.Connected || after.Hy2.Attempts != 1 || auth.Load() != 1 {
			t.Fatalf("transport replaced: %+v auth=%d", after.Hy2, auth.Load())
		}
		if i > 0 && (after.Started != before.Started || after.Wire.UpBytes <= before.Wire.UpBytes || after.Wire.DownBytes <= before.Wire.DownBytes) {
			t.Fatal("uptime or counters reset")
		}
		before = after
		cfg.SOCKSListen = snap.Device // Must release the exact same port before reusing it.
		// A real inbound setup failure must not tear down the shared transport.
		occupied, err := net.Listen("tcp", cfg.SOCKSListen)
		if err != nil {
			t.Fatal(err)
		}
		fail := rt.RunObserved(context.Background(), cfg, logf, monitor)
		occupied.Close()
		if fail == nil || !monitor.Snapshot().Hy2.Connected {
			t.Fatal("inbound failure destroyed Hy2")
		}
	}
	rt.Close()
	if monitor.Snapshot().Hy2.Connected {
		t.Fatal("transport survived owner shutdown")
	}
}
