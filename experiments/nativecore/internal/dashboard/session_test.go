package dashboard

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"breach-nativecore/engine"
	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
)

func switchConfig() engine.Config {
	return engine.Config{Mode: "direct", Remote: "127.0.0.1:443", Password: "test-password", TLS: hy2.TLSOptions{ServerName: "hy2.test"}, Inbound: "tun", Interface: "auto", DirectInterface: "", SOCKSListen: "127.0.0.1:0", MTU: 1280, StartupTimeoutSeconds: 5}
}
func discardLog(string, ...any) {}
func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for engine")
		var zero T
		return zero
	}
}

func TestSwitchWaitsForCleanupAndQuitCancelsPendingStart(t *testing.T) {
	started := make(chan string, 3)
	cleaning := make(chan struct{}, 3)
	release := make(chan struct{}, 3)
	runner := func(ctx context.Context, cfg engine.Config, _ func(string, ...any), _ *engine.Monitor) error {
		started <- cfg.Inbound
		<-ctx.Done()
		cleaning <- struct{}{}
		<-release
		return ctx.Err()
	}
	cfg := switchConfig()
	cfg.DirectInterface = "auto"
	s := newSession(context.Background(), cfg, discardLog, runner)
	defer func() { release <- struct{}{}; s.close() }()
	if receive(t, started) != "tun" {
		t.Fatal("wrong initial mode")
	}
	s.switchMode(true, true)
	receive(t, cleaning)
	s.switchMode(true, true)
	select {
	case <-started:
		t.Fatal("started before route/DNS cleanup")
	default:
	}
	select {
	case <-s.done:
		t.Fatal("cleanup was not awaited")
	default:
	}
	release <- struct{}{}
	s.finished(receive(t, s.done))
	if receive(t, started) != "socks" || s.cfg.AutoRoute {
		t.Fatal("incorrect proxy mode")
	}
	s.transition = "" // The fake runner has no network monitor/readiness event.
	s.switchMode(true, true)
	receive(t, cleaning)
	s.stop()
	release <- struct{}{}
	s.finished(receive(t, s.done))
	select {
	case <-started:
		t.Fatal("started another engine after quit")
	default:
	}
	if s.done != nil || s.pending != nil {
		t.Fatal("shutdown retained pending work")
	}
}

func TestSwitchPreflightDoesNotStopProxy(t *testing.T) {
	cfg := switchConfig()
	s := &session{base: cfg, cfg: cfg, monitor: &engine.Monitor{}, logf: discardLog}
	s.cfg.Inbound = "socks"
	canceled := false
	s.cancel = func() { canceled = true }
	s.switchMode(false, true)
	if canceled || !strings.Contains(s.notice, "sudo") {
		t.Fatal("root preflight interrupted proxy")
	}
	s.switchMode(true, false)
	if canceled || !strings.Contains(s.notice, "macOS") {
		t.Fatal("platform preflight interrupted proxy")
	}
	s.base = s.cfg
	s.switchMode(true, true)
	if canceled || !strings.Contains(s.notice, "stateFile") {
		t.Fatal("missing TUN configuration interrupted proxy")
	}
}

func TestModeProfilesPreserveTUNSettings(t *testing.T) {
	cfg := switchConfig()
	cfg.AutoRoute = true
	cfg.Routing.DNS.FakeIP = true
	cfg.Routing.DNS.StateFile = filepath.Join(t.TempDir(), "fakeip.jsonl")
	s := &session{base: cfg, cfg: cfg}
	proxy, err := s.target(true, true)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.AutoRoute || proxy.Inbound != "socks" || proxy.Routing.DNS.StateFile != cfg.Routing.DNS.StateFile {
		t.Fatal("proxy profile damaged shared settings")
	}
	s.cfg = proxy
	if tun, err := s.target(true, true); err == nil {
		if !tun.AutoRoute || tun.Interface != cfg.Interface || tun.Routing.DNS.StateFile != cfg.Routing.DNS.StateFile {
			t.Fatal("TUN profile lost on round trip")
		}
	} else if !strings.Contains(err.Error(), "only on macOS") {
		t.Fatal(err)
	}
	if s.base.Inbound != "tun" || !s.base.AutoRoute {
		t.Fatal("base config mutated")
	}
}

func waitOnline(t *testing.T, s *session) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.snapshot().Phase == "online" {
			return
		}
		select {
		case err := <-s.done:
			s.finished(err)
			t.Fatalf("engine stopped: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("engine did not become online")
}

func TestFailedSwitchRestoresRealSOCKSListener(t *testing.T) {
	server := hy2test.NewServer(t)
	shared := engine.NewRuntime(context.Background())
	defer shared.Close()
	cfg := switchConfig()
	cfg.Remote = server.Addr.String()
	cfg.TLS = server.TLS
	// The previous/restored proxies use real Hy2. Only TUN startup is replaced
	// with a failure, so this regression test never changes kernel routes.
	runner := func(ctx context.Context, c engine.Config, logf func(string, ...any), m *engine.Monitor) error {
		if c.Inbound == "tun" {
			return errors.New("test TUN setup failure")
		}
		return shared.RunObserved(ctx, c, logf, m)
	}
	cfg.Inbound = "socks"
	s := newSession(context.Background(), cfg, discardLog, runner)
	defer s.close()
	waitOnline(t, s)
	before := s.snapshot()
	original := before.Device
	s.cfg.SOCKSListen = original
	s.base.Inbound = "tun"
	s.base.DirectInterface = "auto"
	s.switchMode(true, true)
	s.finished(receive(t, s.done))
	if s.cfg.Inbound != "tun" {
		t.Fatal("target did not start")
	}
	s.finished(receive(t, s.done))
	waitOnline(t, s)
	if s.cfg.Inbound != "socks" || s.snapshot().Device != original || !strings.Contains(s.notice, "test TUN setup failure") {
		t.Fatal("failed to restore proxy after TUN error")
	}
	if after := s.snapshot(); after.Hy2.Attempts != before.Hy2.Attempts || after.Started != before.Started {
		t.Fatal("rollback replaced shared transport")
	}
	conn, err := net.DialTimeout("tcp", original, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	if _, err = conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 2)
	if _, err = io.ReadFull(conn, reply); err != nil || reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("restored SOCKS handshake: %v %v", reply, err)
	}
}
