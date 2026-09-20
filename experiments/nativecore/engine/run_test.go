package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
	"golang.org/x/net/proxy"
)

func testConfig() Config {
	return Config{Mode: "direct", Remote: "127.0.0.1:443", Password: "test-password", TLS: hy2.TLSOptions{ServerName: "hy2.test"}, Inbound: "socks", SOCKSListen: "127.0.0.1:0", MTU: 1280, StartupTimeoutSeconds: 5}
}

func TestConfigValidation(t *testing.T) {
	c := testConfig()
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Mode = "turn"
	c.Remote = ""
	c.Turn = json.RawMessage(`{"token":"test","deviceId":"test","server":"127.0.0.1:48000","wgListen":"0.0.0.0:51821"}`)
	b, e := c.turnJSON()
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(b, `"wgListen":"127.0.0.1:0"`) {
		t.Fatal("public mouth was not replaced")
	}
	c.Turn = json.RawMessage(`{"server":"127.0.0.1:48000","socks":"127.0.0.1:1080"}`)
	if c.Validate() == nil {
		t.Fatal("legacy remote SOCKS accepted")
	}
	c = testConfig()
	c.Inbound = "tun"
	if c.Validate() == nil {
		t.Fatal("outer TUN loop not rejected")
	}
	c = testConfig()
	c.Password = ""
	if c.Validate() == nil {
		t.Fatal("missing authentication accepted")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if e = os.WriteFile(path, []byte(`{"mode":"direct","remote":"127.0.0.1:443","password":"p","tls":{"serverName":"test"},"unknown":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Load(path, "turn"); e == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestSOCKSListenerSurvivesRealServerRestart(t *testing.T) {
	s := hy2test.NewServer(t)
	c := testConfig()
	c.Remote = s.Addr.String()
	c.TLS = s.TLS
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	ready := make(chan string, 1)
	auth := make(chan struct{}, 10)
	monitor := &Monitor{}
	go func() {
		done <- RunObserved(ctx, c, func(format string, args ...any) {
			line := fmt.Sprintf(format, args...)
			if strings.HasPrefix(line, "SOCKS5 ready on ") {
				ready <- strings.Fields(line)[3]
			}
			if strings.HasPrefix(line, "Hy2 authenticated") {
				auth <- struct{}{}
			}
		}, monitor)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if !errors.Is(e, context.Canceled) {
				t.Errorf("shutdown: %v", e)
			}
			if s := monitor.Snapshot(); s.Phase != "stopped" || s.Hy2.Connected {
				t.Errorf("stale status after shutdown: %+v", s)
			}
		case <-time.After(5 * time.Second):
			t.Error("engine shutdown stuck")
		}
	})
	var address string
	select {
	case address = <-ready:
	case e := <-done:
		t.Fatalf("startup: %v", e)
	case <-time.After(8 * time.Second):
		t.Fatal("startup timed out")
	}
	<-auth
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
	check := func() {
		d, e := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 5 * time.Second})
		if e != nil {
			t.Fatal(e)
		}
		qctx, qcancel := context.WithTimeout(ctx, 5*time.Second)
		defer qcancel()
		conn, e := d.(proxy.ContextDialer).DialContext(qctx, "tcp", echo.Addr().String())
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(time.Second))
		conn.Write([]byte("roundtrip"))
		b := make([]byte, 9)
		if _, e = io.ReadFull(conn, b); e != nil || string(b) != "roundtrip" {
			t.Fatalf("SOCKS echo: %q %v", b, e)
		}
	}
	check()
	first := monitor.Snapshot()
	if first.Phase != "online" || first.Device != address || first.Wire.UpBytes == 0 || first.Wire.DownBytes == 0 {
		t.Fatalf("missing live telemetry: %+v", first)
	}
	s.Stop()
	// Restart on the same port. The old QUIC connection is unknown to the new
	// server; the client must detect loss and authenticate a fresh connection.
	s.Start()
	select {
	case <-auth:
	case <-time.After(45 * time.Second):
		t.Fatal("no automatic reconnect")
	}
	check()
	last := monitor.Snapshot()
	if last.Hy2.Reconnects == 0 || last.Wire.UpBytes <= first.Wire.UpBytes || last.Wire.DownBytes <= first.Wire.DownBytes {
		t.Fatalf("telemetry reset across reconnect: before=%+v after=%+v", first, last)
	}
}

func TestAuthenticationFailuresStopWithoutListener(t *testing.T) {
	s := hy2test.NewServer(t)
	for _, which := range []string{"password", "pin", "ca"} {
		t.Run(which, func(t *testing.T) {
			c := testConfig()
			c.Remote = s.Addr.String()
			c.TLS = s.TLS
			want := "authentication error"
			switch which {
			case "password":
				c.Password = "wrong"
			case "pin":
				c.TLS.CertSHA256 = strings.Repeat("0", 64)
				want = "pin mismatch"
			case "ca":
				c.TLS.CertSHA256 = ""
				want = "certificate"
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			err := Run(ctx, c, t.Logf)
			if err == nil || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestCancelDuringAuthentication(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	c := testConfig()
	c.Remote = pc.LocalAddr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, c, nil) }()
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("authentication did not cancel")
	}
}
