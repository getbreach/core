package hy2_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
)

func TestAuthenticationAndCertificate(t *testing.T) {
	addr, tls := hy2test.Server(t)
	for _, tc := range []struct {
		name, password string
		tls            hy2.TLSOptions
		success        bool
	}{
		{"pinned", "test-password", tls, true},
		{"bad-password", "incorrect", tls, false},
		{"bad-pin", "test-password", hy2.TLSOptions{CertSHA256: strings.Repeat("00", 32)}, false},
		{"untrusted-certificate", "test-password", hy2.TLSOptions{ServerName: "hy2.test"}, false},
		{"malformed-pin", "test-password", hy2.TLSOptions{CertSHA256: "invalid"}, false},
		{"ambiguous-tls", "test-password", hy2.TLSOptions{CertSHA256: tls.CertSHA256, Insecure: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pc, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			c, err := hy2.Dial(ctx, pc, addr, tc.password, tc.tls)
			if c != nil {
				defer c.Close()
			}
			if (err == nil) != tc.success {
				t.Fatalf("success=%v, error=%v", tc.success, err)
			}
			if !tc.success {
				if _, err := pc.WriteTo([]byte{1}, addr); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("failed dial did not close socket: %v", err)
				}
			}
		})
	}
}

func TestDialCancellationClosesSocket(t *testing.T) {
	blackhole, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blackhole.Close()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = hy2.Dial(ctx, pc, blackhole.LocalAddr(), "test", hy2.TLSOptions{ServerName: "hy2.test"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
	if _, err := pc.WriteTo([]byte{1}, blackhole.LocalAddr()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("socket leaked: %v", err)
	}
}

func TestUDPReadCancellationAndSessionClose(t *testing.T) {
	for _, mode := range []string{"cancel", "close-client"} {
		t.Run(mode, func(t *testing.T) {
			c := hy2test.Client(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			u, err := c.OpenUDP(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			done := make(chan error, 1)
			go func() { _, _, err := u.ReadFrom(ctx); done <- err }()
			if mode == "cancel" {
				cancel()
			} else {
				c.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("Receive succeeded after shutdown")
				}
			case <-time.After(time.Second):
				t.Fatal("Receive stuck on shutdown")
			}
		})
	}
}

func TestUnsupportedDatagramsReturnErrors(t *testing.T) {
	c := hy2test.Client(t)
	u, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	for _, size := range []int{0, 4096, 65507} {
		if err := u.WriteTo(make([]byte, size), "127.0.0.1:1234"); err == nil {
			t.Fatalf("size %d was silently accepted", size)
		}
	}
	u.Close()
	if err := u.WriteTo([]byte{1}, "127.0.0.1:1234"); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("send after close: %v", err)
	}
}
