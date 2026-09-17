//go:build linux && !android

// Package integration tests the real Linux kernel -> TUN -> netstack -> Hy2
// path. The test must run inside a NEW network namespace (see scripts/linux-tun.sh).
package integration

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"breach-nativecore/bridge"
	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
	"breach-nativecore/packetio"
	"golang.org/x/net/dns/dnsmessage"
)

// TEST-NET destinations terminate at local fixtures after traversing Hy2.
// This substitution exists only in the test, never in the production bridge.
type fixtureOutbound struct{ *hy2.Client }

func fixtureAddress(target string) string {
	h, p, _ := net.SplitHostPort(target)
	if net.ParseIP(h).To4() != nil {
		h = "127.0.0.1"
	} else {
		h = "::1"
	}
	return net.JoinHostPort(h, p)
}
func virtualAddress(target string) string {
	h, p, _ := net.SplitHostPort(target)
	if net.ParseIP(h).To4() != nil {
		h = "198.19.0.1"
	} else {
		h = "2001:db8::1"
	}
	return net.JoinHostPort(h, p)
}
func (o fixtureOutbound) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	return o.Client.DialTCP(ctx, fixtureAddress(target))
}
func (o fixtureOutbound) OpenUDP(ctx context.Context) (bridge.Datagrams, error) {
	d, e := o.Client.OpenUDP(ctx)
	if e != nil {
		return nil, e
	}
	return fixtureUDP{d}, nil
}

type fixtureUDP struct{ bridge.Datagrams }

func (d fixtureUDP) WriteTo(p []byte, target string) error {
	return d.Datagrams.WriteTo(p, fixtureAddress(target))
}
func (d fixtureUDP) ReadFrom(ctx context.Context) ([]byte, string, error) {
	p, a, e := d.Datagrams.ReadFrom(ctx)
	if e != nil {
		return nil, "", e
	}
	return p, virtualAddress(a), nil
}

func TestLinuxTUN(t *testing.T) {
	if os.Getenv("BREACH_NATIVE_TUN_TEST") != "1" {
		t.Skip("use scripts/linux-tun.sh in an isolated Linux namespace")
	}
	if os.Geteuid() != 0 {
		t.Fatal("test needs root in an isolated network namespace")
	}
	// Reject an ordinary host/container namespace, even when the env is set.
	links, err := exec.Command("ip", "-o", "link", "show").Output()
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Split(strings.TrimSpace(string(links)), "\n"); len(lines) != 1 || !strings.Contains(lines[0], ": lo:") {
		t.Fatal("refusing to change a namespace containing interfaces other than lo")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, e := exec.Command("ip", args...).CombinedOutput(); e != nil {
			t.Fatalf("ip %v: %v: %s", args, e, out)
		}
	}
	ip("link", "set", "lo", "up")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := hy2test.Client(t)
	b, err := bridge.New(fixtureOutbound{c}, bridge.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	tun, err := packetio.OpenTUN("breachtest0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- packetio.Run(ctx, b, tun) }()
	defer func() {
		cancel()
		tun.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("packet pump failed to stop")
		}
	}()
	ip("link", "set", tun.Name(), "mtu", "1280", "up")
	ip("addr", "add", "198.18.0.1/24", "dev", tun.Name())
	ip("-6", "addr", "add", "fd42::1/64", "dev", tun.Name(), "nodad")
	ip("route", "add", "198.19.0.1/32", "dev", tun.Name())
	ip("-6", "route", "add", "2001:db8::1/128", "dev", tun.Name())
	for _, host := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(host, func(t *testing.T) {
			ln, err := net.Listen("tcp", host)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			go func() {
				s, e := ln.Accept()
				if e != nil {
					return
				}
				defer s.Close()
				s.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(s, s)
			}()
			tcpConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", virtualAddress(ln.Addr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer tcpConn.Close()
			tcpConn.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte("linux TUN"), 1024)
			written := make(chan error, 1)
			go func() {
				_, e := tcpConn.Write(want)
				written <- e
			}()
			got := make([]byte, len(want))
			_, err = io.ReadFull(tcpConn, got)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("TCP payload mismatch")
			}
			u, err := net.ListenPacket("udp", host)
			if err != nil {
				t.Fatal(err)
			}
			defer u.Close()
			go func() {
				buf := make([]byte, 8192)
				for {
					n, from, e := u.ReadFrom(buf)
					if e != nil {
						return
					}
					u.WriteTo(buf[:n], from)
				}
			}()
			udpConn, err := net.Dial("udp", virtualAddress(u.LocalAddr().String()))
			if err != nil {
				t.Fatal(err)
			}
			defer udpConn.Close()
			udpConn.SetDeadline(time.Now().Add(5 * time.Second))
			want = bytes.Repeat([]byte("u"), 3000)
			if _, err := udpConn.Write(want); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 8192)
			n, err := udpConn.Read(buf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], want) {
				t.Fatal("UDP fragment/reassembly mismatch")
			}
		})
	}
	// A kernel DNS client using port 53 traverses the same TUN and Hy2 path.
	dns, err := net.ListenPacket("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, e := dns.ReadFrom(buf)
			if e != nil {
				return
			}
			var m dnsmessage.Message
			if m.Unpack(buf[:n]) != nil || len(m.Questions) == 0 {
				continue
			}
			m.Response = true
			m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: m.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 123}}}}
			p, e := m.Pack()
			if e == nil {
				dns.WriteTo(p, from)
			}
		}
	}()
	resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, "198.19.0.1:53")
	}}
	ips, err := resolver.LookupNetIP(ctx, "ip4", "native.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0].String() != "192.0.2.123" {
		t.Fatalf("DNS answer: %v", ips)
	}
	if stats := b.Stats(); stats.PacketsIn == 0 || stats.PacketsOut == 0 {
		t.Fatal("kernel bypassed TUN")
	}
}
