package routing

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"breach-nativecore/internal/hy2test"
	"breach-nativecore/outbound"
	"golang.org/x/net/dns/dnsmessage"
)

type rejectTunnel struct{}

func (rejectTunnel) DialTCP(context.Context, string) (net.Conn, error) {
	return nil, errors.New("tunnel unavailable")
}
func (rejectTunnel) OpenUDP(context.Context) (outbound.Datagrams, error) {
	return nil, errors.New("tunnel unavailable")
}
func router(t *testing.T, cfg Config, out outbound.Outbound, opts Options) *Router {
	t.Helper()
	r, e := New(cfg, out, opts)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { r.Close() })
	return r
}
func TestOrderedPolicy(t *testing.T) {
	r := router(t, Config{DefaultAction: "tunnel", Sets: map[string]Set{"geosite-test": {Domains: []string{"domain:example.com", "full:exact.test", "regexp:^api[0-9]+\\.test$"}}, "geoip-lan": {IPs: []string{"10.0.0.0/8", "fd00::/8"}}}, Rules: []Rule{
		{Domains: []string{"full:blocked.example.com"}, Action: "block"},
		{Domains: []string{"geosite:test"}, Ports: "443,8000-8010", Network: "tcp", Action: "direct"},
		{IPs: []string{"geoip:lan"}, Action: "direct"},
	}}, rejectTunnel{}, Options{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.8")}, nil
	}})
	for _, tc := range []struct{ target, network, want string }{
		{"blocked.example.com:443", "tcp", "block"}, {"WWW.EXAMPLE.COM.:443", "tcp", "direct"}, {"notexample.com:443", "tcp", "tunnel"},
		{"api12.test:8001", "tcp", "direct"}, {"x.exact.test:443", "tcp", "tunnel"}, {"example.com:443", "udp", "tunnel"},
		{"example.com:80", "tcp", "tunnel"}, {"10.2.3.4:123", "udp", "direct"}, {"[fd42::5]:22", "tcp", "direct"},
	} {
		t.Run(tc.target+tc.network, func(t *testing.T) {
			d, e := r.decide(context.Background(), tc.network, tc.target)
			if tc.want == "block" {
				if !errors.Is(e, ErrBlocked) {
					t.Fatal(e)
				}
				return
			}
			if e != nil || d.action != tc.want {
				t.Fatalf("%+v %v, want %s", d, e, tc.want)
			}
		})
	}
}
func TestInvalidPoliciesFailClosed(t *testing.T) {
	for _, cfg := range []Config{
		{DefaultAction: "oops"}, {Rules: []Rule{{Action: "oops"}}}, {Rules: []Rule{{Action: "direct", Ports: "0"}}},
		{Rules: []Rule{{Action: "direct", Ports: "100-1"}}}, {Rules: []Rule{{Action: "direct", Domains: []string{"geosite:missing"}}}},
		{Rules: []Rule{{Action: "direct", IPs: []string{"bad"}}}}, {Rules: []Rule{{Action: "direct", Domains: []string{"regexp:["}}}},
	} {
		if _, e := New(cfg, rejectTunnel{}, Options{}); e == nil {
			t.Fatalf("accepted %+v", cfg)
		}
	}
}
func TestTunnelFailureNeverFallsBack(t *testing.T) {
	r := router(t, Config{}, rejectTunnel{}, Options{})
	if _, e := r.DialTCP(context.Background(), "127.0.0.1:80"); e == nil || e.Error() != "tunnel unavailable" {
		t.Fatal(e)
	}
}
func tcpEcho(t *testing.T) string {
	ln, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}
func udpEcho(t *testing.T) string {
	pc, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := pc.ReadFrom(b)
			if e != nil {
				return
			}
			pc.WriteTo(b[:n], a)
		}
	}()
	return pc.LocalAddr().String()
}
func TestDirectProtectedAndBlockedTCP(t *testing.T) {
	target := tcpEcho(t)
	called := false
	r := router(t, Config{DefaultAction: "direct"}, rejectTunnel{}, Options{Control: func(string, string, syscall.RawConn) error { called = true; return errors.New("protect refused") }})
	if _, e := r.DialTCP(context.Background(), target); e == nil || !called {
		t.Fatal("unprotected socket used")
	}
	r = router(t, Config{DefaultAction: "direct"}, rejectTunnel{}, Options{})
	c, e := r.DialTCP(context.Background(), target)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	c.Write([]byte("hello"))
	b := make([]byte, 5)
	if _, e = io.ReadFull(c, b); e != nil || string(b) != "hello" {
		t.Fatal(e)
	}
	r.Close()
	if _, e = c.Write([]byte{1}); e == nil {
		t.Fatal("direct connection survived router close")
	}
}
func TestUDPChoosesEveryDestination(t *testing.T) {
	tunnel := hy2test.Client(t)
	directAddr, tunnelAddr := udpEcho(t), udpEcho(t)
	_, dp, _ := net.SplitHostPort(directAddr)
	r := router(t, Config{Rules: []Rule{{Ports: dp, Action: "direct"}, {Ports: "1", Action: "block"}}}, tunnel, Options{})
	u, e := r.OpenUDP(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for _, target := range []string{directAddr, tunnelAddr} {
		if e = u.WriteTo([]byte(target), target); e != nil {
			t.Fatal(e)
		}
		p, from, e := u.ReadFrom(ctx)
		if e != nil || from != target || string(p) != target {
			t.Fatalf("%q %s %v", p, from, e)
		}
	}
	if e = u.WriteTo([]byte{1}, "127.0.0.1:1"); !errors.Is(e, ErrBlocked) {
		t.Fatal(e)
	}
	r.Close()
	if _, _, e = u.ReadFrom(ctx); e == nil {
		t.Fatal("UDP survived close")
	}
}
func question(t *testing.T, name string, typ dnsmessage.Type) []byte {
	t.Helper()
	n, e := dnsmessage.NewName(name + ".")
	if e != nil {
		t.Fatal(e)
	}
	b, e := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 123, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}).Pack()
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func fakeAnswer(t *testing.T, r *Router, name string, typ dnsmessage.Type) netip.Addr {
	t.Helper()
	p, e := r.dns.answer(context.Background(), question(t, name, typ))
	if e != nil {
		t.Fatal(e)
	}
	var m dnsmessage.Message
	if e = m.Unpack(p); e != nil || m.RCode != 0 || len(m.Answers) != 1 {
		t.Fatalf("%+v %v", m, e)
	}
	switch v := m.Answers[0].Body.(type) {
	case *dnsmessage.AResource:
		return netip.AddrFrom4(v.A)
	case *dnsmessage.AAAAResource:
		return netip.AddrFrom16(v.AAAA)
	}
	t.Fatal("unexpected DNS answer")
	return netip.Addr{}
}
func TestFakeDNSPersistentRoutingAndUDPSource(t *testing.T) {
	state := filepath.Join(t.TempDir(), "fake.jsonl")
	cfg := Config{DefaultAction: "block", DNS: DNSConfig{FakeIP: true, StateFile: state}, Rules: []Rule{{Domains: []string{"domain:allowed.test"}, Action: "direct"}}}
	opts := Options{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}}
	r := router(t, cfg, rejectTunnel{}, opts)
	fake := fakeAnswer(t, r, "allowed.test", dnsmessage.TypeA)
	fake6 := fakeAnswer(t, r, "allowed.test", dnsmessage.TypeAAAA)
	blocked := fakeAnswer(t, r, "blocked.test", dnsmessage.TypeA)
	if _, e := r.DialTCP(context.Background(), net.JoinHostPort(blocked.String(), "443")); !errors.Is(e, ErrBlocked) {
		t.Fatal(e)
	}
	if _, e := r.DialTCP(context.Background(), "198.18.200.200:80"); e == nil {
		t.Fatal("unknown fake address escaped")
	}
	echo := udpEcho(t)
	_, port, _ := net.SplitHostPort(echo)
	u, e := r.OpenUDP(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	dst := net.JoinHostPort(fake.String(), port)
	if e = u.WriteTo([]byte("fake UDP"), dst); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, from, e := u.ReadFrom(ctx)
	if e != nil || from != dst || string(p) != "fake UDP" {
		t.Fatalf("%q %s %v", p, from, e)
	}
	r.Close()
	r = router(t, cfg, rejectTunnel{}, opts)
	if a := fakeAnswer(t, r, "allowed.test", dnsmessage.TypeA); a != fake {
		t.Fatalf("mapping changed %s -> %s", fake, a)
	}
	if a := fakeAnswer(t, r, "allowed.test", dnsmessage.TypeAAAA); a != fake6 {
		t.Fatal("IPv6 mapping changed")
	}
	// DNS over both local TCP and UDP never touches the unavailable tunnel.
	c, e := r.DialTCP(context.Background(), "1.1.1.1:53")
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	q := question(t, "tcp.test", dnsmessage.TypeA)
	c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(q))), q...))
	var size [2]byte
	if _, e = io.ReadFull(c, size[:]); e != nil {
		t.Fatal(e)
	}
	response := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, e = io.ReadFull(c, response); e != nil {
		t.Fatal(e)
	}
	u, e = r.OpenUDP(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer u.Close()
	if e = u.WriteTo(q, "8.8.8.8:53"); e != nil {
		t.Fatal(e)
	}
	p, _, e = u.ReadFrom(ctx)
	if e != nil || !bytes.Equal(p, response) {
		t.Fatal("TCP/UDP DNS disagree", e)
	}
}
func TestParallelFakeDNS(t *testing.T) {
	r := router(t, Config{DNS: DNSConfig{FakeIP: true}}, rejectTunnel{}, Options{})
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 20 {
				if _, e := r.dns.fakeIP("same.test", false); e != nil {
					t.Error(e)
				}
			}
		}()
	}
	wg.Wait()
	if len(r.dns.ids) != 1 {
		t.Fatal("duplicate allocations")
	}
}
