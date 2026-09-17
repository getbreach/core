package bridge

import (
	"context"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"breach-nativecore/internal/hy2test"
	"breach-nativecore/routing"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

// Actual IP packets enter the DNS interceptor, obtain a fake address, and then
// use that address for both TCP and UDP through the real Hy2 server.
func TestRoutedFakeDNSPackets(t *testing.T) {
	tunnel := hy2test.Client(t)
	router, e := routing.New(routing.Config{DefaultAction: "block", DNS: routing.DNSConfig{FakeIP: true}, Rules: []routing.Rule{{Domains: []string{"domain:allowed.test"}, IPs: []string{"127.0.0.1/32"}, Action: "tunnel"}}}, tunnel, routing.Options{Resolve: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
	}})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { router.Close() })
	h := packetHarness(t, Options{}, router)
	// endpoint() rewrites loopback fixture addresses into non-loopback IPs.
	dnsAddr, proto := endpoint(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	c, e := gonet.DialUDP(h.os, nil, &dnsAddr, proto)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	q, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 7, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("allowed.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	c.Write(q)
	buf := make([]byte, 4096)
	n, e := c.Read(buf)
	if e != nil {
		t.Fatal(e)
	}
	var reply dnsmessage.Message
	if e = reply.Unpack(buf[:n]); e != nil || len(reply.Answers) != 1 {
		t.Fatalf("DNS: %v", e)
	}
	fake := reply.Answers[0].Body.(*dnsmessage.AResource).A
	tcpTarget := tcpEcho(t, "127.0.0.1:0")
	addr, _ := endpoint(tcpTarget.Addr())
	ip := netip.AddrFrom4(fake)
	// Build a netstack address without using fixture rewriting again.
	addr.Addr = tcpip.AddrFrom4(ip.As4())
	tcp, e := gonet.DialContextTCP(h.ctx, h.os, addr, proto)
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	tcp.SetDeadline(time.Now().Add(3 * time.Second))
	tcp.Write([]byte("routed"))
	got := make([]byte, 6)
	if _, e = io.ReadFull(tcp, got); e != nil || string(got) != "routed" {
		t.Fatal("TCP", e)
	}
	udpTarget := udpEcho(t, "127.0.0.1:0")
	ua, up := endpoint(udpTarget.LocalAddr())
	ua.Addr = tcpip.AddrFrom4(ip.As4())
	udp, e := gonet.DialUDP(h.os, nil, &ua, up)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	udp.SetDeadline(time.Now().Add(3 * time.Second))
	udp.Write([]byte("reply to fake source"))
	n, e = udp.Read(buf)
	if e != nil || string(buf[:n]) != "reply to fake source" {
		t.Fatal("UDP fake source mapping", e)
	}
}
