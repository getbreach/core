package bridge

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"breach/qtun"
	"golang.org/x/net/dns/dnsmessage"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

// A second netstack plays the OS side of a TUN: actual IP/TCP/UDP packets cross
// the bridge. The qtun leg uses real loopback UDP and real TCP/UDP exit sockets.
type harness struct {
	bridge *Bridge
	os     *stack.Stack
	client *qtun.Client
	ctx    context.Context
}

// Keep loopback out of the IP packet path (a real network stack rejects it on
// a non-loopback NIC). Only the test's exit connector translates TEST-NET IPs
// to the local echo services; production QUICOutbound never rewrites targets.
type localOutbound struct{ QUICOutbound }

func mapEndpoint(address string, toLocal bool) string {
	host, port, _ := net.SplitHostPort(address)
	v4 := net.ParseIP(host).To4() != nil
	if toLocal {
		if v4 {
			host = "127.0.0.1"
		} else {
			host = "::1"
		}
	} else {
		if v4 {
			host = "198.19.0.1"
		} else {
			host = "2001:db8::1"
		}
	}
	return net.JoinHostPort(host, port)
}
func (o localOutbound) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	return o.QUICOutbound.DialTCP(ctx, mapEndpoint(target, true))
}
func (o localOutbound) OpenUDP(ctx context.Context) (Datagrams, error) {
	d, err := o.QUICOutbound.OpenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return localDatagrams{d}, nil
}

type localDatagrams struct{ Datagrams }

func (d localDatagrams) WriteTo(p []byte, target string) error {
	return d.Datagrams.WriteTo(p, mapEndpoint(target, true))
}
func (d localDatagrams) ReadFrom(ctx context.Context) ([]byte, string, error) {
	p, from, err := d.Datagrams.ReadFrom(ctx)
	if err != nil {
		return nil, "", err
	}
	return p, mapEndpoint(from, false), nil
}

func newHarness(t testing.TB, opts Options) *harness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	srv, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsServer, pin, err := qtun.ServerTLS("", "")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = qtun.Serve(ctx, srv, tlsServer, qtun.ServerOptions{Auth: func(s string) bool { return s == "test" }, AllowPrivate: true})
	}()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsClient, err := qtun.ClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	client, err := qtun.Dial(ctx, pc, srv.LocalAddr(), tlsClient, "test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); client.Close(); pc.Close(); srv.Close(); <-done })
	h := packetHarness(t, opts, localOutbound{QUICOutbound{Client: client}})
	h.client = client
	return h
}

func packetHarness(t testing.TB, opts Options, out Outbound) *harness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	b, err := New(out, opts)
	if err != nil {
		t.Fatal(err)
	}
	os := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	link := channel.New(256, 1280, "")
	if e := os.CreateNIC(1, link); e != nil {
		t.Fatal(e)
	}
	for _, addr := range []struct {
		address net.IP
		proto   tcpip.NetworkProtocolNumber
		prefix  int
	}{
		{net.ParseIP("198.18.0.2").To4(), ipv4.ProtocolNumber, 24},
		{net.ParseIP("fd42::2").To16(), ipv6.ProtocolNumber, 64},
	} {
		if e := os.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: addr.proto, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(addr.address), PrefixLen: addr.prefix}}, stack.AddressProperties{}); e != nil {
			t.Fatal(e)
		}
	}
	os.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	var pumps sync.WaitGroup
	pumps.Add(2)
	go func() {
		defer pumps.Done()
		for {
			pkt := link.ReadContext(ctx)
			if pkt == nil {
				return
			}
			v := pkt.ToView()
			_ = b.Inject(v.AsSlice())
			v.Release()
			pkt.DecRef()
		}
	}()
	go func() {
		defer pumps.Done()
		for {
			data, err := b.ReadPacket(ctx)
			if err != nil {
				return
			}
			proto := ipv4.ProtocolNumber
			if data[0]>>4 == 6 {
				proto = ipv6.ProtocolNumber
			}
			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(data)})
			link.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()
	t.Cleanup(func() {
		cancel()
		b.Close()
		os.Close()
		link.Close()
		os.Wait()
		pumps.Wait()
		if b.Stats().ActiveFlows != 0 {
			t.Error("bridge leaked flows")
		}
	})
	return &harness{bridge: b, os: os, ctx: ctx}
}

func endpoint(addr net.Addr) (tcpip.FullAddress, tcpip.NetworkProtocolNumber) {
	host, port, _ := net.SplitHostPort(mapEndpoint(addr.String(), false))
	ip := net.ParseIP(host)
	proto := ipv4.ProtocolNumber
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	} else {
		ip = ip.To16()
		proto = ipv6.ProtocolNumber
	}
	var p uint16
	for _, c := range port {
		p = p*10 + uint16(c-'0')
	}
	return tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFromSlice(ip), Port: p}, proto
}

func tcpEcho(t testing.TB, address string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", address)
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

func TestTCPPacketsThroughQUIC(t *testing.T) {
	for _, host := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(host, func(t *testing.T) {
			ln := tcpEcho(t, host)
			h := newHarness(t, Options{})
			addr, proto := endpoint(ln.Addr())
			c, err := gonet.DialContextTCP(h.ctx, h.os, addr, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(8 * time.Second))
			want := bytes.Repeat([]byte("native TCP"), 8192)
			written := make(chan error, 1)
			go func() {
				_, err := c.Write(want)
				if err == nil {
					err = c.CloseWrite()
				}
				written <- err
			}()
			got, err := io.ReadAll(c)
			if err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("TCP corruption: got %d bytes, want %d", len(got), len(want))
			}
			if s := h.bridge.Stats(); s.PacketsIn == 0 || s.PacketsOut == 0 {
				t.Fatal("test bypassed IP packet bridge")
			}
		})
	}
}

func udpEcho(t testing.TB, address string) net.PacketConn {
	t.Helper()
	c, err := net.ListenPacket("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			c.WriteTo(buf[:n], from)
		}
	}()
	return c
}

func TestUDPFlowsAndFragmentedReplies(t *testing.T) {
	testUDPFlows(t, newHarness, []int{0, 32, 1200, 4096})
}

func testUDPFlows(t *testing.T, makeHarness func(testing.TB, Options) *harness, sizes []int) {
	for _, host := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(host, func(t *testing.T) {
			echo := udpEcho(t, host)
			h := makeHarness(t, Options{})
			addr, proto := endpoint(echo.LocalAddr())
			// Concurrent flows to the SAME destination must not conflict on bind.
			for i := 0; i < 3; i++ {
				c, err := gonet.DialUDP(h.os, nil, &addr, proto)
				if err != nil {
					t.Fatal(err)
				}
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				for _, size := range sizes {
					want := bytes.Repeat([]byte{byte(i + 1)}, size)
					if _, err := c.Write(want); err != nil {
						t.Fatal(err)
					}
					buf := make([]byte, 8192)
					n, err := c.Read(buf)
					if err != nil {
						t.Fatalf("size %d: %v", size, err)
					}
					if !bytes.Equal(buf[:n], want) {
						t.Fatalf("datagram mismatch: %d/%d", n, size)
					}
				}
			}
		})
	}
}

func TestDNSUDPAndTCP(t *testing.T) { testDNS(t, newHarness) }

func testDNS(t *testing.T, makeHarness func(testing.TB, Options) *harness) {
	name := dnsmessage.MustNewName("native.test.")
	query, _ := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 42, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}).Pack()
	answer := func(p []byte) []byte {
		var m dnsmessage.Message
		if err := m.Unpack(p); err != nil {
			return nil
		}
		m.Response = true
		m.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 123}}}}
		out, _ := m.Pack()
		return out
	}
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, e := u.ReadFrom(buf)
			if e != nil {
				return
			}
			u.WriteTo(answer(buf[:n]), from)
		}
	}()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, e := ln.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(5 * time.Second))
		var size [2]byte
		if _, e := io.ReadFull(c, size[:]); e != nil {
			return
		}
		buf := make([]byte, binary.BigEndian.Uint16(size[:]))
		if _, e := io.ReadFull(c, buf); e != nil {
			return
		}
		resp := answer(buf)
		binary.BigEndian.PutUint16(size[:], uint16(len(resp)))
		c.Write(append(size[:], resp...))
	}()
	h := makeHarness(t, Options{})
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			var c net.Conn
			var err error
			if network == "udp" {
				a, p := endpoint(u.LocalAddr())
				c, err = gonet.DialUDP(h.os, nil, &a, p)
			} else {
				a, p := endpoint(ln.Addr())
				c, err = gonet.DialContextTCP(h.ctx, h.os, a, p)
			}
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			q := query
			if network == "tcp" {
				q = binary.BigEndian.AppendUint16(nil, uint16(len(q)))
				q = append(q, query...)
			}
			if _, err := c.Write(q); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4096)
			var n int
			if network == "tcp" {
				var l [2]byte
				if _, err := io.ReadFull(c, l[:]); err != nil {
					t.Fatal(err)
				}
				n, err = io.ReadFull(c, buf[:binary.BigEndian.Uint16(l[:])])
			} else {
				n, err = c.Read(buf)
			}
			if err != nil {
				t.Fatal(err)
			}
			var m dnsmessage.Message
			if err := m.Unpack(buf[:n]); err != nil {
				t.Fatal(err)
			}
			if !m.Response || m.ID != 42 || len(m.Answers) != 1 {
				t.Fatalf("bad DNS reply: %+v", m)
			}
		})
	}
}

func TestCloseUnblocksReadersAndFlows(t *testing.T) {
	h := newHarness(t, Options{})
	echo := udpEcho(t, "127.0.0.1:0")
	a, p := endpoint(echo.LocalAddr())
	u, err := gonet.DialUDP(h.os, nil, &a, p)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	u.Write([]byte("open"))
	buf := make([]byte, 4)
	if _, err := u.Read(buf); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { h.bridge.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked")
	}
	if _, err := h.bridge.ReadPacket(context.Background()); err == nil {
		t.Fatal("read after close succeeded")
	}
	if err := h.bridge.Inject([]byte{0x45}); err == nil {
		t.Fatal("inject after close succeeded")
	}
}

func TestUDPIdleExpiry(t *testing.T) {
	h := newHarness(t, Options{UDPIdleTimeout: 100 * time.Millisecond})
	echo := udpEcho(t, "127.0.0.1:0")
	a, p := endpoint(echo.LocalAddr())
	u, err := gonet.DialUDP(h.os, nil, &a, p)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(3 * time.Second))
	u.Write([]byte("idle"))
	buf := make([]byte, 4)
	if _, err := u.Read(buf); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for h.bridge.Stats().ActiveFlows != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.bridge.Stats().ActiveFlows != 0 {
		t.Fatal("idle UDP flow retained")
	}
}

func TestFlowLimitKeepsExistingFlow(t *testing.T) {
	h := newHarness(t, Options{MaxFlows: 1})
	echo := udpEcho(t, "127.0.0.1:0")
	a, p := endpoint(echo.LocalAddr())
	first, err := gonet.DialUDP(h.os, nil, &a, p)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	first.SetDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 16)
	first.Write([]byte("first"))
	if _, err := first.Read(buf); err != nil {
		t.Fatal(err)
	}
	second, err := gonet.DialUDP(h.os, nil, &a, p)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetDeadline(time.Now().Add(100 * time.Millisecond))
	second.Write([]byte("second"))
	if _, err := second.Read(buf); err == nil {
		t.Fatal("second flow exceeded budget")
	}
	first.Write([]byte("alive"))
	n, err := first.Read(buf)
	if err != nil || string(buf[:n]) != "alive" {
		t.Fatalf("first flow broken: %q %v", buf[:n], err)
	}
	if s := h.bridge.Stats(); s.ActiveFlows != 1 || s.RejectedFlows == 0 {
		t.Fatalf("flow accounting: %+v", s)
	}
}

type pipeOutbound struct{ peer net.Conn }

func (o *pipeOutbound) DialTCP(context.Context, string) (net.Conn, error) {
	a, b := net.Pipe()
	o.peer = b
	return a, nil
}
func (*pipeOutbound) OpenUDP(context.Context) (Datagrams, error) { return nil, net.ErrClosed }

func TestCloseDuringUnfinishedTCPHandshake(t *testing.T) {
	o := &pipeOutbound{}
	b, err := New(o, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	p := make([]byte, 40)
	src := tcpip.AddrFrom4([4]byte{198, 18, 0, 2})
	dst := tcpip.AddrFrom4([4]byte{198, 19, 0, 1})
	ip := header.IPv4(p[:20])
	ip.Encode(&header.IPv4Fields{TotalLength: 40, TTL: 64, Protocol: uint8(tcp.ProtocolNumber), SrcAddr: src, DstAddr: dst})
	ip.SetChecksum(^ip.CalculateChecksum())
	tc := header.TCP(p[20:])
	tc.Encode(&header.TCPFields{SrcPort: 12345, DstPort: 80, SeqNum: 1, DataOffset: 20, Flags: header.TCPFlagSyn, WindowSize: 65535})
	tc.SetChecksum(^checksum.Checksum(p[20:], header.PseudoHeaderChecksum(tcp.ProtocolNumber, src, dst, 20)))
	if err := b.Inject(p); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := b.ReadPacket(ctx); err != nil {
		t.Fatal("no SYN-ACK:", err)
	}
	// Never ACK the SYN-ACK. Close must abort the pending handshake immediately.
	done := make(chan struct{})
	go func() { b.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close waited for SYN retransmission timeout")
	}
	if o.peer != nil {
		o.peer.Close()
	}
}

func BenchmarkTCPPacketBridge(b *testing.B) {
	ln := tcpEcho(b, "127.0.0.1:0")
	h := newHarness(b, Options{})
	a, p := endpoint(ln.Addr())
	c, err := gonet.DialContextTCP(h.ctx, h.os, a, p)
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("x"), 32*1024)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, got); err != nil {
			b.Fatal(err)
		}
	}
}

// Same qtun/echo leg and payload as the packet benchmark, without TCP/IP/TUN.
func BenchmarkTCPDirectQUIC(b *testing.B) {
	ln := tcpEcho(b, "127.0.0.1:0")
	h := newHarness(b, Options{})
	c, err := h.client.Open(h.ctx, ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	defer c.Close()
	payload := bytes.Repeat([]byte("x"), 32*1024)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(c, got); err != nil {
			b.Fatal(err)
		}
	}
}
