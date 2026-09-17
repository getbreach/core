// Package bridge is the experimental, OS-independent IP packet entry point.
// TCP/IP is terminated locally and TCP/UDP are handed to the tunnel outbound.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"breach-nativecore/outbound"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Outbound has no dependency on TUN descriptors or a particular OS.
// Implementations must honor ctx and return connections that Close unblocks.
type Outbound = outbound.Outbound
type Datagrams = outbound.Datagrams

type Options struct {
	MTU            int
	MaxFlows       int
	UDPIdleTimeout time.Duration
	DialTimeout    time.Duration
}

type Stats struct {
	PacketsIn     uint64
	PacketsOut    uint64
	ActiveFlows   int
	RejectedFlows uint64
}

// Bridge owns its netstack and flows, but does not own the Outbound.
// Inject copies its input; ReadPacket returns bytes owned by the caller.
// These methods also support Apple's packetFlow without extracting a private fd.
type Bridge struct {
	stack              *stack.Stack
	link               *channel.Endpoint
	out                Outbound
	opts               Options
	ctx                context.Context
	cancel             context.CancelFunc
	injectMu           sync.Mutex
	mu                 sync.Mutex
	closed             bool
	flows              int
	wg                 sync.WaitGroup
	once               sync.Once
	in, sent, rejected atomic.Uint64
}

func New(out Outbound, opts Options) (*Bridge, error) {
	if out == nil {
		return nil, errors.New("bridge: outbound is required")
	}
	if opts.MTU == 0 {
		opts.MTU = 1280
	}
	if opts.MaxFlows == 0 {
		opts.MaxFlows = 256
	}
	if opts.UDPIdleTimeout == 0 {
		opts.UDPIdleTimeout = 30 * time.Second
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = 10 * time.Second
	}
	if opts.MTU < 1280 || opts.MTU > 65535 || opts.MaxFlows < 1 || opts.UDPIdleTimeout < 0 || opts.DialTimeout < 0 {
		return nil, errors.New("bridge: invalid MTU, flow limit or timeout")
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &Bridge{out: out, opts: opts, ctx: ctx, cancel: cancel}
	b.link = channel.New(256, uint32(opts.MTU), "")
	b.stack = stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := b.stack.CreateNIC(1, b.link); err != nil {
		b.Close()
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	// TUN packets target arbitrary internet addresses, none assigned to this NIC.
	if err := b.stack.SetPromiscuousMode(1, true); err != nil {
		b.Close()
		return nil, fmt.Errorf("promiscuous: %s", err)
	}
	if err := b.stack.SetSpoofing(1, true); err != nil {
		b.Close()
		return nil, fmt.Errorf("spoofing: %s", err)
	}
	b.stack.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	fwd := tcp.NewForwarder(b.stack, 0, opts.MaxFlows, b.handleTCP)
	b.stack.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)
	b.stack.SetTransportProtocolHandler(udp.ProtocolNumber, b.handleUDP)
	return b, nil
}

func (b *Bridge) Inject(packet []byte) error {
	b.injectMu.Lock()
	defer b.injectMu.Unlock()
	if b.ctx.Err() != nil {
		return net.ErrClosed
	}
	if len(packet) == 0 || len(packet) > b.opts.MTU {
		return errors.New("bridge: invalid packet length")
	}
	var proto tcpip.NetworkProtocolNumber
	switch packet[0] >> 4 {
	case 4:
		proto = ipv4.ProtocolNumber
	case 6:
		proto = ipv6.ProtocolNumber
	default:
		return errors.New("bridge: expected IPv4 or IPv6 packet")
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
	defer pkt.DecRef()
	b.link.InjectInbound(proto, pkt)
	b.in.Add(1)
	return nil
}

func (b *Bridge) ReadPacket(ctx context.Context) ([]byte, error) {
	pkt := b.link.ReadContext(ctx)
	if pkt == nil {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return nil, net.ErrClosed
	}
	defer pkt.DecRef()
	v := pkt.ToView()
	defer v.Release()
	b.sent.Add(1)
	return append([]byte(nil), v.AsSlice()...), nil
}

func (b *Bridge) Stats() Stats {
	b.mu.Lock()
	active := b.flows
	b.mu.Unlock()
	return Stats{b.in.Load(), b.sent.Load(), active, b.rejected.Load()}
}

func (b *Bridge) begin() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed || b.flows >= b.opts.MaxFlows {
		b.rejected.Add(1)
		return false
	}
	b.flows++
	b.wg.Add(1)
	return true
}

func (b *Bridge) end() { b.mu.Lock(); b.flows--; b.mu.Unlock(); b.wg.Done() }

func (b *Bridge) Close() error {
	b.once.Do(func() {
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		b.cancel()
		b.injectMu.Lock()
		// Forwarder.CreateEndpoint registers a TCP endpoint asynchronously and
		// waits for its SYN handshake. Abort until admitted workers have exited:
		// a single Stack.Close snapshot can miss an endpoint registered just after
		// that snapshot and leave shutdown waiting for a SYN retransmit timeout.
		done := make(chan struct{})
		go func() { b.wg.Wait(); close(done) }()
		tick := time.NewTicker(10 * time.Millisecond)
	loop:
		for {
			for _, ep := range b.stack.RegisteredEndpoints() {
				ep.Abort()
			}
			select {
			case <-done:
				break loop
			case <-tick.C:
			}
		}
		tick.Stop()
		b.stack.Close()
		b.link.Close()
		b.injectMu.Unlock()
		b.stack.Wait()
	})
	return nil
}

func target(id stack.TransportEndpointID) string {
	return net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
}

func (b *Bridge) handleTCP(r *tcp.ForwarderRequest) {
	if !b.begin() {
		r.Complete(true)
		return
	}
	defer b.end()
	ctx, cancel := context.WithTimeout(b.ctx, b.opts.DialTimeout)
	remote, err := b.out.DialTCP(ctx, target(r.ID()))
	cancel()
	if err != nil {
		r.Complete(true)
		return
	}
	defer remote.Close()
	if b.ctx.Err() != nil {
		r.Complete(true)
		return
	}
	stopRemote := context.AfterFunc(b.ctx, func() { remote.Close() })
	defer stopRemote()
	var q waiter.Queue
	ep, e := r.CreateEndpoint(&q)
	r.Complete(e != nil)
	if e != nil {
		return
	}
	local := gonet.NewTCPConn(&q, ep)
	defer local.Close()
	stopLocal := context.AfterFunc(b.ctx, func() { local.Close() })
	defer stopLocal()
	copyTCP(local, remote)
}

// CloseWrite preserves replies after a client half-closes its request.
func copyTCP(a, b net.Conn) {
	done := make(chan struct{})
	copyOne := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		if err != nil {
			a.Close()
			b.Close()
			return
		}
		if c, ok := dst.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		} else {
			dst.Close()
		}
	}
	go func() { defer close(done); copyOne(a, b) }()
	copyOne(b, a)
	<-done
}

func (b *Bridge) handleUDP(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
	if !b.begin() {
		return true
	}
	var q waiter.Queue
	ep, err := b.stack.NewEndpoint(udp.ProtocolNumber, pkt.NetworkProtocolNumber, &q)
	if err != nil {
		b.end()
		return true
	}
	ep.SocketOptions().SetReuseAddress(true)
	ep.SocketOptions().SetReusePort(true)
	if err = ep.Bind(tcpip.FullAddress{NIC: 1, Addr: id.LocalAddress, Port: id.LocalPort}); err == nil {
		err = ep.Connect(tcpip.FullAddress{NIC: 1, Addr: id.RemoteAddress, Port: id.RemotePort})
	}
	if err != nil {
		ep.Close()
		b.end()
		return true
	}
	// Register the connected flow before the next packet arrives. Deliver the
	// first datagram too, without retaining a clone of its PacketBuffer.
	ep.(stack.TransportEndpoint).HandlePacket(id, pkt)
	local := gonet.NewUDPConn(&q, ep)
	go b.relayUDP(local, target(id))
	return true
}

func (b *Bridge) relayUDP(local *gonet.UDPConn, dst string) {
	defer b.end()
	defer local.Close()
	ctx, cancel := context.WithCancel(b.ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { local.Close() })
	defer stop()
	dialCtx, dialCancel := context.WithTimeout(ctx, b.opts.DialTimeout)
	remote, err := b.out.OpenUDP(dialCtx)
	dialCancel()
	if err != nil {
		return
	}
	defer remote.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer local.Close()
		for {
			data, from, err := remote.ReadFrom(ctx)
			if err != nil {
				return
			}
			// A connected UDP flow must not accept packets from another source.
			if !sameEndpoint(from, dst) {
				continue
			}
			local.SetReadDeadline(time.Now().Add(b.opts.UDPIdleTimeout))
			if _, err := local.Write(data); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 65535)
	for {
		local.SetReadDeadline(time.Now().Add(b.opts.UDPIdleTimeout))
		n, err := local.Read(buf)
		if err != nil {
			break
		}
		if err := remote.WriteTo(buf[:n], dst); err != nil {
			break
		}
	}
	cancel()
	remote.Close()
	<-done
}

func sameEndpoint(a, b string) bool {
	x, ex := netip.ParseAddrPort(a)
	y, ey := netip.ParseAddrPort(b)
	return ex == nil && ey == nil && x.Port() == y.Port() && x.Addr().Unmap() == y.Addr().Unmap()
}
