package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"breach-nativecore/outbound"
)

var ErrBlocked = errors.New("connection blocked by routing policy")

type Options struct {
	Control Control
	// Optional deterministic resolver for embedders/tests; by default DNS goes
	// through the tunnel, including resolution for explicitly direct domains.
	Resolve func(context.Context, string) ([]netip.Addr, error)
}
type Router struct {
	mu       sync.Mutex
	tcp      map[*ownedConn]struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	rules    []compiledRule
	fallback string
	tunnel   outbound.Outbound
	direct   Direct
	dns      *dnsService
	resolve  func(context.Context, string) ([]netip.Addr, error)
}

// New compiles the entire policy before accepting traffic. No invalid rule or
// missing geodata is silently ignored. The router borrows the tunnel.
func New(cfg Config, tunnel outbound.Outbound, opts Options) (*Router, error) {
	if cfg.DefaultAction == "" {
		cfg.DefaultAction = "tunnel"
	}
	if !validAction(cfg.DefaultAction) || tunnel == nil {
		return nil, errors.New("invalid default action or missing tunnel")
	}
	cfg, e := loadSets(cfg)
	if e != nil {
		return nil, e
	}
	rules, e := compile(cfg)
	if e != nil {
		return nil, e
	}
	dns, e := newDNS(cfg.DNS, tunnel)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	r := &Router{tcp: map[*ownedConn]struct{}{}, ctx: ctx, cancel: cancel, rules: rules, fallback: cfg.DefaultAction, tunnel: tunnel, direct: Direct{opts.Control}, dns: dns}
	r.resolve = opts.Resolve
	if r.resolve == nil {
		r.resolve = dns.lookup
	}
	return r, nil
}
func (r *Router) Close() error {
	r.cancel()
	r.mu.Lock()
	conns := make([]*ownedConn, 0, len(r.tcp))
	for c := range r.tcp {
		conns = append(conns, c)
	}
	r.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
	return r.dns.close()
}

type decision struct{ action, target string }

func (r *Router) decide(ctx context.Context, network, target string) (decision, error) {
	host, port, e := splitTarget(target)
	if e != nil {
		return decision{}, e
	}
	var ips []netip.Addr
	domain := ""
	if a, e := netip.ParseAddr(host); e == nil {
		if fakeAddress(a) && r.dns.fake {
			var ok bool
			domain, ok = r.dns.reverse(a)
			if !ok {
				return decision{}, errors.New("unknown/stale FakeIP; resolve the name again")
			}
			host = domain
		} else {
			ips = []netip.Addr{a.Unmap()}
		}
	} else {
		domain, e = domainName(host)
		if e != nil {
			return decision{}, e
		}
		host = domain
	}
	resolve := func() error {
		if ips != nil {
			return nil
		}
		var e error
		ips, e = r.resolve(ctx, domain)
		if e == nil && len(ips) == 0 {
			e = errors.New("DNS returned no usable address")
		}
		return e
	}
	action := r.fallback
	var selected netip.Addr
	for _, rule := range r.rules {
		if !rule.matchBase(network, domain, port) {
			continue
		}
		if len(rule.IPs) > 0 {
			if e := resolve(); e != nil {
				return decision{}, e
			}
			matched := false
			for _, a := range ips {
				if rule.matchIP(a) {
					matched = true
					selected = a
					break
				}
			}
			if !matched {
				continue
			}
		}
		action = rule.Action
		break
	}
	if action == "block" {
		return decision{}, ErrBlocked
	}
	// UDP needs an exact address to filter replies and restore a FakeIP source.
	// Pin IP-based decisions to the matched address to avoid a second DNS result
	// changing the route between evaluation and dialing.
	if selected.IsValid() {
		host = selected.String()
	} else if action == "direct" || network == "udp" {
		if e := resolve(); e != nil {
			return decision{}, e
		}
		host = ips[0].String()
	}
	return decision{action, net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}
func (r *Router) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	if r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	_, p, e := splitTarget(target)
	if e != nil {
		return nil, e
	}
	if r.dns.fake && p == 53 {
		return r.dnsTCP(), nil
	}
	d, e := r.decide(ctx, "tcp", target)
	if e != nil {
		return nil, e
	}
	var c net.Conn
	if d.action == "direct" {
		c, e = r.direct.DialTCP(ctx, d.target)
	} else {
		c, e = r.tunnel.DialTCP(ctx, d.target)
	}
	if e != nil {
		return nil, e
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ctx.Err() != nil {
		c.Close()
		return nil, net.ErrClosed
	}
	owned := &ownedConn{Conn: c, owner: r}
	r.tcp[owned] = struct{}{}
	return owned, nil
}

type ownedConn struct {
	net.Conn
	owner *Router
}

func (c *ownedConn) Close() error {
	err := c.Conn.Close()
	c.owner.mu.Lock()
	delete(c.owner.tcp, c)
	c.owner.mu.Unlock()
	return err
}
func (c *ownedConn) CloseWrite() error {
	if v, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return v.CloseWrite()
	}
	return c.Close()
}

type udpReply struct {
	data []byte
	from string
	err  error
}
type udpFlow struct {
	conn outbound.Datagrams
	wire string
}
type routedUDP struct {
	r       *Router
	ctx     context.Context
	cancel  context.CancelFunc
	mu      sync.Mutex
	flows   map[string]udpFlow
	replies chan udpReply
	once    sync.Once
}

func (r *Router) OpenUDP(ctx context.Context) (outbound.Datagrams, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if r.ctx.Err() != nil {
		return nil, net.ErrClosed
	}
	life, cancel := context.WithCancel(r.ctx)
	d := &routedUDP{r: r, ctx: life, cancel: cancel, flows: map[string]udpFlow{}, replies: make(chan udpReply, 64)}
	// The caller owns associations; parent shutdown must also interrupt sockets.
	context.AfterFunc(life, func() { d.Close() })
	return d, nil
}
func (d *routedUDP) WriteTo(p []byte, target string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ctx.Err() != nil {
		return net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(d.ctx, 10*time.Second)
	defer cancel()
	_, port, e := splitTarget(target)
	if e != nil {
		return e
	}
	if d.r.dns.fake && port == 53 {
		reply, e := d.r.dns.answer(ctx, p)
		if e != nil {
			return e
		}
		select {
		case d.replies <- udpReply{data: reply, from: target}:
		default:
		} // bounded, UDP may drop
		return nil
	}
	flow, ok := d.flows[target]
	if !ok {
		if len(d.flows) >= 64 {
			return errors.New("UDP association destination limit reached")
		}
		route, e := d.r.decide(ctx, "udp", target)
		if e != nil {
			return e
		}
		var c outbound.Datagrams
		if route.action == "direct" {
			c, e = d.r.direct.openUDP(ctx, route.target)
		} else {
			c, e = d.r.tunnel.OpenUDP(ctx)
		}
		if e != nil {
			return e
		}
		flow = udpFlow{c, route.target}
		d.flows[target] = flow
		go d.receive(target, flow)
	}
	return flow.conn.WriteTo(p, flow.wire)
}
func (d *routedUDP) receive(original string, f udpFlow) {
	for {
		p, from, e := f.conn.ReadFrom(d.ctx)
		if e != nil {
			select {
			case d.replies <- udpReply{err: e}:
			case <-d.ctx.Done():
			}
			return
		}
		a, ae := netip.ParseAddrPort(from)
		b, be := netip.ParseAddrPort(f.wire)
		if ae != nil || be != nil || a.Port() != b.Port() || a.Addr().Unmap() != b.Addr().Unmap() {
			continue
		}
		select {
		case d.replies <- udpReply{data: p, from: original}:
		default:
		}
	}
}
func (d *routedUDP) ReadFrom(ctx context.Context) ([]byte, string, error) {
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-d.ctx.Done():
		return nil, "", net.ErrClosed
	case r := <-d.replies:
		return r.data, r.from, r.err
	}
}
func (d *routedUDP) Close() error {
	d.once.Do(func() {
		d.cancel()
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, f := range d.flows {
			f.conn.Close()
		}
	})
	return nil
}

// Validate checks policy syntax without opening a socket, useful before VPN setup.
func Validate(cfg Config) error {
	if cfg.DefaultAction != "" && !validAction(cfg.DefaultAction) {
		return fmt.Errorf("invalid default action %q", cfg.DefaultAction)
	}
	cfg, e := loadSets(cfg)
	if e != nil {
		return e
	}
	_, e = compile(cfg)
	return e
}
