package routing

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"breach-nativecore/outbound"
	"golang.org/x/net/dns/dnsmessage"
)

var fake4 = netip.MustParsePrefix("198.18.0.0/15")
var fake6 = netip.MustParsePrefix("fd00:198:18::/96")

func fakeAddress(a netip.Addr) bool { return fake4.Contains(a.Unmap()) || fake6.Contains(a) }

type dnsEntry struct {
	ips     []netip.Addr
	expires time.Time
}
type fakeEntry struct {
	Name string `json:"name"`
	ID   uint32 `json:"id"`
}
type dnsService struct {
	fake     bool
	upstream string
	tunnel   outbound.Outbound
	mu       sync.Mutex
	names    map[string]uint32
	ids      map[uint32]string
	cache    map[string]dnsEntry
	state    *os.File
	closed   bool
	stateErr error
}

func newDNS(cfg DNSConfig, tunnel outbound.Outbound) (*dnsService, error) {
	if cfg.Upstream == "" {
		cfg.Upstream = "1.1.1.1:53"
	}
	if a, e := netip.ParseAddrPort(cfg.Upstream); e != nil || a.Port() == 0 || fakeAddress(a.Addr()) {
		return nil, errors.New("DNS upstream must be a real IP:port")
	}
	d := &dnsService{fake: cfg.FakeIP, upstream: cfg.Upstream, tunnel: tunnel, names: map[string]uint32{}, ids: map[uint32]string{}, cache: map[string]dnsEntry{}}
	if cfg.StateFile != "" && cfg.FakeIP {
		f, e := os.OpenFile(cfg.StateFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if e != nil {
			return nil, e
		}
		stat, err := f.Stat()
		if err != nil {
			f.Close()
			return nil, err
		}
		if stat.Size() > 32<<20 {
			f.Close()
			return nil, errors.New("FakeIP state exceeds 32 MiB")
		}
		// Append-only IDs are never reassigned: an OS-cached FakeIP must never start
		// pointing at a different domain after reconnect or eviction.
		scan := bufio.NewScanner(io.LimitReader(f, 32<<20))
		scan.Buffer(make([]byte, 4096), 4096)
		for scan.Scan() {
			var v fakeEntry
			if e = json.Unmarshal(scan.Bytes(), &v); e != nil {
				f.Close()
				return nil, fmt.Errorf("invalid FakeIP state: %w", e)
			}
			name, err := domainName(v.Name)
			if err != nil || name != v.Name || v.ID == 0 || v.ID > 65534 || v.ID != uint32(len(d.ids)+1) || d.ids[v.ID] != "" || d.names[name] != 0 {
				f.Close()
				return nil, errors.New("invalid or duplicate FakeIP state entry")
			}
			d.names[name] = v.ID
			d.ids[v.ID] = name
		}
		if e = scan.Err(); e != nil {
			f.Close()
			return nil, e
		}
		d.state = f
	}
	return d, nil
}
func (d *dnsService) close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.state != nil {
		return d.state.Close()
	}
	return nil
}
func (d *dnsService) fakeIP(name string, v6 bool) (netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return netip.Addr{}, net.ErrClosed
	}
	if d.stateErr != nil {
		return netip.Addr{}, d.stateErr
	}
	id := d.names[name]
	if id == 0 {
		if len(d.names) >= 65534 {
			return netip.Addr{}, errors.New("FakeIP pool exhausted")
		}
		// Journal IDs are contiguous and never recycled.
		for id = uint32(len(d.ids) + 1); d.ids[id] != ""; id++ {
		}
		if d.state != nil {
			p, _ := json.Marshal(fakeEntry{name, id})
			p = append(p, '\n')
			if _, e := d.state.Write(p); e != nil {
				d.stateErr = e
				return netip.Addr{}, e
			}
			if e := d.state.Sync(); e != nil {
				d.stateErr = e
				return netip.Addr{}, e
			}
		}
		d.names[name] = id
		d.ids[id] = name
	}
	if v6 {
		a := fake6.Addr().As16()
		binary.BigEndian.PutUint32(a[12:], id)
		return netip.AddrFrom16(a), nil
	}
	a := fake4.Addr().As4()
	binary.BigEndian.PutUint16(a[2:], uint16(id))
	return netip.AddrFrom4(a), nil
}
func (d *dnsService) reverse(a netip.Addr) (string, bool) {
	var id uint32
	a = a.Unmap()
	if fake4.Contains(a) {
		v := a.As4()
		if v[1] != 18 {
			return "", false
		}
		id = uint32(binary.BigEndian.Uint16(v[2:]))
	} else if fake6.Contains(a) {
		v := a.As16()
		id = binary.BigEndian.Uint32(v[12:])
	} else {
		return "", false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	n, ok := d.ids[id]
	return n, ok
}
func (d *dnsService) answer(ctx context.Context, wire []byte) ([]byte, error) {
	var q dnsmessage.Message
	if e := q.Unpack(wire); e != nil {
		return nil, e
	}
	if q.Response || q.OpCode != 0 || len(q.Questions) != 1 {
		return nil, errors.New("expected a single DNS question")
	}
	question := q.Questions[0]
	if question.Class != dnsmessage.ClassINET {
		return nil, errors.New("unsupported DNS class")
	}
	// Do not return HTTPS/SVCB address hints which would bypass the FakeIP map.
	if question.Type != dnsmessage.TypeA && question.Type != dnsmessage.TypeAAAA && question.Type != 64 && question.Type != 65 {
		return d.exchange(ctx, wire)
	}
	name, e := domainName(question.Name.String())
	if e != nil {
		return nil, e
	}
	resp := dnsmessage.Message{Header: dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}, Questions: q.Questions}
	if question.Type == dnsmessage.TypeA || question.Type == dnsmessage.TypeAAAA {
		a, e := d.fakeIP(name, question.Type == dnsmessage.TypeAAAA)
		if e != nil {
			resp.RCode = dnsmessage.RCodeServerFailure
			return resp.Pack()
		}
		res := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: question.Class, TTL: 60}}
		if a.Is4() {
			res.Body = &dnsmessage.AResource{A: a.As4()}
		} else {
			res.Body = &dnsmessage.AAAAResource{AAAA: a.As16()}
		}
		resp.Answers = []dnsmessage.Resource{res}
	}
	return resp.Pack()
}
func (d *dnsService) exchange(ctx context.Context, wire []byte) ([]byte, error) {
	if len(wire) < 12 || len(wire) > 65535 {
		return nil, errors.New("invalid DNS query length")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, e := d.tunnel.DialTCP(ctx, d.upstream)
	if e != nil {
		return nil, e
	}
	defer c.Close()
	stop := context.AfterFunc(ctx, func() { c.Close() })
	defer stop()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, e = c.Write(binary.BigEndian.AppendUint16(nil, uint16(len(wire)))); e != nil {
		return nil, e
	}
	if _, e = c.Write(wire); e != nil {
		return nil, e
	}
	var size [2]byte
	if _, e = io.ReadFull(c, size[:]); e != nil {
		return nil, e
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, e = io.ReadFull(c, reply); e != nil {
		return nil, e
	}
	var q, a dnsmessage.Message
	if q.Unpack(wire) != nil || a.Unpack(reply) != nil || a.ID != q.ID || !a.Response || len(a.Questions) != len(q.Questions) {
		return nil, errors.New("invalid DNS response")
	}
	for i := range q.Questions {
		if q.Questions[i] != a.Questions[i] {
			return nil, errors.New("DNS question mismatch")
		}
	}
	return reply, nil
}
func (d *dnsService) lookup(ctx context.Context, name string) ([]netip.Addr, error) {
	d.mu.Lock()
	cached, ok := d.cache[name]
	d.mu.Unlock()
	if ok && time.Now().Before(cached.expires) {
		return append([]netip.Addr(nil), cached.ips...), nil
	}
	var ips []netip.Addr
	ttl := uint32(300)
	var lastErr error
	for _, typ := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		n, e := dnsmessage.NewName(name + ".")
		if e != nil {
			return nil, e
		}
		var id [2]byte
		if _, e = rand.Read(id[:]); e != nil {
			return nil, e
		}
		q := dnsmessage.Message{Header: dnsmessage.Header{ID: binary.BigEndian.Uint16(id[:]), RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: n, Type: typ, Class: dnsmessage.ClassINET}}}
		wire, _ := q.Pack()
		reply, e := d.exchange(ctx, wire)
		if e != nil {
			lastErr = e
			continue
		}
		var a dnsmessage.Message
		if e = a.Unpack(reply); e != nil {
			lastErr = e
			continue
		}
		if a.RCode != dnsmessage.RCodeSuccess {
			lastErr = fmt.Errorf("DNS response %v", a.RCode)
			continue
		}
		for _, res := range a.Answers {
			if res.Header.TTL < ttl {
				ttl = res.Header.TTL
			}
			var ip netip.Addr
			switch v := res.Body.(type) {
			case *dnsmessage.AResource:
				ip = netip.AddrFrom4(v.A)
			case *dnsmessage.AAAAResource:
				ip = netip.AddrFrom16(v.AAAA)
			}
			if ip.IsValid() && !fakeAddress(ip) {
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("DNS returned no A/AAAA answers")
	}
	if ttl > 0 {
		d.mu.Lock()
		if len(d.cache) >= 4096 {
			for k, v := range d.cache {
				if time.Now().After(v.expires) {
					delete(d.cache, k)
				}
			}
		}
		if len(d.cache) < 4096 {
			d.cache[name] = dnsEntry{append([]netip.Addr(nil), ips...), time.Now().Add(time.Duration(ttl) * time.Second)}
		}
		d.mu.Unlock()
	}
	return ips, nil
}
func (r *Router) dnsTCP() net.Conn {
	app, server := net.Pipe()
	go func() {
		defer server.Close()
		stop := context.AfterFunc(r.ctx, func() { server.Close() })
		defer stop()
		for {
			server.SetDeadline(time.Now().Add(30 * time.Second))
			var size [2]byte
			if _, e := io.ReadFull(server, size[:]); e != nil {
				return
			}
			q := make([]byte, binary.BigEndian.Uint16(size[:]))
			if _, e := io.ReadFull(server, q); e != nil {
				return
			}
			p, e := r.dns.answer(r.ctx, q)
			if e != nil {
				return
			}
			if _, e = server.Write(binary.BigEndian.AppendUint16(nil, uint16(len(p)))); e != nil {
				return
			}
			if _, e = server.Write(p); e != nil {
				return
			}
		}
	}()
	return app
}
