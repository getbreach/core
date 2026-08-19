// breach-server: uncensored-side endpoint serving MULTIPLE independent clients.
// Each relay stream runs a DTLS-SRTP handshake; decrypted upstream packets carry
// an 8-byte clientID, so the server groups a client's allocations together and
// gives each client its OWN backend socket (WireGuard sees distinct source ports
// → replies route back to the right client). Downstream for a client is fanned
// only across THAT client's allocations.
package main

import (
	"flag"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"breach/media"
)

const clientIDLen = 8

var (
	rxCount atomic.Int64
	txCount atomic.Int64
)

// vconn drives the per-relay-address DTLS handshake over the shared socket.
type vconn struct {
	shared *net.UDPConn
	raddr  *net.UDPAddr
	in     chan []byte
	rdl    atomic.Pointer[time.Time]
	done   chan struct{}
	once   sync.Once
}

func (c *vconn) Read(b []byte) (int, error) {
	var timer <-chan time.Time
	if dl := c.rdl.Load(); dl != nil && !dl.IsZero() {
		d := time.Until(*dl)
		if d <= 0 {
			return 0, timeoutErr{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timer = t.C
	}
	select {
	case p := <-c.in:
		return copy(b, p), nil
	case <-timer:
		return 0, timeoutErr{}
	case <-c.done:
		return 0, timeoutErr{}
	}
}
func (c *vconn) Write(b []byte) (int, error) { return c.shared.WriteToUDP(b, c.raddr) }
func (c *vconn) Close() error                { c.once.Do(func() { close(c.done) }); return nil }
func (c *vconn) LocalAddr() net.Addr         { return c.shared.LocalAddr() }
func (c *vconn) RemoteAddr() net.Addr        { return c.raddr }
func (c *vconn) SetReadDeadline(t time.Time) error {
	c.rdl.Store(&t)
	return nil
}
func (c *vconn) SetWriteDeadline(time.Time) error { return nil }
func (c *vconn) SetDeadline(t time.Time) error    { c.rdl.Store(&t); return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

type peer struct {
	addr  *net.UDPAddr
	vc    *vconn
	sess  atomic.Pointer[media.Session]
	seen  atomic.Int64
	group *clientGroup // set once the clientID is learned
}

// clientGroup is one logical client: its allocations + a dedicated WG backend.
type clientGroup struct {
	id    string
	wg    *net.UDPConn
	mu    sync.Mutex
	peers []*peer
	rr    int
}

func (g *clientGroup) add(p *peer) {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, x := range g.peers {
		if x == p {
			return
		}
	}
	g.peers = append(g.peers, p)
}

func (g *clientGroup) pick() *peer {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.peers) == 0 {
		return nil
	}
	g.rr = (g.rr + 1) % len(g.peers)
	return g.peers[g.rr]
}

func (g *clientGroup) pruneLive(cut int64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	live := g.peers[:0]
	for _, p := range g.peers {
		if p.seen.Load() >= cut {
			live = append(live, p)
		}
	}
	g.peers = live
	return len(live)
}

type srv struct {
	conn    *net.UDPConn
	wgAddr  *net.UDPAddr // backend for WireGuard clients (nil if disabled)
	hy2Addr *net.UDPAddr // backend for Hysteria2/QUIC clients (nil if disabled)
	mu      sync.Mutex
	peers   map[string]*peer
	groups  map[string]*clientGroup
}

// pickBackend chooses a client's backend from the first byte of its first data
// packet. QUIC (Hysteria2) always sets the header fixed bit (0x40); WireGuard
// message types are 1..4 (bit clear). With only one backend configured, it wins.
func (s *srv) pickBackend(firstByte byte) *net.UDPAddr {
	if s.hy2Addr == nil {
		return s.wgAddr
	}
	if s.wgAddr == nil {
		return s.hy2Addr
	}
	if firstByte&0x40 != 0 {
		return s.hy2Addr
	}
	return s.wgAddr
}

func (s *srv) group(id string, backend *net.UDPAddr) *clientGroup {
	s.mu.Lock()
	defer s.mu.Unlock()
	if g, ok := s.groups[id]; ok {
		return g
	}
	wg, err := net.DialUDP("udp", nil, backend)
	if err != nil {
		log.Printf("client %x backend dial: %v", []byte(id), err)
		return nil
	}
	wg.SetReadBuffer(8 << 20)
	wg.SetWriteBuffer(8 << 20)
	g := &clientGroup{id: id, wg: wg}
	s.groups[id] = g
	go s.downstream(g)
	log.Printf("new client %x (backend %s -> %s)", []byte(id), wg.LocalAddr(), backend)
	return g
}

// downstream relays a client's backend replies across its own allocations only.
func (s *srv) downstream(g *clientGroup) {
	buf := make([]byte, 65536)
	for {
		n, err := g.wg.Read(buf)
		if err != nil {
			return // group closed
		}
		p := g.pick()
		if p == nil {
			continue
		}
		sess := p.sess.Load()
		if sess == nil {
			continue
		}
		if wire, err := sess.Protect(media.PTData, buf[:n]); err == nil {
			s.conn.WriteToUDP(wire, p.addr)
			txCount.Add(1)
		}
	}
}

func (s *srv) peersSnapshot() []*peer {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*peer, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p)
	}
	return out
}

func main() {
	listen := flag.String("listen", ":48000", "public UDP address client allocations relay to")
	wg := flag.String("wg", "127.0.0.1:51820", "backend for WireGuard clients (empty to disable)")
	hy2 := flag.String("hy2", "", "backend for Hysteria2/QUIC clients; if set, clients are dispatched wg|hy2 by sniffing the first packet")
	kaMs := flag.Int("keepalive-ms", 50, "keepalive interval per relay stream (ms)")
	flag.Parse()

	laddr, err := net.ResolveUDPAddr("udp", *listen)
	if err != nil {
		log.Fatalf("resolve listen: %v", err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	conn.SetReadBuffer(16 << 20)
	conn.SetWriteBuffer(16 << 20)

	var wgAddr, hy2Addr *net.UDPAddr
	if *wg != "" {
		if wgAddr, err = net.ResolveUDPAddr("udp", *wg); err != nil {
			log.Fatalf("resolve wg: %v", err)
		}
	}
	if *hy2 != "" {
		if hy2Addr, err = net.ResolveUDPAddr("udp", *hy2); err != nil {
			log.Fatalf("resolve hy2: %v", err)
		}
	}
	if wgAddr == nil && hy2Addr == nil {
		log.Fatal("need at least one backend: -wg and/or -hy2")
	}

	s := &srv{conn: conn, wgAddr: wgAddr, hy2Addr: hy2Addr, peers: map[string]*peer{}, groups: map[string]*clientGroup{}}
	log.Printf("breach-server: tunnel(dtls-srtp,multi-client)=%s wg=%q hy2=%q", *listen, *wg, *hy2)

	go func() {
		for range time.Tick(time.Second) {
			s.mu.Lock()
			np, ng := len(s.peers), len(s.groups)
			s.mu.Unlock()
			log.Printf("[stat] dataRx=%d txData=%d streams=%d clients=%d", rxCount.Load(), txCount.Load(), np, ng)
		}
	}()

	// Per-stream SRTP keepalive to every established allocation.
	go func() {
		t := time.NewTicker(time.Duration(*kaMs) * time.Millisecond)
		defer t.Stop()
		pad := make([]byte, 8)
		for range t.C {
			for _, p := range s.peersSnapshot() {
				if sess := p.sess.Load(); sess != nil {
					if wire, err := sess.Protect(media.PTKeepalive, pad); err == nil {
						conn.WriteToUDP(wire, p.addr)
					}
				}
			}
		}
	}()

	// Prune stale peers/clients.
	go func() {
		for range time.Tick(10 * time.Second) {
			cut := time.Now().Add(-30 * time.Second).UnixNano()
			s.mu.Lock()
			for k, p := range s.peers {
				if p.seen.Load() < cut {
					p.vc.Close()
					delete(s.peers, k)
				}
			}
			for id, g := range s.groups {
				if g.pruneLive(cut) == 0 {
					g.wg.Close()
					delete(s.groups, id)
					log.Printf("client %x gone", []byte(id))
				}
			}
			s.mu.Unlock()
		}
	}()

	buf := make([]byte, 65536)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalf("read: %v", err)
		}
		key := src.String()
		s.mu.Lock()
		p, ok := s.peers[key]
		if !ok {
			p = &peer{addr: src, vc: &vconn{shared: conn, raddr: src, in: make(chan []byte, 256), done: make(chan struct{})}}
			s.peers[key] = p
			go handshake(s, p, key)
		}
		s.mu.Unlock()
		p.seen.Store(time.Now().UnixNano())

		sess := p.sess.Load()
		if sess == nil {
			if media.IsDTLS(buf[:n]) {
				d := make([]byte, n)
				copy(d, buf[:n])
				select {
				case p.vc.in <- d:
				default:
				}
			}
			continue
		}
		if !media.IsRTP(buf[:n]) {
			continue
		}
		pt, payload, derr := sess.Unprotect(buf[:n])
		if derr != nil {
			continue
		}
		// Only data packets carry the clientID + inner-protocol payload; the
		// first byte of that payload picks the backend (sniff once per client).
		if pt != media.PTData || len(payload) <= clientIDLen {
			continue
		}
		cid := string(payload[:clientIDLen])
		if p.group == nil {
			if g := s.group(cid, s.pickBackend(payload[clientIDLen])); g != nil {
				g.add(p)
				p.group = g
			}
		}
		if p.group != nil {
			p.group.wg.Write(payload[clientIDLen:])
			rxCount.Add(1)
		}
	}
}

func handshake(s *srv, p *peer, key string) {
	sess, err := media.Server(p.vc)
	if err != nil {
		log.Printf("dtls handshake %s: %v", p.addr, err)
		s.mu.Lock()
		delete(s.peers, key)
		s.mu.Unlock()
		return
	}
	p.sess.Store(sess)
	log.Printf("stream up from %s", p.addr)
}
