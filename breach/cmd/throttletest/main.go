// throttletest probes MAX TURN's anti-abuse on a single allocation, fully
// self-contained: it is both the TURN client and the counting peer (same VPS).
//
// Modes:
//
//	raw     : ChannelBind, then blast raw ChannelData (no DTLS at all)
//	hs-raw  : ChannelBind, complete a real DTLS handshake, then blast RAW bytes
//	dtls    : ChannelBind, complete a real DTLS handshake, then send DTLS app-data
//
// All modes report arrivals/sec at the peer socket (true wire delivery). If raw
// survives but dtls dies -> ongoing DTLS app-data is the trigger. If hs-raw also
// dies -> the handshake itself marks the allocation.
package main

import (
	"crypto/rand"
	"flag"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/dtls/v2"

	"breach/dtlscfg"
	"breach/turn"
)

var (
	rawCount  atomic.Int64
	rawEchoOn atomic.Bool // hs-raw: peer raw-echoes only after the handshake
	peerAddr  atomic.Pointer[net.UDPAddr]
)

func main() {
	turnAddr := flag.String("turn", "", "TURN host:port")
	user := flag.String("user", "", "TURN username")
	pass := flag.String("pass", "", "TURN credential")
	peerIP := flag.String("peerIP", "185.238.191.17", "this VPS public IP")
	peerPort := flag.Int("peerPort", 48050, "local peer UDP port")
	mode := flag.String("mode", "raw", "raw | hs-raw | dtls")
	pps := flag.Int("pps", 100, "send rate")
	secs := flag.Int("secs", 15, "duration")
	size := flag.Int("size", 1024, "payload bytes")
	transport := flag.String("transport", "auto", "TURN transport: auto|udp|tcp")
	echoEvery := flag.Int("echoEvery", 1, "peer echoes 1 of every N datagrams (0=never)")
	peerPad := flag.Int("peerPad", 0, "peer sends N pps INDEPENDENT padding back (not echo)")
	flag.Parse()

	needDTLS := *mode == "hs-raw" || *mode == "dtls"
	startPeer(*peerPort, *mode, *echoEvery, *peerPad)
	time.Sleep(300 * time.Millisecond)

	peer := &net.UDPAddr{IP: net.ParseIP(*peerIP), Port: *peerPort}
	a, err := turn.NewAlloc(*turnAddr, *user, *pass, peer, 0x4000, *transport)
	if err != nil {
		log.Fatalf("alloc: %v", err)
	}
	defer a.Close()
	log.Printf("mode=%s: allocation + channel up (edge %s)", *mode, *turnAddr)

	payload := make([]byte, *size)
	rand.Read(payload)
	send := func(b []byte) { a.Send(b) }

	if needDTLS {
		dc, err := dtls.Client(a.NetConn(), dtlscfg.Client())
		if err != nil {
			log.Fatalf("dtls handshake: %v", err)
		}
		log.Printf("mode=%s: DTLS handshake complete", *mode)
		if *mode == "dtls" {
			send = func(b []byte) { dc.Write(b) }
		} else {
			rawEchoOn.Store(true) // hs-raw: now safe for the peer to raw-echo
		}
		go func() {
			buf := make([]byte, 4096)
			for {
				if _, e := dc.Read(buf); e != nil {
					return
				}
			}
		}()
	}

	// per-second arrivals sampler
	go func() {
		var prev int64
		for range time.Tick(time.Second) {
			cur := rawCount.Load()
			log.Printf("[rate] arrivals/sec=%d total=%d", cur-prev, cur)
			prev = cur
		}
	}()

	iv := time.Second / time.Duration(*pps)
	deadline := time.Now().Add(time.Duration(*secs) * time.Second)
	next := time.Now()
	sent := 0
	for time.Now().Before(deadline) {
		send(payload)
		sent++
		next = next.Add(iv)
		if d := time.Until(next); d > 0 {
			time.Sleep(d)
		}
	}
	time.Sleep(1500 * time.Millisecond)
	log.Printf("mode=%s DONE: sent=%d turnSends=%d sendErr=%d arrivedAtPeer=%d (%.0f%% delivered)",
		*mode, sent, turn.SentPackets.Load(), turn.SendErrors.Load(),
		rawCount.Load(), 100*float64(rawCount.Load())/float64(sent))
}

// startPeer listens on the peer port, counts every datagram, and (if DTLS is
// needed) completes handshakes so the client's dtls.Client can connect.
func startPeer(port int, mode string, echoEvery, peerPad int) {
	needDTLS := mode == "hs-raw" || mode == "dtls"
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		log.Fatalf("peer bind: %v", err)
	}
	conn.SetReadBuffer(16 << 20)
	conn.SetWriteBuffer(16 << 20)

	var cfg *dtls.Config
	if needDTLS {
		cfg, err = dtlscfg.Server()
		if err != nil {
			log.Fatalf("dtls cfg: %v", err)
		}
	}

	// Independent padding back to the relay address (mimics our keepalive,
	// NOT echo-correlated). Tests whether decoupled return traffic unlocks.
	if peerPad > 0 {
		go func() {
			t := time.NewTicker(time.Second / time.Duration(peerPad))
			defer t.Stop()
			for range t.C {
				if a := peerAddr.Load(); a != nil {
					conn.WriteToUDP([]byte{0xfe}, a)
				}
			}
		}()
	}

	sessions := map[string]*vconn{}
	var mu sync.Mutex
	go func() {
		buf := make([]byte, 65536)
		for {
			n, raddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			peerAddr.Store(raddr)
			c := rawCount.Add(1)
			// raw echo: always for raw mode; for hs-raw only after handshake.
			rawEcho := mode == "raw" || (mode == "hs-raw" && rawEchoOn.Load())
			if rawEcho && echoEvery > 0 && c%int64(echoEvery) == 0 {
				conn.WriteToUDP(buf[:n], raddr)
			}
			if !needDTLS {
				continue
			}
			// Feed a DTLS server so the client's handshake completes; in dtls
			// mode it also echoes app-data back (bidirectional DTLS).
			key := raddr.String()
			mu.Lock()
			vc, ok := sessions[key]
			if !ok {
				vc = &vconn{shared: conn, raddr: raddr, in: make(chan []byte, 8192)}
				sessions[key] = vc
				echoBack := mode == "dtls"
				go func() {
					dc, e := dtls.Server(vc, cfg)
					if e != nil {
						return
					}
					b := make([]byte, 4096)
					for {
						m, e := dc.Read(b)
						if e != nil {
							return
						}
						if echoBack {
							dc.Write(b[:m])
						}
					}
				}()
			}
			mu.Unlock()
			d := make([]byte, n)
			copy(d, buf[:n])
			select {
			case vc.in <- d:
			default:
			}
		}
	}()
}

type vconn struct {
	shared *net.UDPConn
	raddr  *net.UDPAddr
	in     chan []byte
	rdl    atomic.Pointer[time.Time]
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
	}
}
func (c *vconn) Write(b []byte) (int, error)       { return c.shared.WriteToUDP(b, c.raddr) }
func (c *vconn) Close() error                      { return nil }
func (c *vconn) LocalAddr() net.Addr               { return c.shared.LocalAddr() }
func (c *vconn) RemoteAddr() net.Addr              { return c.raddr }
func (c *vconn) SetReadDeadline(t time.Time) error { c.rdl.Store(&t); return nil }
func (c *vconn) SetWriteDeadline(time.Time) error  { return nil }
func (c *vconn) SetDeadline(t time.Time) error     { c.rdl.Store(&t); return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }
