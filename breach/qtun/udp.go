package qtun

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go"
)

// UDP support, so DNS and QUIC-based sites go through the tunnel instead of
// leaking around it. Without this a SOCKS5 proxy carries TCP only, which means
// name resolution happens on the local network and HTTP/3 either bypasses the
// proxy or fails.
//
// UDP rides QUIC DATAGRAM frames, not streams: an unreliable payload belongs on
// an unreliable carrier. Putting UDP on a reliable stream would make a lost
// packet block every later one and would retransmit data whose moment has
// passed — actively harmful for the inner QUIC we are trying to carry.
//
// Fragmentation exists because of that same inner QUIC: it insists on sending
// datagrams of at least 1200 bytes, while our own datagram budget is smaller
// (the path is TURN-relayed and SRTP-wrapped). A packet that does not fit is
// split; losing a fragment loses the packet, which is exactly UDP's contract.

const (
	// kindTCP/kindUDP select what a stream is for.
	kindTCP = 0
	kindUDP = 1

	udpHeaderFixed = 4 + 2 + 1 + 1 + 2 // session, packetID, fragID, fragCount, addrLen
	reasmTTL       = 5 * time.Second
	maxReasm       = 256

	// Our own datagram ceiling, deliberately well below what the connection
	// advertises. SendDatagram only checks that a frame COULD fit an empty
	// packet; the packer then silently discards it if an ACK or stream frame got
	// there first (packet_packer.go: "Discard this frame"). Sizing to the
	// advertised maximum therefore loses packets at random — and on fragmented
	// traffic one lost fragment loses the whole datagram, so it shows up as UDP
	// simply not working rather than as occasional loss. Leaving ~200 bytes for
	// whatever shares the packet costs one extra fragment on large payloads and
	// removes the failure entirely.
	safeDatagramPayload = 900

	// A datagram that cannot be packed for DatagramFrameMaxPeekTimes (10)
	// consecutive attempts is discarded by quic-go, so a long burst of fragments
	// outruns the congestion window and loses pieces — and one lost fragment
	// wastes the whole packet. Cap the burst instead of sending something that
	// cannot arrive: ~7 KB covers every UDP payload that occurs in practice
	// (a 1500-byte path MTU, EDNS0 at 4096, QUIC at 1200), and anything larger
	// is dropped, which is what UDP promises anyway.
	maxFragments = 8
)

// ---- datagram framing ------------------------------------------------------
//
//	session(4) packetID(2) fragID(1) fragCount(1) addrLen(2) addr payload

func encodeUDP(session uint32, packetID uint16, fragID, fragCount uint8, addr string, payload []byte) []byte {
	b := make([]byte, 0, udpHeaderFixed+len(addr)+len(payload))
	b = binary.BigEndian.AppendUint32(b, session)
	b = binary.BigEndian.AppendUint16(b, packetID)
	b = append(b, fragID, fragCount)
	b = binary.BigEndian.AppendUint16(b, uint16(len(addr)))
	b = append(b, addr...)
	b = append(b, payload...)
	return b
}

type udpFrame struct {
	session   uint32
	packetID  uint16
	fragID    uint8
	fragCount uint8
	addr      string
	payload   []byte
}

func decodeUDP(b []byte) (udpFrame, error) {
	var f udpFrame
	if len(b) < udpHeaderFixed {
		return f, errors.New("qtun: short UDP frame")
	}
	f.session = binary.BigEndian.Uint32(b[0:4])
	f.packetID = binary.BigEndian.Uint16(b[4:6])
	f.fragID, f.fragCount = b[6], b[7]
	n := int(binary.BigEndian.Uint16(b[8:10]))
	// fragCount is bounded by what we ourselves ever send. Accepting the wire
	// maximum of 255 would let a peer pin ~72 MiB per connection in
	// half-assembled packets, and no legitimate sender needs it.
	if f.fragCount == 0 || int(f.fragCount) > maxFragments ||
		int(f.fragID) >= int(f.fragCount) || len(b) < udpHeaderFixed+n {
		return f, errors.New("qtun: malformed UDP frame")
	}
	f.addr = string(b[udpHeaderFixed : udpHeaderFixed+n])
	f.payload = b[udpHeaderFixed+n:]
	return f, nil
}

// ---- reassembly ------------------------------------------------------------

type reassembler struct {
	mu    sync.Mutex
	m     map[uint64]*pendingPacket
	bytes int // buffered across all half-assembled packets
}

type pendingPacket struct {
	frags [][]byte
	got   int
	addr  string
	size  int
	at    time.Time
}

func newReassembler() *reassembler { return &reassembler{m: map[uint64]*pendingPacket{}} }

// push returns the complete payload once every fragment has arrived.
func (r *reassembler) push(f udpFrame) ([]byte, string, bool) {
	if f.fragCount == 1 {
		return f.payload, f.addr, true
	}
	key := uint64(f.session)<<16 | uint64(f.packetID)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.gcLocked()

	p := r.m[key]
	if p == nil {
		p = &pendingPacket{frags: make([][]byte, f.fragCount), addr: f.addr, at: time.Now()}
		r.m[key] = p
	}
	// A 16-bit packetID wraps within seconds at video rates, so an abandoned
	// half-packet can collide with a fresh one that reuses its id. Fragment
	// counts that disagree are the detectable half of that: start over rather
	// than splice two different packets together.
	if int(f.fragCount) != len(p.frags) {
		r.bytes -= p.size
		p = &pendingPacket{frags: make([][]byte, f.fragCount), addr: f.addr, at: time.Now()}
		r.m[key] = p
	}
	if int(f.fragID) >= len(p.frags) || p.frags[f.fragID] != nil {
		return nil, "", false // duplicate or inconsistent; drop, as UDP allows
	}
	cp := make([]byte, len(f.payload))
	copy(cp, f.payload)
	p.frags[f.fragID] = cp
	p.got++
	p.size += len(cp)
	r.bytes += len(cp)
	if p.got < len(p.frags) {
		return nil, "", false
	}
	delete(r.m, key)
	r.bytes -= p.size
	out := make([]byte, 0, p.got*len(cp))
	for _, fr := range p.frags {
		out = append(out, fr...)
	}
	return out, p.addr, true
}

// gcLocked drops half-assembled packets. A fragment that never arrives must not
// hold memory forever, and the sender has long since moved on.
//
// Expiry runs on every push rather than on a timer, which is enough because a
// peer that stops sending also stops being able to add anything: the ceiling on
// what a silent connection can pin is whatever it left behind, and that is
// bounded by maxReasm and maxFragments.
func (r *reassembler) gcLocked() {
	cut := time.Now().Add(-reasmTTL)
	for k, p := range r.m {
		if p.at.Before(cut) {
			r.bytes -= p.size
			delete(r.m, k)
		}
	}
	// Still over the cap after expiry: evict the OLDEST, not everything. Wiping
	// the table took out the packets that were genuinely mid-reassembly along
	// with the junk, so a lossy path lost good traffic several times a second.
	for len(r.m) > maxReasm {
		var oldestKey uint64
		var oldest time.Time
		first := true
		for k, p := range r.m {
			if first || p.at.Before(oldest) {
				oldestKey, oldest, first = k, p.at, false
			}
		}
		r.bytes -= r.m[oldestKey].size
		delete(r.m, oldestKey)
	}
}

// ---- sending with adaptive fragmentation -----------------------------------

// datagramSender splits a payload to fit the connection's datagram budget. The
// budget is discovered from the first oversized send rather than assumed, since
// it depends on the path.
type datagramSender struct {
	conn     *quic.Conn
	maxSize  atomic.Int64 // 0 = not yet known
	packetID atomic.Uint32
}

func (d *datagramSender) send(session uint32, addr string, payload []byte) error {
	id := uint16(d.packetID.Add(1))

	// Budget is the smaller of our own ceiling and anything the connection has
	// told us is too big. It is never the advertised maximum, for the reason in
	// safeDatagramPayload.
	budget := safeDatagramPayload
	if learned := int(d.maxSize.Load()); learned > 0 && learned < budget {
		budget = learned
	}
	per := budget - udpHeaderFixed - len(addr)
	if per <= 0 {
		return fmt.Errorf("qtun: datagram budget %d too small for a %d-byte address", budget, len(addr))
	}

	n := 1
	if len(payload) > per {
		n = (len(payload) + per - 1) / per
	}
	if n > maxFragments {
		// Dropped deliberately, and not reported as an error: the caller is
		// relaying UDP, where loss is normal and a failure here would tear down a
		// working session over one oversized packet.
		return nil
	}
	for i := 0; i < n; i++ {
		lo := i * per
		hi := lo + per
		if hi > len(payload) {
			hi = len(payload)
		}
		err := d.conn.SendDatagram(encodeUDP(session, id, uint8(i), uint8(n), addr, payload[lo:hi]))
		if err == nil {
			continue
		}
		// The path turned out to be tighter than our ceiling. Record it and give
		// up on THIS packet: it is UDP, the sender will cope, and the next one
		// will be split to fit.
		var tooLarge *quic.DatagramTooLargeError
		if errors.As(err, &tooLarge) {
			d.maxSize.Store(tooLarge.MaxDatagramPayloadSize)
			return nil
		}
		return err
	}
	return nil
}

// ---- client side -----------------------------------------------------------

// UDPSession is one SOCKS5 UDP association: a single relayed socket on the exit
// that may talk to many destinations.
type UDPSession struct {
	id     uint32
	c      *Client
	stream *quic.Stream // open for as long as the session lives
	in     chan udpMessage
	closed chan struct{}
	once   sync.Once
}

type udpMessage struct {
	payload []byte
	from    string
}

// OpenUDP asks the exit for a relayed UDP socket.
func (c *Client) OpenUDP(ctx context.Context) (*UDPSession, error) {
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeRequest(st, kindUDP, c.token, "udp"); err != nil {
		st.Close()
		return nil, err
	}
	_ = st.SetReadDeadline(time.Now().Add(handshakeLimit))
	status, session, err := readUDPReply(st)
	if err != nil {
		st.Close()
		return nil, err
	}
	_ = st.SetReadDeadline(time.Time{})
	if status != statusOK {
		st.Close()
		if status == statusAuth {
			return nil, ErrAuth
		}
		return nil, fmt.Errorf("qtun: exit refused a UDP session (status %d)", status)
	}

	s := &UDPSession{id: session, c: c, stream: st, in: make(chan udpMessage, 256), closed: make(chan struct{})}
	c.mu.Lock()
	c.sessions[session] = s
	c.mu.Unlock()

	// The stream is the session's lifetime: when it ends, the exit frees the
	// socket and we stop.
	go func() {
		buf := make([]byte, 1)
		_, _ = st.Read(buf)
		s.Close()
	}()
	return s, nil
}

// WriteTo sends one datagram to target ("host:port") through the exit.
func (s *UDPSession) WriteTo(payload []byte, target string) error {
	select {
	case <-s.closed:
		return net.ErrClosed
	default:
	}
	return s.c.sender.send(s.id, target, payload)
}

// ReadFrom returns the next datagram the exit received for this session.
func (s *UDPSession) ReadFrom(ctx context.Context) (payload []byte, from string, err error) {
	select {
	case m := <-s.in:
		return m.payload, m.from, nil
	case <-s.closed:
		return nil, "", net.ErrClosed
	case <-ctx.Done():
		return nil, "", ctx.Err()
	}
}

func (s *UDPSession) Close() error {
	s.once.Do(func() {
		close(s.closed)
		s.stream.Close()
		s.c.mu.Lock()
		delete(s.c.sessions, s.id)
		s.c.mu.Unlock()
	})
	return nil
}

func (s *UDPSession) deliver(payload []byte, from string) {
	select {
	case s.in <- udpMessage{payload: payload, from: from}:
	case <-s.closed:
	default: // reader is behind; dropping is UDP's contract
	}
}

// readDatagrams demuxes the connection's datagrams to their sessions.
func (c *Client) readDatagrams(ctx context.Context) {
	re := newReassembler()
	for {
		b, err := c.conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		f, err := decodeUDP(b)
		if err != nil {
			continue
		}
		payload, from, ok := re.push(f)
		if !ok {
			continue
		}
		c.mu.Lock()
		s := c.sessions[f.session]
		c.mu.Unlock()
		if s != nil {
			s.deliver(payload, from)
		}
	}
}

// ---- server side -----------------------------------------------------------

// udpRelay is the exit's half of one session: an unconnected UDP socket whose
// replies are wrapped back to the client. One socket per session behaves like an
// ordinary NAT entry, which is what the SOCKS5 association expects.
type udpRelay struct {
	id           uint32
	pc           *net.UDPConn
	sender       *datagramSender
	allowPrivate bool
	// out decouples the connection's single datagram-demux goroutine from name
	// resolution. Resolving inline meant one slow or unresolvable name stalled
	// EVERY session on the connection for the resolver timeout, and a client
	// using proxy-side DNS (the leak-free setting) resolves on every packet.
	out    chan udpOut
	closed chan struct{}
	once   sync.Once

	mu    sync.Mutex
	cache map[string]cachedAddr
}

type udpOut struct {
	payload []byte
	target  string
}

type cachedAddr struct {
	addr *net.UDPAddr
	at   time.Time
	err  bool // resolution failed or the policy refused it
}

const (
	udpResolveTTL   = 30 * time.Second
	udpResolveCache = 512
	udpOutQueue     = 256
)

func (u *udpRelay) close() {
	u.once.Do(func() {
		close(u.closed)
		u.pc.Close()
	})
}

func (u *udpRelay) run() {
	buf := make([]byte, 65535)
	for {
		n, src, err := u.pc.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if err := u.sender.send(u.id, src.String(), buf[:n]); err != nil {
			return
		}
	}
}

// enqueue hands a datagram to the session's own writer. Never blocks: the demux
// goroutine serves every session on the connection, so waiting here would stall
// them all. A full queue drops, which is what UDP promises.
func (u *udpRelay) enqueue(payload []byte, target string) {
	cp := make([]byte, len(payload))
	copy(cp, payload)
	select {
	case u.out <- udpOut{payload: cp, target: target}:
	case <-u.closed:
	default:
	}
}

// writer resolves and sends, off the demux path.
func (u *udpRelay) writer() {
	for {
		select {
		case <-u.closed:
			return
		case m := <-u.out:
			addr, ok := u.resolve(m.target)
			if !ok {
				continue
			}
			_, _ = u.pc.WriteToUDP(m.payload, addr)
		}
	}
}

// resolve caches both answers and refusals: a client hammering a blocked or
// bogus name must not cost a lookup per packet.
func (u *udpRelay) resolve(target string) (*net.UDPAddr, bool) {
	u.mu.Lock()
	if c, ok := u.cache[target]; ok && time.Since(c.at) < udpResolveTTL {
		u.mu.Unlock()
		return c.addr, !c.err
	}
	u.mu.Unlock()

	addr, err := resolveAllowed(target, u.allowPrivate)

	u.mu.Lock()
	if len(u.cache) >= udpResolveCache {
		u.cache = make(map[string]cachedAddr, udpResolveCache)
	}
	u.cache[target] = cachedAddr{addr: addr, at: time.Now(), err: err != nil}
	u.mu.Unlock()
	return addr, err == nil
}

// serveUDPSession allocates the relay socket and holds it for the stream's life.
func serveUDPSession(st *quic.Stream, sessions *sessionTable, sender *datagramSender, allowPrivate bool, logf func(string, ...any)) {
	pc, err := net.ListenUDP("udp", nil)
	if err != nil {
		_, _ = st.Write([]byte{statusDial, 0, 0, 0, 0})
		shutdown(st)
		return
	}
	pc.SetReadBuffer(4 << 20)
	pc.SetWriteBuffer(4 << 20)

	u := &udpRelay{
		pc:           pc,
		sender:       sender,
		allowPrivate: allowPrivate,
		out:          make(chan udpOut, udpOutQueue),
		closed:       make(chan struct{}),
		cache:        map[string]cachedAddr{},
	}
	u.id = sessions.add(u)

	reply := make([]byte, 5)
	reply[0] = statusOK
	binary.BigEndian.PutUint32(reply[1:], u.id)
	if _, err := st.Write(reply); err != nil {
		sessions.remove(u.id)
		u.close()
		shutdown(st)
		return
	}

	go u.run()
	go u.writer()

	// Blocks until the client closes the stream (or the connection dies), which
	// is precisely when the SOCKS5 association ends.
	buf := make([]byte, 1)
	_, _ = st.Read(buf)
	sessions.remove(u.id)
	u.close()
	st.Close()
}

type sessionTable struct {
	mu   sync.Mutex
	next uint32
	m    map[uint32]*udpRelay
}

func newSessionTable() *sessionTable { return &sessionTable{m: map[uint32]*udpRelay{}} }

func (t *sessionTable) add(u *udpRelay) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.next++
	u.id = t.next
	t.m[u.id] = u
	return u.id
}

func (t *sessionTable) get(id uint32) *udpRelay {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[id]
}

func (t *sessionTable) remove(id uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.m, id)
}

func (t *sessionTable) closeAll() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for id, u := range t.m {
		u.close()
		delete(t.m, id)
	}
}

// serverDatagrams demuxes inbound datagrams to their session's relay socket.
func serverDatagrams(ctx context.Context, conn *quic.Conn, sessions *sessionTable) {
	re := newReassembler()
	for {
		b, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			return
		}
		f, err := decodeUDP(b)
		if err != nil {
			continue
		}
		payload, target, ok := re.push(f)
		if !ok {
			continue
		}
		if u := sessions.get(f.session); u != nil {
			u.enqueue(payload, target)
		}
	}
}

func readUDPReply(st *quic.Stream) (status byte, session uint32, err error) {
	var b [5]byte
	if _, err := readFull(st, b[:]); err != nil {
		return 0, 0, err
	}
	return b[0], binary.BigEndian.Uint32(b[1:]), nil
}
