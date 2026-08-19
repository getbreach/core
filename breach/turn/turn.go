// Package turn is a minimal TURN (RFC 5766) client: one allocation per Alloc,
// channel-data transport, long-term auth, keepalive with stale-nonce recovery.
package turn

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

type ResponseError struct {
	Operation string
	Code      int
}

func (e *ResponseError) Error() string {
	return fmt.Sprintf("%s rejected: code=%d", e.Operation, e.Code)
}

func ErrorCode(err error) int {
	var responseErr *ResponseError
	if errors.As(err, &responseErr) {
		return responseErr.Code
	}
	return 0
}

// Control, when non-nil, is installed as the socket Control hook on every TURN
// socket so an Android VpnService can protect() the fd — keeping MAX-TURN traffic
// off the tunnel (else it loops and deadlocks). Mirrors maxproto.Control.
var Control func(network, address string, c syscall.RawConn) error

// Wire counters (diagnostic): datagrams actually written to the TURN server.
var (
	SentPackets atomic.Int64
	SendErrors  atomic.Int64
	MaxSendSize atomic.Int64
	BigSends    atomic.Int64 // payloads > 1280 bytes
)

const magicCookie = 0x2112A442

const (
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrChannelNumber      = 0x000C
	attrLifetime           = 0x000D
	attrXorPeerAddress     = 0x0012
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrRequestedTransport = 0x0019
)

const (
	mAllocate     = 0x0003
	mRefresh      = 0x0004
	mChannelBind  = 0x0009
	mAllocateOK   = 0x0103
	mRefreshOK    = 0x0104
	mChannelOK    = 0x0109
	errStaleNonce = 438
)

type message struct {
	typ   uint16
	tid   [12]byte
	attrs []byte
}

func newTID() [12]byte {
	var t [12]byte
	rand.Read(t[:])
	return t
}

func (m *message) addAttr(t uint16, v []byte) {
	m.attrs = append(m.attrs, byte(t>>8), byte(t), byte(len(v)>>8), byte(len(v)))
	m.attrs = append(m.attrs, v...)
	for len(m.attrs)%4 != 0 {
		m.attrs = append(m.attrs, 0)
	}
}

func (m *message) marshal(extra int) []byte {
	out := make([]byte, 20+len(m.attrs))
	binary.BigEndian.PutUint16(out[0:2], m.typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(m.attrs)+extra))
	binary.BigEndian.PutUint32(out[4:8], magicCookie)
	copy(out[8:20], m.tid[:])
	copy(out[20:], m.attrs)
	return out
}

func (m *message) addMI(key []byte) {
	buf := m.marshal(24)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	m.addAttr(attrMessageIntegrity, mac.Sum(nil))
}

func (m *message) bytes() []byte { return m.marshal(0) }

func longTermKey(user, realm, pass string) []byte {
	s := md5.Sum([]byte(user + ":" + realm + ":" + pass))
	return s[:]
}

func xorAddr(ip net.IP, port int) []byte {
	v4 := ip.To4()
	b := make([]byte, 8)
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], uint16(port)^0x2112)
	cookie := []byte{0x21, 0x12, 0xa4, 0x42}
	for i := 0; i < 4; i++ {
		b[4+i] = v4[i] ^ cookie[i]
	}
	return b
}

func parseAttrs(p []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	i := 20
	for i+4 <= len(p) {
		t := binary.BigEndian.Uint16(p[i : i+2])
		l := int(binary.BigEndian.Uint16(p[i+2 : i+4]))
		if i+4+l > len(p) {
			break
		}
		if _, dup := out[t]; !dup {
			out[t] = p[i+4 : i+4+l]
		}
		i += 4 + l + (4-l%4)%4
	}
	return out
}

func errCode(v []byte) int {
	if len(v) < 4 {
		return 0
	}
	return int(v[2])*100 + int(v[3])
}

// Alloc is one live TURN allocation with a bound channel to a fixed peer.
type Alloc struct {
	tr      transport
	channel uint16
	peerIP  net.IP
	peerPt  int
	user    string
	realm   string
	nonce   []byte
	key     []byte

	in     chan []byte
	stun   chan []byte
	closed chan struct{}
}

// Transport reports which transport this allocation runs over ("udp" or "tcp").
func (a *Alloc) Transport() string { return a.tr.kind() }

// NewAlloc dials the TURN server, authenticates, allocates a relay and binds a
// channel to peer. After this returns the allocation is ready for Send / In.
//
// transport picks the client↔server link: "udp", "tcp", or "auto" (default) —
// auto tries UDP and falls back to TCP if the server is unreachable over UDP
// (a common firewall shape: UDP blocked except DNS, TCP open). This mirrors a
// real WebRTC client's ICE-UDP→ICE-TCP fallback; the relay↔peer leg stays UDP
// either way, so the exit server is unaffected.
func NewAlloc(turnAddr, user, pass string, peer *net.UDPAddr, channel uint16, transport string) (*Alloc, error) {
	const fullTimeout = 6 * time.Second
	switch transport {
	case "udp":
		return newAllocT(dialUDP, turnAddr, user, pass, peer, channel, fullTimeout)
	case "tcp":
		return newAllocT(dialTCP, turnAddr, user, pass, peer, channel, fullTimeout)
	case "", "auto":
		// Skip the UDP probe entirely once we've learned UDP is blocked on this
		// network, so only the first allocation of a UDP-blocked run pays for it
		// (and reconnects pay nothing). ResetTransportProbe clears this on a
		// network change.
		if !udpBlocked.Load() {
			// Short probe: a working UDP path to MAX answers in tens of ms, so a
			// few seconds is plenty and fails fast when UDP is filtered.
			a, err := newAllocT(dialUDP, turnAddr, user, pass, peer, channel, autoUDPProbeTimeout)
			if err == nil {
				return a, nil
			}
			var unreachable *errUnreachable
			if !errors.As(err, &unreachable) {
				return nil, err // auth/quota/etc — TCP would fail the same way
			}
			udpBlocked.Store(true)
		}
		return newAllocT(dialTCP, turnAddr, user, pass, peer, channel, fullTimeout)
	default:
		return nil, fmt.Errorf("turn: unknown transport %q (want auto/udp/tcp)", transport)
	}
}

// autoUDPProbeTimeout bounds how long "auto" waits for a UDP challenge reply
// before falling back to TCP. A reachable MAX relay answers in tens of ms.
const autoUDPProbeTimeout = 3 * time.Second

// udpBlocked caches that UDP to MAX TURN is filtered on the current network, so
// "auto" stops re-probing UDP for every allocation. Set on the first UDP-
// unreachable failure, cleared by ResetTransportProbe.
var udpBlocked atomic.Bool

// ResetTransportProbe clears the cached "UDP is blocked" decision so "auto"
// probes UDP again. Call it when the network changes (Wi-Fi↔cellular, VPN up/
// down), where UDP reachability can flip.
func ResetTransportProbe() { udpBlocked.Store(false) }

// newAllocT runs the allocation handshake over a specific transport.
// firstReadTimeout bounds the challenge read (short in "auto" so a blocked UDP
// path falls back to TCP quickly); later reads use the normal 6s.
func newAllocT(dial func(string) (transport, error), turnAddr, user, pass string, peer *net.UDPAddr, channel uint16, firstReadTimeout time.Duration) (*Alloc, error) {
	tr, err := dial(turnAddr)
	if err != nil {
		return nil, &errUnreachable{cause: err}
	}

	a := &Alloc{
		tr: tr, channel: channel, peerIP: peer.IP, peerPt: peer.Port, user: user,
		in: make(chan []byte, 1024), stun: make(chan []byte, 8), closed: make(chan struct{}),
	}

	readTimeout := firstReadTimeout
	read := func() ([]byte, error) {
		tr.setReadDeadline(time.Now().Add(readTimeout))
		return tr.read()
	}

	// Challenge.
	a0 := &message{typ: mAllocate, tid: newTID()}
	a0.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	if err := tr.write(a0.bytes()); err != nil {
		tr.close()
		return nil, &errUnreachable{cause: err}
	}
	resp, err := read()
	if err != nil {
		tr.close()
		// No response to the very first request = the server is unreachable over
		// this transport; auto uses errUnreachable to try the other one.
		return nil, &errUnreachable{cause: fmt.Errorf("allocate challenge: %w", err)}
	}
	at := parseAttrs(resp)
	a.realm = string(at[attrRealm])
	a.nonce = append([]byte(nil), at[attrNonce]...)
	if a.realm == "" || len(a.nonce) == 0 {
		tr.close()
		return nil, fmt.Errorf("no realm/nonce")
	}
	a.key = longTermKey(user, a.realm, pass)
	readTimeout = 6 * time.Second // challenge answered; use the normal deadline

	// Authenticated Allocate.
	a1 := &message{typ: mAllocate, tid: newTID()}
	a1.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	a.auth(a1)
	tr.write(a1.bytes())
	resp, err = read()
	if err != nil {
		tr.close()
		return nil, fmt.Errorf("allocate: %w", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != mAllocateOK {
		tr.close()
		return nil, &ResponseError{Operation: "allocate", Code: errCode(parseAttrs(resp)[attrErrorCode])}
	}

	// ChannelBind.
	if err := a.bind(read); err != nil {
		tr.close()
		return nil, err
	}

	tr.setReadDeadline(time.Time{}) // clear the handshake deadline before the read loop
	go a.run()
	return a, nil
}

func (a *Alloc) auth(m *message) {
	m.addAttr(attrUsername, []byte(a.user))
	m.addAttr(attrRealm, []byte(a.realm))
	m.addAttr(attrNonce, a.nonce)
	m.addMI(a.key)
}

func (a *Alloc) bind(read func() ([]byte, error)) error {
	cb := &message{typ: mChannelBind, tid: newTID()}
	cb.addAttr(attrChannelNumber, []byte{byte(a.channel >> 8), byte(a.channel), 0, 0})
	cb.addAttr(attrXorPeerAddress, xorAddr(a.peerIP, a.peerPt))
	a.auth(cb)
	a.tr.write(cb.bytes())
	resp, err := read()
	if err != nil {
		return fmt.Errorf("channelbind: %w", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != mChannelOK {
		return &ResponseError{Operation: "channelbind", Code: errCode(parseAttrs(resp)[attrErrorCode])}
	}
	return nil
}

func (a *Alloc) run() {
	for {
		buf, err := a.tr.read()
		if err != nil {
			select {
			case <-a.closed:
				close(a.in)
				return
			default:
				// UDP: a transient read error (e.g. deadline) — keep going.
				// TCP: a stream error is terminal, so stop to avoid a busy loop.
				if a.tr.kind() == "tcp" {
					close(a.in)
					return
				}
				continue
			}
		}
		n := len(buf)
		if n >= 4 && binary.BigEndian.Uint16(buf[0:2]) == a.channel {
			l := int(binary.BigEndian.Uint16(buf[2:4]))
			if 4+l <= n {
				p := make([]byte, l)
				copy(p, buf[4:4+l])
				select {
				case a.in <- p:
				default:
				}
			}
		} else if n >= 20 {
			sb := make([]byte, n)
			copy(sb, buf[:n])
			select {
			case a.stun <- sb:
			default:
			}
		}
	}
}

func channelData(channel uint16, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(out[0:2], channel)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(data)))
	copy(out[4:], data)
	return out
}

// Send relays data to the bound peer (server) via ChannelData.
func (a *Alloc) Send(data []byte) error {
	if int64(len(data)) > MaxSendSize.Load() {
		MaxSendSize.Store(int64(len(data)))
	}
	if len(data) > 1280 {
		BigSends.Add(1)
	}
	err := a.tr.write(channelData(a.channel, data))
	if err != nil {
		SendErrors.Add(1)
	} else {
		SentPackets.Add(1)
	}
	return err
}

// In delivers inbound payloads relayed back from the peer.
func (a *Alloc) In() <-chan []byte { return a.in }

// Keepalive refreshes the allocation and re-binds the channel (both ~600s TTL),
// recovering once from a stale nonce. Call every few minutes.
func (a *Alloc) Keepalive() error {
	if err := a.refresh(); err != nil {
		return err
	}
	return a.rebind()
}

func (a *Alloc) await(want uint16) (uint16, map[uint16][]byte, error) {
	select {
	case resp := <-a.stun:
		return binary.BigEndian.Uint16(resp[0:2]), parseAttrs(resp), nil
	case <-time.After(6 * time.Second):
		return 0, nil, fmt.Errorf("timeout awaiting 0x%04x", want)
	}
}

func (a *Alloc) refresh() error {
	for attempt := 0; attempt < 2; attempt++ {
		m := &message{typ: mRefresh, tid: newTID()}
		m.addAttr(attrLifetime, []byte{0, 0, 0x02, 0x58}) // 600s
		a.auth(m)
		a.tr.write(m.bytes())
		typ, at, err := a.await(mRefreshOK)
		if err != nil {
			return err
		}
		if typ == mRefreshOK {
			return nil
		}
		if errCode(at[attrErrorCode]) == errStaleNonce && len(at[attrNonce]) > 0 {
			a.nonce = append([]byte(nil), at[attrNonce]...)
			continue
		}
		return &ResponseError{Operation: "refresh", Code: errCode(at[attrErrorCode])}
	}
	return fmt.Errorf("refresh failed after nonce retry")
}

func (a *Alloc) rebind() error {
	for attempt := 0; attempt < 2; attempt++ {
		cb := &message{typ: mChannelBind, tid: newTID()}
		cb.addAttr(attrChannelNumber, []byte{byte(a.channel >> 8), byte(a.channel), 0, 0})
		cb.addAttr(attrXorPeerAddress, xorAddr(a.peerIP, a.peerPt))
		a.auth(cb)
		a.tr.write(cb.bytes())
		typ, at, err := a.await(mChannelOK)
		if err != nil {
			return err
		}
		if typ == mChannelOK {
			return nil
		}
		if errCode(at[attrErrorCode]) == errStaleNonce && len(at[attrNonce]) > 0 {
			a.nonce = append([]byte(nil), at[attrNonce]...)
			continue
		}
		return &ResponseError{Operation: "rebind", Code: errCode(at[attrErrorCode])}
	}
	return fmt.Errorf("rebind failed after nonce retry")
}

func (a *Alloc) Close() {
	select {
	case <-a.closed:
	default:
		close(a.closed)
	}
	a.tr.close()
}

// Deallocate frees the relay on the TURN server (Refresh lifetime=0) before
// closing, so the credential's allocation quota is released immediately — letting
// a reconnect that reuses a cached credential get a fresh quota instead of 486
// (quota reached) from stale allocations that would otherwise linger ~10 min.
func (a *Alloc) Deallocate() {
	m := &message{typ: mRefresh, tid: newTID()}
	m.addAttr(attrLifetime, []byte{0, 0, 0, 0}) // 0 = delete allocation
	a.auth(m)
	b := m.bytes()
	// Send a few times: a single UDP refresh is easily lost during teardown, and a
	// missed deallocate leaves the allocation alive ~10 min, eating the credential's
	// quota so a reconnect reusing the cached cred hits 486 and needlessly re-mints.
	// (Harmless on TCP, where one write suffices but repeats do no damage.)
	for i := 0; i < 4; i++ {
		a.tr.write(b)
	}
	a.Close()
}
