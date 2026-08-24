// Package qtun is the STREAM mode of the breach tunnel: a minimal
// connection-oriented protocol that lets the client offer a local SOCKS5 proxy
// while the exit dials out on its behalf.
//
// Why it exists. The original ("pipe") mode is deliberately dumb: the client
// relays datagrams between a local UDP mouth and the TURN path, and something
// else — WireGuard or sing-box — terminates the inner protocol at both ends.
// That works, but it means two more moving parts on the exit and a tun device
// (hence root) on a desktop client. In stream mode the two breach binaries are
// the whole VPN: no sing-box, no wireguard-go, no privileges.
//
// Why QUIC. SOCKS5 needs an ordered, reliable, multiplexed byte stream, and the
// tunnel underneath is lossy datagrams. QUIC supplies all three plus TLS 1.3 —
// so there is no hand-rolled reliability layer and no hand-rolled crypto here,
// only framing. It runs over any net.PacketConn, which is exactly what the relay
// pool already looks like. This is NOT Hysteria2: none of its authentication,
// bandwidth negotiation or masquerade is used or needed, because both ends are
// ours. The library is shared with sing-box on mobile, so it costs no extra size
// where size matters.
//
// Framing, per stream:
//
//	client -> server   version(1) kind(1) tokenLen(1) token targetLen(2) target
//	server -> client   status(1)                      [+ session(4) when kind=UDP]
//	then                raw bytes, both ways, until either side closes
//
// kind selects TCP (the target is dialled and piped) or UDP (the exit allocates
// a relayed socket and the stream just holds it open); UDP payloads themselves
// travel as QUIC datagrams, see udp.go.
//
// The token is the client's registry password: the exit is reachable by anyone
// who can speak to the relay, so the inner protocol has to authenticate. It is
// carried per stream rather than per connection to keep the server stateless and
// free of any assumption about stream ordering.
package qtun

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
)

// ALPN identifies the protocol inside QUIC's TLS handshake. Both ends must
// agree, and a mismatch fails the handshake rather than producing garbage.
const ALPN = "breach-qtun/1"

// RelayMarker is the first byte of the one-byte packet a stream-mode client
// sends on each fresh allocation, before any QUIC. The relay picks a client's
// backend by sniffing that first byte, and stream mode carries QUIC — which is
// what Hysteria2 carries too, so it needs an explicit tag rather than a guess.
// 0x00 is unused by both neighbours: WireGuard message types are 1..4 and every
// QUIC header sets 0x40.
const RelayMarker byte = 0x00

const (
	version = 1

	statusOK     = 0
	statusAuth   = 1
	statusDial   = 2
	statusBadReq = 3
	maxTargetLen = 512
	// The exit allows itself 15s to dial, so a client that gives up at 10s
	// reports a timeout for targets the exit is about to reach — and blackholed
	// destinations, the common case for a censorship-circumvention tunnel, take
	// exactly that long to fail.
	handshakeLimit = 20 * time.Second
)

// ErrAuth is returned to a caller whose token the exit rejected.
var ErrAuth = errors.New("qtun: authentication rejected")

// quicConfig is shared by both ends; the two MUST agree on packet size, since
// this is the one QUIC parameter our unusual path makes dangerous.
func quicConfig() *quic.Config {
	return &quic.Config{
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
		// The path is TURN-relayed and wrapped in SRTP, so the usable MTU is well
		// under a normal internet path's. Start small and do NOT probe upwards:
		// a blackholed probe on this path costs a stall, and the ceiling it would
		// find is not worth it.
		// quic-go clamps anything below 1200 up to 1200 (QUIC pads Initials to
		// that), so this is the floor, not a margin — stated explicitly rather
		// than left as a number that looks tunable but is not.
		InitialPacketSize:       1200,
		DisablePathMTUDiscovery: true,
		// A browser session routinely holds more than the default 100 tunnelled
		// connections open at once; past the ceiling OpenStreamSync simply waits,
		// which surfaces as tabs that hang instead of failing.
		MaxIncomingStreams: 1024,
		// UDP (DNS, HTTP/3) rides DATAGRAM frames; see udp.go.
		EnableDatagrams: true,
	}
}

// ---- framing ---------------------------------------------------------------

func writeRequest(w io.Writer, kind byte, token, target string) error {
	if len(token) > 255 {
		return errors.New("qtun: token too long")
	}
	if len(target) == 0 || len(target) > maxTargetLen {
		return errors.New("qtun: bad target")
	}
	buf := make([]byte, 0, 5+len(token)+len(target))
	buf = append(buf, version, kind, byte(len(token)))
	buf = append(buf, token...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(target)))
	buf = append(buf, target...)
	_, err := w.Write(buf)
	return err
}

func readRequest(r io.Reader) (kind byte, token, target string, err error) {
	var head [3]byte
	if _, err = io.ReadFull(r, head[:]); err != nil {
		return 0, "", "", err
	}
	if head[0] != version {
		return 0, "", "", fmt.Errorf("qtun: unsupported version %d", head[0])
	}
	kind = head[1]
	tok := make([]byte, head[2])
	if _, err = io.ReadFull(r, tok); err != nil {
		return 0, "", "", err
	}
	var tl [2]byte
	if _, err = io.ReadFull(r, tl[:]); err != nil {
		return 0, "", "", err
	}
	n := binary.BigEndian.Uint16(tl[:])
	if n == 0 || int(n) > maxTargetLen {
		return 0, "", "", errors.New("qtun: bad target length")
	}
	tgt := make([]byte, n)
	if _, err = io.ReadFull(r, tgt); err != nil {
		return 0, "", "", err
	}
	return kind, string(tok), string(tgt), nil
}

// readFull is io.ReadFull, kept local so udp.go does not need the import.
func readFull(r io.Reader, b []byte) (int, error) { return io.ReadFull(r, b) }

// ---- server ----------------------------------------------------------------

// ServerOptions configures Serve.
type ServerOptions struct {
	// Auth reports whether a token may use the exit. Called for every stream, so
	// it must be cheap and safe for concurrent use.
	Auth func(token string) bool
	// Dial opens the outbound connection. nil uses a TCP dialer that refuses
	// anything but public addresses (see AllowPrivate).
	Dial func(ctx context.Context, target string) (net.Conn, error)
	// AllowPrivate lifts the destination policy, letting clients reach loopback,
	// RFC1918 and link-local through the exit. Off by default: the exit's own
	// admin plane and the host's LAN sit there.
	AllowPrivate bool
	// Logf is optional.
	Logf func(format string, args ...any)
}

// Serve accepts QUIC connections on pc and proxies each stream to its target.
// It blocks until the listener fails.
func Serve(ctx context.Context, pc net.PacketConn, tlsConf *tls.Config, opt ServerOptions) error {
	if opt.Auth == nil {
		return errors.New("qtun: ServerOptions.Auth is required")
	}
	if opt.Dial == nil {
		d := publicDialer(15*time.Second, opt.AllowPrivate)
		opt.Dial = func(ctx context.Context, target string) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", target)
		}
	}
	if opt.Logf == nil {
		opt.Logf = func(string, ...any) {}
	}
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPN}

	ln, err := quic.Listen(pc, tlsConf, quicConfig())
	if err != nil {
		return fmt.Errorf("qtun listen: %w", err)
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return err
		}
		go serveConn(ctx, conn, opt)
	}
}

func serveConn(ctx context.Context, conn *quic.Conn, opt ServerOptions) {
	defer conn.CloseWithError(0, "")

	sessions := newSessionTable()
	defer sessions.closeAll()
	sender := &datagramSender{conn: conn}
	go serverDatagrams(ctx, conn, sessions)

	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go serveStream(ctx, st, opt, sessions, sender)
	}
}

func serveStream(ctx context.Context, st *quic.Stream, opt ServerOptions, sessions *sessionTable, sender *datagramSender) {
	// Bound the header read: an idle stream that never states its target must not
	// hold a goroutine forever.
	_ = st.SetReadDeadline(time.Now().Add(handshakeLimit))
	kind, token, target, err := readRequest(st)
	if err != nil {
		_, _ = st.Write([]byte{statusBadReq})
		shutdown(st)
		return
	}
	_ = st.SetReadDeadline(time.Time{})

	if !opt.Auth(token) {
		if kind == kindUDP {
			_, _ = st.Write([]byte{statusAuth, 0, 0, 0, 0})
		} else {
			_, _ = st.Write([]byte{statusAuth})
		}
		shutdown(st)
		return
	}

	if kind == kindUDP {
		// Holds the stream (and the relay socket) until the client lets go.
		serveUDPSession(st, sessions, sender, opt.AllowPrivate, opt.Logf)
		return
	}
	defer st.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := opt.Dial(dialCtx, target)
	if err != nil {
		opt.Logf("qtun: dial %s: %v", target, err)
		_, _ = st.Write([]byte{statusDial})
		st.CancelRead(0) // release the stream slot; the deferred Close ends the send half
		return
	}
	defer out.Close()

	if _, err := st.Write([]byte{statusOK}); err != nil {
		st.CancelRead(0)
		return
	}
	pipe(quicHalf{st}, asHalfCloser(out))
}

// shutdown abandons a stream we are not going to read.
//
// Stream.Close() ends only the SEND direction. quic-go returns a stream's
// MAX_STREAMS credit once BOTH halves complete, and the receive half completes
// only on CancelRead or on reading to EOF — so a stream abandoned after an error
// reply holds its slot forever. With the default ceiling of 100 incoming
// streams, a hundred refused CONNECTs (blackholed hosts, blocked ad domains) is
// enough to wedge the client's OpenStreamSync permanently, and KeepAlivePeriod
// stops the idle timeout from ever clearing it.
func shutdown(st *quic.Stream) {
	st.CancelRead(0)
	_ = st.Close()
}

// pipe copies in both directions until BOTH are done, propagating each end's
// close so a half-closed connection still delivers its response.
//
// Returning on the first EOF (the obvious implementation) truncates every
// request/response protocol whose client signals "done sending" by shutting down
// its write side — `printf 'GET / HTTP/1.0\r\n\r\n' | nc -N` gets an empty
// reply.
func pipe(a, b halfCloser) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		a.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		b.CloseWrite()
	}()
	wg.Wait()
}

// halfCloser is a stream that can signal end-of-data without tearing the whole
// connection down. Both a QUIC stream and a TCP connection can; anything else
// falls back to a full close.
type halfCloser interface {
	io.ReadWriter
	CloseWrite() error
}

// quicHalf adapts a QUIC stream: its Close() already means "end of my data",
// which is exactly CloseWrite. Full teardown goes through shutdown().
type quicHalf struct{ *quic.Stream }

func (q quicHalf) CloseWrite() error { return q.Stream.Close() }

// asHalfCloser adapts a net.Conn: TCP has CloseWrite, other transports do not.
type fullCloser struct{ net.Conn }

func (f fullCloser) CloseWrite() error { return f.Close() }

func asHalfCloser(c net.Conn) halfCloser {
	if hc, ok := c.(interface {
		io.ReadWriter
		CloseWrite() error
	}); ok {
		return hc
	}
	return fullCloser{c}
}

// ---- client ----------------------------------------------------------------

// Client is a multiplexed connection to an exit running Serve.
type Client struct {
	conn   *quic.Conn
	token  string
	sender *datagramSender

	mu       sync.Mutex
	sessions map[uint32]*UDPSession
}

// Dial establishes the QUIC connection over pc. remote is nominal — pc already
// knows where its datagrams go — but QUIC needs an address to key state on.
func Dial(ctx context.Context, pc net.PacketConn, remote net.Addr, tlsConf *tls.Config, token string) (*Client, error) {
	tlsConf = tlsConf.Clone()
	tlsConf.NextProtos = []string{ALPN}
	conn, err := quic.Dial(ctx, pc, remote, tlsConf, quicConfig())
	if err != nil {
		return nil, fmt.Errorf("qtun dial: %w", err)
	}
	c := &Client{
		conn:     conn,
		token:    token,
		sender:   &datagramSender{conn: conn},
		sessions: map[uint32]*UDPSession{},
	}
	go c.readDatagrams(context.Background())
	return c, nil
}

// Open asks the exit to connect to target ("host:port") and returns the stream
// as a net.Conn once the exit reports success.
func (c *Client) Open(ctx context.Context, target string) (net.Conn, error) {
	st, err := c.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if err := writeRequest(st, kindTCP, c.token, target); err != nil {
		st.Close()
		return nil, err
	}
	var status [1]byte
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetReadDeadline(dl)
	} else {
		_ = st.SetReadDeadline(time.Now().Add(handshakeLimit))
	}
	if _, err := io.ReadFull(st, status[:]); err != nil {
		st.Close()
		return nil, err
	}
	_ = st.SetReadDeadline(time.Time{})
	switch status[0] {
	case statusOK:
		return &streamConn{Stream: st, local: c.conn.LocalAddr(), remote: c.conn.RemoteAddr()}, nil
	case statusAuth:
		st.Close()
		return nil, ErrAuth
	case statusDial:
		st.Close()
		return nil, fmt.Errorf("qtun: exit could not reach %s", target)
	default:
		st.Close()
		return nil, fmt.Errorf("qtun: exit rejected the request (status %d)", status[0])
	}
}

// Close tears down the whole multiplexed connection.
func (c *Client) Close() error { return c.conn.CloseWithError(0, "") }

// Done fires when the connection is gone (idle timeout, the exit restarting, a
// path that stayed broken). Callers that must keep working across that need it:
// nothing else reports the loss, and every later Open would simply fail.
func (c *Client) Done() <-chan struct{} { return c.conn.Context().Done() }

// streamConn adapts a QUIC stream to net.Conn: a stream carries no addresses of
// its own, so it borrows the connection's.
type streamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func (s *streamConn) LocalAddr() net.Addr  { return s.local }
func (s *streamConn) RemoteAddr() net.Addr { return s.remote }

// CloseWrite ends only our side, so a half-closed request still gets its reply.
func (s *streamConn) CloseWrite() error { return s.Stream.Close() }

// Close means "done with this connection" for a net.Conn, so it must release the
// stream slot too — Stream.Close() alone leaves the receive half outstanding and
// the credit is never returned.
func (s *streamConn) Close() error {
	s.Stream.CancelRead(0)
	return s.Stream.Close()
}

// ConstantTimeTokenMatch is a convenience for Auth implementations holding a
// small set of valid tokens: it avoids leaking which prefix matched.
func ConstantTimeTokenMatch(got string, valid []string) bool {
	ok := false
	for _, v := range valid {
		if subtle.ConstantTimeCompare([]byte(got), []byte(v)) == 1 {
			ok = true
		}
	}
	return ok
}
