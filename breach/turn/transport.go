package turn

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// transport is the client↔TURN-server link. Two implementations: UDP, where
// every datagram is exactly one STUN/ChannelData message, and TCP, where the
// same messages ride a byte stream and must be framed (RFC 5766 §2.1, §11.5).
// The rest of the package is transport-agnostic — it just writes and reads whole
// messages.
type transport interface {
	// write sends one already-marshalled message (STUN or ChannelData).
	write(msg []byte) error
	// read returns the next complete message. For UDP the returned slice is only
	// valid until the next read (reused buffer); callers copy before reusing.
	read() ([]byte, error)
	setReadDeadline(t time.Time) error
	localAddr() net.Addr
	remoteAddr() net.Addr
	close() error
	// kind is "udp" or "tcp", for diagnostics.
	kind() string
}

// errUnreachable marks a failure to get ANY response from the server (the
// challenge read timed out / the dial failed) — as opposed to an auth or quota
// rejection. "auto" uses it to decide whether falling back to the other
// transport could help.
type errUnreachable struct{ cause error }

func (e *errUnreachable) Error() string { return "turn server unreachable: " + e.cause.Error() }
func (e *errUnreachable) Unwrap() error { return e.cause }

// ── UDP ─────────────────────────────────────────────────────────────────────

type udpTransport struct {
	c     *net.UDPConn
	raddr *net.UDPAddr
	rbuf  []byte
}

func dialUDP(turnAddr string) (transport, error) {
	raddr, err := net.ResolveUDPAddr("udp", turnAddr)
	if err != nil {
		return nil, err
	}
	// Unconnected socket: avoids ICMP errors surfacing as read errors (which
	// kill/spin a connected socket) and accepts relayed data from any source.
	// Opened via ListenConfig so the Control hook protects the fd (Android).
	lc := net.ListenConfig{Control: Control}
	pc, err := lc.ListenPacket(context.Background(), "udp", "")
	if err != nil {
		return nil, err
	}
	uc := pc.(*net.UDPConn)
	uc.SetReadBuffer(4 << 20)
	uc.SetWriteBuffer(4 << 20)
	return &udpTransport{c: uc, raddr: raddr}, nil
}

func (u *udpTransport) write(msg []byte) error {
	_, err := u.c.WriteToUDP(msg, u.raddr)
	return err
}

func (u *udpTransport) read() ([]byte, error) {
	if u.rbuf == nil {
		u.rbuf = make([]byte, 65536)
	}
	n, _, err := u.c.ReadFromUDP(u.rbuf)
	if err != nil {
		return nil, err
	}
	return u.rbuf[:n], nil
}

func (u *udpTransport) setReadDeadline(t time.Time) error { return u.c.SetReadDeadline(t) }
func (u *udpTransport) localAddr() net.Addr               { return u.c.LocalAddr() }
func (u *udpTransport) remoteAddr() net.Addr              { return u.raddr }
func (u *udpTransport) close() error                      { return u.c.Close() }
func (u *udpTransport) kind() string                      { return "udp" }

// ── TCP ─────────────────────────────────────────────────────────────────────

type tcpTransport struct {
	c  net.Conn
	br *bufio.Reader
}

func dialTCP(turnAddr string) (transport, error) {
	d := net.Dialer{Timeout: 8 * time.Second, Control: Control}
	c, err := d.Dial("tcp", turnAddr)
	if err != nil {
		return nil, err
	}
	return &tcpTransport{c: c, br: bufio.NewReaderSize(c, 65536)}, nil
}

func (t *tcpTransport) write(msg []byte) error {
	// Over TCP, ChannelData must be padded to a 4-byte boundary so the next
	// message stays aligned (RFC 5766 §11.5). STUN messages are already aligned
	// (20-byte header + 4-byte-padded attributes), so padding every write to 4
	// is a no-op for them and correct for ChannelData.
	if pad := (4 - len(msg)%4) % 4; pad > 0 {
		buf := make([]byte, len(msg)+pad)
		copy(buf, msg)
		msg = buf
	}
	_, err := t.c.Write(msg)
	return err
}

func (t *tcpTransport) read() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(t.br, hdr[:]); err != nil {
		return nil, err
	}
	first := binary.BigEndian.Uint16(hdr[0:2])
	length := int(binary.BigEndian.Uint16(hdr[2:4]))

	// A STUN message type has its two high bits clear (< 0x4000); a ChannelData
	// number is 0x4000–0x7FFF. The length field means different things for each.
	if first < 0x4000 {
		// STUN: length is the attributes length; total = 20-byte header + attrs.
		if length > 65515 {
			return nil, fmt.Errorf("tcp: STUN length %d too large", length)
		}
		msg := make([]byte, 20+length)
		copy(msg, hdr[:])
		if _, err := io.ReadFull(t.br, msg[4:]); err != nil {
			return nil, err
		}
		return msg, nil
	}

	// ChannelData: total = 4-byte header + length, then padding to a 4-byte
	// boundary that is NOT counted in length.
	msg := make([]byte, 4+length)
	copy(msg, hdr[:])
	if _, err := io.ReadFull(t.br, msg[4:]); err != nil {
		return nil, err
	}
	if pad := (4 - length%4) % 4; pad > 0 {
		if _, err := io.CopyN(io.Discard, t.br, int64(pad)); err != nil {
			return nil, err
		}
	}
	return msg, nil
}

func (t *tcpTransport) setReadDeadline(dl time.Time) error { return t.c.SetReadDeadline(dl) }
func (t *tcpTransport) localAddr() net.Addr                { return t.c.LocalAddr() }
func (t *tcpTransport) remoteAddr() net.Addr               { return t.c.RemoteAddr() }
func (t *tcpTransport) close() error                       { return t.c.Close() }
func (t *tcpTransport) kind() string                       { return "tcp" }
