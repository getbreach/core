// Package rtpframe wraps tunnel datagrams in an RTP header so the relayed
// payload looks like WebRTC/SRTP media (first byte 0x80, payload type, sequence,
// timestamp, SSRC) rather than a raw WireGuard/QUIC packet. The payload is
// already encrypted by the inner tunnel (WireGuard/Hysteria), so RTP-header +
// encrypted-payload is, to a DPI that can't decrypt, indistinguishable from
// RTP-header + SRTP-ciphertext.
package rtpframe

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

const (
	HeaderSize  = 12
	PTData      = 111 // dynamic payload type carrying tunnel data
	PTKeepalive = 110 // keepalive (dropped by receiver), keeps the stream "live"
	tsStep      = 960 // ~20ms @ 48kHz, like Opus
)

// Sender holds per-stream RTP state (one per TURN allocation / relay peer).
type Sender struct {
	mu   sync.Mutex
	ssrc uint32
	seq  uint16
	ts   uint32
}

func NewSender() *Sender {
	var b [10]byte
	rand.Read(b[:])
	return &Sender{
		ssrc: binary.BigEndian.Uint32(b[0:4]),
		seq:  binary.BigEndian.Uint16(b[4:6]),
		ts:   binary.BigEndian.Uint32(b[6:10]),
	}
}

// Frame builds an RTP packet of the given payload type carrying payload.
func (s *Sender) Frame(pt byte, payload []byte) []byte {
	out := make([]byte, HeaderSize+len(payload))
	out[0] = 0x80 // V=2, P=0, X=0, CC=0
	out[1] = pt & 0x7f
	s.mu.Lock()
	binary.BigEndian.PutUint16(out[2:4], s.seq)
	binary.BigEndian.PutUint32(out[4:8], s.ts)
	binary.BigEndian.PutUint32(out[8:12], s.ssrc)
	s.seq++
	s.ts += tsStep
	s.mu.Unlock()
	copy(out[HeaderSize:], payload)
	return out
}

// Parse validates an RTP packet and returns its payload type and payload.
func Parse(b []byte) (pt byte, payload []byte, ok bool) {
	if len(b) < HeaderSize || b[0]&0xc0 != 0x80 {
		return 0, nil, false
	}
	return b[1] & 0x7f, b[HeaderSize:], true
}
