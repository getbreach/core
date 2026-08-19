// Package media turns each TURN allocation into a DTLS-SRTP session, so the wire
// trace is exactly a WebRTC call: a real DTLS handshake (with the use_srtp
// extension) followed by SRTP-AEAD media packets. The DTLS channel is used ONLY
// for the handshake (MAX throttles sustained DTLS application-data); data then
// flows as SRTP/RTP (first byte 0x80+), which MAX does not throttle.
package media

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"

	"github.com/pion/dtls/v2"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"

	"breach/dtlscfg"
)

const (
	PTData      = 111
	PTKeepalive = 110
	tsStep      = 960
)

// IsDTLS reports whether a datagram is a DTLS record (content types 20-63),
// i.e. a (possibly late) handshake retransmit rather than SRTP media.
func IsDTLS(b []byte) bool { return len(b) > 0 && b[0] >= 20 && b[0] < 64 }

// IsRTP reports whether a datagram looks like RTP/SRTP (first two bits = 10).
func IsRTP(b []byte) bool { return len(b) > 0 && b[0]&0xc0 == 0x80 }

type Session struct {
	out, in *srtp.Context

	mu   sync.Mutex
	ssrc uint32
	seq  uint16
	ts   uint32
}

// Client performs the DTLS client handshake over conn and derives SRTP keys.
// After key export the DTLS conn is closed so its background reader stops
// competing for inbound datagrams (conn.Close must free, not kill, the channel).
func Client(conn net.Conn) (*Session, error) {
	dc, err := dtls.Client(conn, dtlscfg.Client())
	if err != nil {
		return nil, fmt.Errorf("dtls client: %w", err)
	}
	s, err := newSession(dc, true)
	dc.Close()
	return s, err
}

// Server performs the DTLS server handshake over conn and derives SRTP keys.
func Server(conn net.Conn) (*Session, error) {
	cfg, err := dtlscfg.Server()
	if err != nil {
		return nil, err
	}
	dc, err := dtls.Server(conn, cfg)
	if err != nil {
		return nil, fmt.Errorf("dtls server: %w", err)
	}
	s, err := newSession(dc, false)
	dc.Close()
	return s, err
}

func newSession(dc *dtls.Conn, isClient bool) (*Session, error) {
	state := dc.ConnectionState()
	// AEAD_AES_128_GCM: 16-byte key + 12-byte salt, per direction.
	km, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, 2*(16+12))
	if err != nil {
		return nil, fmt.Errorf("export keying material: %w", err)
	}
	ck, sk := km[0:16], km[16:32]
	cs, ss := km[32:44], km[44:56]

	encKey, encSalt, decKey, decSalt := ck, cs, sk, ss
	if !isClient {
		encKey, encSalt, decKey, decSalt = sk, ss, ck, cs
	}

	profile := srtp.ProtectionProfileAeadAes128Gcm
	out, err := srtp.CreateContext(encKey, encSalt, profile)
	if err != nil {
		return nil, fmt.Errorf("srtp out: %w", err)
	}
	// No anti-replay: the relay reorders datagrams and we don't need replay
	// protection (the inner WireGuard/Hysteria provides real security). With it
	// on, reordered packets get dropped — major downstream loss.
	in, err := srtp.CreateContext(decKey, decSalt, profile, srtp.SRTPNoReplayProtection())
	if err != nil {
		return nil, fmt.Errorf("srtp in: %w", err)
	}

	var seed [10]byte
	rand.Read(seed[:])
	return &Session{
		out: out, in: in,
		ssrc: binary.BigEndian.Uint32(seed[0:4]),
		seq:  binary.BigEndian.Uint16(seed[4:6]),
		ts:   binary.BigEndian.Uint32(seed[6:10]),
	}, nil
}

// Protect builds an RTP packet of payload type pt carrying payload and returns
// the encrypted SRTP packet ready to relay.
func (s *Session) Protect(pt byte, payload []byte) ([]byte, error) {
	s.mu.Lock()
	pkt := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: pt, SequenceNumber: s.seq, Timestamp: s.ts, SSRC: s.ssrc},
		Payload: payload,
	}
	s.seq++
	s.ts += tsStep
	s.mu.Unlock()

	raw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	return s.out.EncryptRTP(nil, raw, nil)
}

// Unprotect decrypts an SRTP packet and returns its payload type and payload.
func (s *Session) Unprotect(wire []byte) (pt byte, payload []byte, err error) {
	dec, err := s.in.DecryptRTP(nil, wire, nil)
	if err != nil {
		return 0, nil, err
	}
	var p rtp.Packet
	if err := p.Unmarshal(dec); err != nil {
		return 0, nil, err
	}
	return p.PayloadType, p.Payload, nil
}
