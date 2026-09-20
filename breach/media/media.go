// Package media turns each TURN allocation into a DTLS-SRTP session, so the wire
// trace is exactly a WebRTC call: a real DTLS handshake (with the use_srtp
// extension) followed by SRTP-AEAD media packets. The DTLS channel is used ONLY
// for the handshake (MAX throttles sustained DTLS application-data); data then
// flows as SRTP/RTP (first byte 0x80+), which MAX does not throttle.
package media

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
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

	// DefaultMaxPadding bounds the random RTP padding Protect adds to each packet
	// (see Session.padMax). On by default: without it the wire packet size is a
	// fixed offset from the inner WireGuard/QUIC packet, so a size histogram
	// separates the tunnel from a real call for free. A real call's packet sizes
	// vary; ours should too. Kept modest because every byte here is pure overhead
	// on a keepalive-heavy path. 0 disables it.
	DefaultMaxPadding = 16

	// maxPaddedWire caps the SRTP packet size Protect will pad UP TO. The binding
	// limit is not the path MTU but the TURN relay's own size cliff: ChannelData
	// payloads (i.e. these SRTP packets) up to ~1280 relay cleanly, above ~1300
	// they are dropped (see README, turn.Send's BigSends threshold, and the WG
	// MTU of 1280). Padding must never push a packet across that cliff, so it may
	// only fill up to the clean ceiling. Full-size packets already at/over it get
	// no padding — their size varies with the traffic anyway — while the small,
	// constant-size ones (keepalives above all, the loudest fingerprint) get the
	// whole range.
	maxPaddedWire = 1280
	rtpHeaderLen  = 12
	srtpGCMTag    = 16
)

// IsDTLS reports whether a datagram is a DTLS record (content types 20-63),
// i.e. a (possibly late) handshake retransmit rather than SRTP media.
func IsDTLS(b []byte) bool { return len(b) > 0 && b[0] >= 20 && b[0] < 64 }

// IsRTP reports whether a datagram looks like RTP/SRTP (first two bits = 10).
func IsRTP(b []byte) bool { return len(b) > 0 && b[0]&0xc0 == 0x80 }

type Session struct {
	out, in *srtp.Context

	mu     sync.Mutex
	inMu   sync.Mutex
	ssrc   uint32
	seq    uint16
	ts     uint32
	padMax byte // max RTP PaddingSize Protect may add; 0 disables padding
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

// ClientContext bounds a new stream handshake without affecting other streams.
func ClientContext(ctx context.Context, conn net.Conn) (*Session, error) {
	dc, err := dtls.ClientWithContext(ctx, conn, dtlscfg.Client())
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
		ssrc:   binary.BigEndian.Uint32(seed[0:4]),
		seq:    binary.BigEndian.Uint16(seed[4:6]),
		ts:     binary.BigEndian.Uint32(seed[6:10]),
		padMax: DefaultMaxPadding,
	}, nil
}

// SetMaxPadding overrides the upper bound on the random RTP padding Protect adds
// to each packet; 0 disables padding entirely. Padding is self-describing on the
// wire (RFC 3550 §5.1) and stripped by the receiver's rtp.Unmarshal, so the two
// ends need not agree on this value — each shapes only its own outbound.
// It may be changed concurrently with Protect.
func (s *Session) SetMaxPadding(max byte) {
	s.mu.Lock()
	s.padMax = max
	s.mu.Unlock()
}

// Protect builds an RTP packet of payload type pt carrying payload and returns
// the encrypted SRTP packet ready to relay.
//
// When padMax is set it appends a random amount of RTP padding (RFC 3550 §5.1),
// so the wire packet size stops being a fixed offset from the inner payload —
// otherwise a size histogram tells this tunnel apart from a real call at a
// glance. The pad bytes sit inside the SRTP-encrypted region, so they are
// ciphertext on the wire and need no randomising of their own; only the header
// P bit and the trailing length byte are structural, and both are what a real
// padded RTP stream carries. The receiver's rtp.Unmarshal strips it back off, so
// this is a send-only change that needs no coordination with the far end.
func (s *Session) Protect(pt byte, payload []byte) ([]byte, error) {
	s.mu.Lock()
	// Sequence allocation and SRTP rollover/cipher state are one operation.
	// Uplink data and keepalives may share this session concurrently.
	defer s.mu.Unlock()
	pkt := &rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: pt, SequenceNumber: s.seq, Timestamp: s.ts, SSRC: s.ssrc},
		Payload: payload,
	}
	s.seq++
	s.ts += tsStep
	// [0, room]: leaving some packets unpadded keeps the padding from being a
	// constant shift an observer could just subtract back out. PaddingSize counts
	// the trailing length byte itself, so any n >= 1 is a valid pad (RFC 3550).
	// room is the headroom to maxPaddedWire, so a packet already at/over the relay
	// cliff (room <= 0) is never grown across it.
	if s.padMax > 0 {
		max := int(s.padMax)
		if room := maxPaddedWire - (rtpHeaderLen + len(payload) + srtpGCMTag); room < max {
			max = room
		}
		if max > 0 {
			if n := mrand.IntN(max + 1); n > 0 {
				pkt.Header.Padding = true
				pkt.Header.PaddingSize = byte(n)
			}
		}
	}
	raw, err := pkt.Marshal()
	if err != nil {
		return nil, err
	}
	return s.out.EncryptRTP(nil, raw, nil)
}

// Unprotect decrypts an SRTP packet and returns its payload type and payload.
func (s *Session) Unprotect(wire []byte) (pt byte, payload []byte, err error) {
	s.inMu.Lock()
	defer s.inMu.Unlock()
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
