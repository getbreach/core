package media

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/pion/srtp/v3"
)

// newLoopbackSession builds a Session whose out and in contexts share one key,
// so a packet Protect encrypts can be Unprotect'd back — a loopback that
// exercises the real SRTP + RTP-padding path without a DTLS handshake.
func newLoopbackSession(t *testing.T, padMax byte) *Session {
	t.Helper()
	key := make([]byte, 16)
	salt := make([]byte, 12)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	profile := srtp.ProtectionProfileAeadAes128Gcm
	out, err := srtp.CreateContext(key, salt, profile)
	if err != nil {
		t.Fatal(err)
	}
	in, err := srtp.CreateContext(key, salt, profile, srtp.SRTPNoReplayProtection())
	if err != nil {
		t.Fatal(err)
	}
	return &Session{out: out, in: in, ssrc: 0x11223344, seq: 1, padMax: padMax}
}

// Padding is a send-side concern only: whatever Protect appends, Unprotect must
// hand back the exact original payload and payload type. Runs many packets per
// payload so a range of random pad sizes (including zero) is exercised.
func TestProtectUnprotectRoundTripWithPadding(t *testing.T) {
	s := newLoopbackSession(t, DefaultMaxPadding)
	payloads := [][]byte{
		{},
		[]byte("x"),
		[]byte("a slightly longer keepalive-sized payload"),
		bytes.Repeat([]byte{0xAB}, 1200),
	}
	for _, want := range payloads {
		for i := 0; i < 64; i++ {
			wire, err := s.Protect(PTData, want)
			if err != nil {
				t.Fatalf("Protect(len=%d): %v", len(want), err)
			}
			pt, got, err := s.Unprotect(wire)
			if err != nil {
				t.Fatalf("Unprotect(len=%d): %v", len(want), err)
			}
			if pt != PTData {
				t.Fatalf("pt = %d; want %d", pt, PTData)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("payload round trip mismatch: got %d bytes, want %d", len(got), len(want))
			}
		}
	}
}

// The point of the change: a constant payload must NOT map to a constant wire
// size, and the spread must stay within the configured bound.
func TestPaddingSpreadsWireSize(t *testing.T) {
	const padMax = 16
	s := newLoopbackSession(t, padMax)
	payload := []byte("constant payload")

	sizes := map[int]int{}
	min, max := 1<<30, 0
	for i := 0; i < 400; i++ {
		wire, err := s.Protect(PTData, payload)
		if err != nil {
			t.Fatal(err)
		}
		n := len(wire)
		sizes[n]++
		if n < min {
			min = n
		}
		if n > max {
			max = n
		}
	}
	if len(sizes) < 3 {
		t.Errorf("padding produced only %d distinct wire sizes; expected a spread", len(sizes))
	}
	// The added bytes are exactly the RTP padding, so the span cannot exceed the
	// configured maximum.
	if span := max - min; span > padMax {
		t.Errorf("wire-size span %d exceeds padMax %d", span, padMax)
	}
}

// padMax == 0 must reproduce the old behaviour exactly: one payload, one size.
func TestNoPaddingWhenDisabled(t *testing.T) {
	s := newLoopbackSession(t, 0)
	payload := []byte("constant payload")

	first, err := s.Protect(PTData, payload)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		wire, err := s.Protect(PTData, payload)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) != len(first) {
			t.Fatalf("padMax=0 changed wire size: %d vs %d", len(wire), len(first))
		}
	}
}

// SetMaxPadding is the configuration seam; disabling it at runtime must hold.
func TestSetMaxPaddingDisables(t *testing.T) {
	s := newLoopbackSession(t, DefaultMaxPadding)
	s.SetMaxPadding(0)
	payload := []byte("constant payload")
	first, _ := s.Protect(PTData, payload)
	for i := 0; i < 32; i++ {
		wire, _ := s.Protect(PTData, payload)
		if len(wire) != len(first) {
			t.Fatalf("SetMaxPadding(0) did not disable padding: %d vs %d", len(wire), len(first))
		}
	}
}

// A packet already at/over the relay's size cliff must never be grown: padding
// it past ~1300 would get it dropped by the TURN relay. Only packets with
// headroom below maxPaddedWire get padded.
func TestPaddingRespectsMTUCeiling(t *testing.T) {
	s := newLoopbackSession(t, DefaultMaxPadding)

	// A packet already over the clean-relay ceiling: no padding, ever.
	full := bytes.Repeat([]byte{0xCD}, 1400)
	base, err := s.Protect(PTData, full)
	if err != nil {
		t.Fatal(err)
	}
	// A full inner packet already exceeds the ceiling unpadded — that is the
	// traffic that already flows — so it must be left exactly as-is.
	if len(base) <= maxPaddedWire {
		t.Fatalf("test assumption broken: full packet wire %d is below the ceiling", len(base))
	}
	for i := 0; i < 200; i++ {
		wire, err := s.Protect(PTData, full)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) != len(base) {
			t.Fatalf("a full-size packet was padded (%d vs %d) — MTU risk", len(wire), len(base))
		}
		pt, got, derr := s.Unprotect(wire)
		if derr != nil || pt != PTData || !bytes.Equal(got, full) {
			t.Fatalf("round trip of full packet failed: %v", derr)
		}
	}

	// A packet just below the ceiling gets only the sliver of headroom: the
	// padded wire size must never cross maxPaddedWire.
	near := bytes.Repeat([]byte{0xCD}, maxPaddedWire-rtpHeaderLen-srtpGCMTag-4)
	maxSeen := 0
	for i := 0; i < 400; i++ {
		wire, err := s.Protect(PTData, near)
		if err != nil {
			t.Fatal(err)
		}
		if len(wire) > maxSeen {
			maxSeen = len(wire)
		}
	}
	if maxSeen > maxPaddedWire {
		t.Errorf("near-ceiling packet grew to %d, past the ceiling %d", maxSeen, maxPaddedWire)
	}
}
