package qtun

import (
	"bytes"
	"testing"
)

// Framing and reassembly, isolated from QUIC: if this is wrong, the transport
// tests fail in ways that look like the network.
func TestFragmentReassemble(t *testing.T) {
	const addr = "127.0.0.1:53"
	payload := make([]byte, 4000)
	for i := range payload {
		payload[i] = byte(i * 3)
	}
	const per = 1000

	re := newReassembler()
	n := (len(payload) + per - 1) / per
	var out []byte
	var got bool
	for i := 0; i < n; i++ {
		lo, hi := i*per, (i+1)*per
		if hi > len(payload) {
			hi = len(payload)
		}
		frame := encodeUDP(7, 42, uint8(i), uint8(n), addr, payload[lo:hi])
		f, err := decodeUDP(frame)
		if err != nil {
			t.Fatalf("frag %d: decode: %v", i, err)
		}
		if f.session != 7 || f.packetID != 42 || f.addr != addr {
			t.Fatalf("frag %d: header mangled: %+v", i, f)
		}
		var a string
		out, a, got = re.push(f)
		if got {
			if i != n-1 {
				t.Fatalf("declared complete at fragment %d of %d", i, n)
			}
			if a != addr {
				t.Fatalf("address lost: %q", a)
			}
		}
	}
	if !got {
		t.Fatal("never reassembled")
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("reassembled %d bytes, want %d", len(out), len(payload))
	}
}

func TestSingleFragmentPassesThrough(t *testing.T) {
	re := newReassembler()
	f, err := decodeUDP(encodeUDP(1, 1, 0, 1, "1.1.1.1:53", []byte("q")))
	if err != nil {
		t.Fatal(err)
	}
	out, addr, ok := re.push(f)
	if !ok || string(out) != "q" || addr != "1.1.1.1:53" {
		t.Fatalf("got %q %q %v", out, addr, ok)
	}
}
