package turn

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// stunMessage builds a minimal STUN message with an attrs blob already padded to
// 4 bytes (as addAttr guarantees), so total length is 4-aligned.
func stunMessage(typ uint16, attrs []byte) []byte {
	msg := make([]byte, 20+len(attrs))
	binary.BigEndian.PutUint16(msg[0:2], typ)
	binary.BigEndian.PutUint16(msg[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(msg[4:8], magicCookie)
	copy(msg[20:], attrs)
	return msg
}

// TCP carries STUN and ChannelData on one stream; the framer must split them
// back into whole messages, honouring ChannelData's 4-byte padding (RFC 5766
// §11.5) which is NOT counted in the length field.
func TestTCPFramerSplitsStream(t *testing.T) {
	stun := stunMessage(mAllocateOK, []byte{0, 8, 0, 4, 1, 2, 3, 4}) // 8-byte attrs
	// ChannelData with a 5-byte payload -> length 5, padded to 8 on the wire.
	payload := []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE}
	cd := channelData(0x4000, payload) // 4 header + 5 = 9 bytes, unpadded
	cdPadded := append(append([]byte{}, cd...), 0, 0, 0)

	var stream bytes.Buffer
	stream.Write(stun)
	stream.Write(cdPadded)
	stream.Write(stun) // a second message right after the padding must still frame

	tr := &tcpTransport{br: bufio.NewReader(&stream)}

	got1, err := tr.read()
	if err != nil {
		t.Fatalf("read STUN: %v", err)
	}
	if !bytes.Equal(got1, stun) {
		t.Errorf("STUN msg mismatch\n got % x\nwant % x", got1, stun)
	}

	got2, err := tr.read()
	if err != nil {
		t.Fatalf("read ChannelData: %v", err)
	}
	if binary.BigEndian.Uint16(got2[0:2]) != 0x4000 {
		t.Errorf("channel number = %#x", got2[0:2])
	}
	if l := binary.BigEndian.Uint16(got2[2:4]); int(l) != len(payload) {
		t.Errorf("length = %d, want %d", l, len(payload))
	}
	if !bytes.Equal(got2[4:], payload) {
		t.Errorf("payload = % x, want % x", got2[4:], payload)
	}

	got3, err := tr.read()
	if err != nil {
		t.Fatalf("read second STUN: %v", err)
	}
	if !bytes.Equal(got3, stun) {
		t.Error("padding was not consumed — second message misframed")
	}
}

// A message split across many small TCP segments must still reassemble.
func TestTCPFramerReassemblesAcrossReads(t *testing.T) {
	stun := stunMessage(mChannelOK, []byte{0, 0, 0, 0})
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		// Dribble one byte at a time to stress partial reads.
		for _, b := range stun {
			server.Write([]byte{b})
		}
	}()

	tr := &tcpTransport{c: client, br: bufio.NewReader(client)}
	tr.setReadDeadline(time.Now().Add(2 * time.Second))
	got, err := tr.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, stun) {
		t.Errorf("reassembled %x, want %x", got, stun)
	}
}

// write pads ChannelData to a 4-byte boundary on TCP, and leaves already-aligned
// STUN messages untouched.
func TestTCPWritePadsChannelData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tr := &tcpTransport{c: client}

	// A ChannelData with a 5-byte payload = 9 bytes, must go out as 12 (padded).
	cd := channelData(0x4000, []byte{1, 2, 3, 4, 5})
	go tr.write(cd)

	buf := make([]byte, 32)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(server, buf[:12])
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != 12 {
		t.Errorf("wrote %d bytes, want 12 (9 + 3 padding)", n)
	}
	// The length field still reflects the unpadded payload.
	if l := binary.BigEndian.Uint16(buf[2:4]); l != 5 {
		t.Errorf("length field = %d, want 5 (padding is not counted)", l)
	}

	// A STUN message is already 4-aligned; write must not grow it.
	stun := stunMessage(mAllocate, []byte{0, 8, 0, 4, 9, 9, 9, 9})
	go tr.write(stun)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	got := make([]byte, len(stun))
	if _, err := io.ReadFull(server, got); err != nil {
		t.Fatalf("read stun: %v", err)
	}
	if !bytes.Equal(got, stun) {
		t.Errorf("STUN message was altered on write")
	}
}

// A write followed by a read round-trips through the framer unchanged.
func TestTCPWriteReadRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	wtr := &tcpTransport{c: a}
	rtr := &tcpTransport{c: b, br: bufio.NewReader(b)}

	cd := channelData(0x4001, bytes.Repeat([]byte{0x7}, 13))
	go wtr.write(cd)

	rtr.setReadDeadline(time.Now().Add(2 * time.Second))
	got, err := rtr.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, cd) {
		t.Errorf("round-trip mismatch\n got % x\nwant % x", got, cd)
	}
}

// The cached "UDP is blocked" decision must be resettable, so a network change
// makes auto re-probe UDP instead of staying pinned to TCP.
func TestResetTransportProbe(t *testing.T) {
	udpBlocked.Store(true)
	ResetTransportProbe()
	if udpBlocked.Load() {
		t.Error("ResetTransportProbe did not clear the cached decision")
	}
}

// The auto UDP probe timeout must be short enough to fail fast on a blocked
// network but comfortably longer than a real MAX RTT.
func TestAutoUDPProbeTimeoutIsShort(t *testing.T) {
	if autoUDPProbeTimeout < time.Second || autoUDPProbeTimeout > 4*time.Second {
		t.Errorf("autoUDPProbeTimeout = %v; want a small few-second value", autoUDPProbeTimeout)
	}
}

// An unknown transport name is rejected up front, not silently treated as auto.
func TestNewAllocRejectsUnknownTransport(t *testing.T) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
	if _, err := NewAlloc("127.0.0.1:1", "u", "p", peer, 0x4000, "carrier-pigeon"); err == nil {
		t.Error("expected an error for an unknown transport")
	}
}
