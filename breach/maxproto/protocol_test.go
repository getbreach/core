package maxproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"testing"
	"testing/iotest"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
)

// Wire-format conformance vectors, ported from kolibri-net/tests/vectors.rs.
// Both implementations talk to the same server, so the header layout, the
// compression sniffing and the lenient LZ4-block decoder must agree exactly.
// Opcode numbers below match kolibri-net/src/protocol/opcodes.rs.
// opLogin is not redeclared here — auth.go already carries it.
const (
	opPing      = 1
	opChatsList = 53
	opMsgSend   = 64
)

// msgpack for {"a": 1}: fixmap(1) + fixstr "a" + int 1.
var msgpackA1 = []byte{0x81, 0xA1, 0x61, 0x01}

// serverPacket hand-builds an inbound packet; packPacket only emits requests
// (cmd 0, flag 0), so responses and compressed bodies need building by hand.
func serverPacket(cmd byte, opcode, seq uint16, flag byte, body []byte) []byte {
	out := make([]byte, headerSize+len(body))
	out[0] = protocolVer
	out[1] = cmd
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint16(out[4:6], opcode)
	binary.BigEndian.PutUint32(out[6:10], uint32(flag)<<24|uint32(len(body))&0xFFFFFF)
	copy(out[headerSize:], body)
	return out
}

// Ported from header_layout_matches_dart_wire_format. Pins the full frame, so it
// also asserts that Go's msgpack encoder produces kolibri's MSGPACK_A1.
func TestHeaderLayoutMatchesWireFormat(t *testing.T) {
	got, err := packPacket(opLogin, 5, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}
	want := []byte{
		10,   // ver
		0,    // cmd (request)
		0, 5, // seq = 5
		0, 19, // opcode = LOGIN
		0, 0, 0, 4, // packedLen: flag 0 | len 4
		0x81, 0xA1, 0x61, 0x01, // payload
	}
	if !bytes.Equal(got, want) {
		t.Errorf("frame mismatch\n got % x\nwant % x", got, want)
	}
}

// Ported from roundtrip_uncompressed.
func TestRoundtripUncompressed(t *testing.T) {
	raw, err := packPacket(opMsgSend, 42, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}
	pkt, err := readPacket(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if pkt.Ver != protocolVer {
		t.Errorf("ver = %d, want %d", pkt.Ver, protocolVer)
	}
	if pkt.Cmd != cmdRequest {
		t.Errorf("cmd = %d, want %d", pkt.Cmd, cmdRequest)
	}
	if pkt.Seq != 42 {
		t.Errorf("seq = %d, want 42", pkt.Seq)
	}
	if pkt.Opcode != opMsgSend {
		t.Errorf("opcode = %d, want %d", pkt.Opcode, opMsgSend)
	}
	m, ok := pkt.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T, want map[string]any", pkt.Payload)
	}
	if len(m) != 1 || toInt64(m["a"]) != 1 {
		t.Errorf("payload = %#v, want {\"a\": 1}", m)
	}
}

// Ported from empty_payload_packet. A zero-length body must decode to a packet
// with a nil payload rather than a msgpack error.
//
// Divergence from kolibri: kolibri's encode() takes pre-serialized bytes and can
// emit a truly empty body, while packPacket msgpack-encodes its argument, so
// packPacket(op, seq, nil) sends a 1-byte msgpack nil (0xC0), not an empty body.
// Only the inbound direction is exercised here because only the server sends
// header-only packets.
func TestEmptyPayloadPacket(t *testing.T) {
	raw := serverPacket(cmdOK, opPing, 1, 0, nil)
	if len(raw) != headerSize {
		t.Fatalf("frame length = %d, want %d", len(raw), headerSize)
	}
	pkt, err := readPacket(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	if pkt.Payload != nil {
		t.Errorf("payload = %#v, want nil", pkt.Payload)
	}
	if pkt.Opcode != opPing {
		t.Errorf("opcode = %d, want %d", pkt.Opcode, opPing)
	}
	if !pkt.IsOK() {
		t.Errorf("cmd = %d, want OK", pkt.Cmd)
	}
}

// Ported from framing_reassembles_across_chunks. maxproto frames off a
// bufio.Reader instead of kolibri's PacketReceiver, so a one-byte-at-a-time
// reader is the equivalent stress on the partial-header / partial-body paths.
func TestFramingReassemblesAcrossChunks(t *testing.T) {
	var stream bytes.Buffer
	for _, p := range []struct {
		opcode, seq uint16
	}{
		{opPing, 1},
		{opMsgSend, 2},
		{opChatsList, 3},
	} {
		raw, err := packPacket(p.opcode, p.seq, map[string]any{"a": 1})
		if err != nil {
			t.Fatalf("packPacket: %v", err)
		}
		stream.Write(raw)
	}

	r := bufio.NewReader(iotest.OneByteReader(bytes.NewReader(stream.Bytes())))
	for i, wantSeq := range []uint16{1, 2, 3} {
		pkt, err := readPacket(r)
		if err != nil {
			t.Fatalf("packet %d: %v", i, err)
		}
		if pkt.Seq != wantSeq {
			t.Errorf("packet %d: seq = %d, want %d", i, pkt.Seq, wantSeq)
		}
	}
	if _, err := readPacket(r); err != io.EOF {
		t.Errorf("after the last packet: err = %v, want EOF (nothing buffered)", err)
	}
}

// Ported from framing_handles_multiple_packets_in_one_chunk.
func TestFramingHandlesMultiplePacketsInOneChunk(t *testing.T) {
	a, err := packPacket(opPing, 10, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}
	b, err := packPacket(opPing, 11, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}

	r := bufio.NewReader(bytes.NewReader(append(append([]byte{}, a...), b...)))
	for _, wantSeq := range []uint16{10, 11} {
		pkt, err := readPacket(r)
		if err != nil {
			t.Fatalf("readPacket: %v", err)
		}
		if pkt.Seq != wantSeq {
			t.Errorf("seq = %d, want %d", pkt.Seq, wantSeq)
		}
	}
}

// The header flag only says "compressed", not which codec; a set flag must send
// the body through the sniffer. The body is a literals-only LZ4 block whose
// literals are exactly msgpackA1.
func TestInboundCompressedPayloadIsDecompressed(t *testing.T) {
	block := append([]byte{0x40}, msgpackA1...) // token: 4 literals, 0 match
	raw := serverPacket(cmdOK, opMsgSend, 3, 0x02, block)

	pkt, err := readPacket(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("readPacket: %v", err)
	}
	m, ok := pkt.Payload.(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T, want map[string]any", pkt.Payload)
	}
	if toInt64(m["a"]) != 1 {
		t.Errorf("payload = %#v, want {\"a\": 1}", m)
	}
}

// Divergence from kolibri, pinned deliberately: kolibri's codec compresses any
// outbound payload >= COMPRESSION_THRESHOLD (32 B) as an LZ4 block and puts a
// size hint in the flag byte, while maxproto always sends flag 0 uncompressed.
// The server accepts both. If maxproto ever starts compressing, this test should
// be replaced rather than deleted — the two must not diverge silently.
func TestOutboundIsAlwaysUncompressed(t *testing.T) {
	raw, err := packPacket(opMsgSend, 7, map[string]any{"pad": string(bytes.Repeat([]byte{0xAB}, 200))})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}
	if len(raw) < headerSize+200 {
		t.Fatalf("frame is %d bytes for a 200-byte payload — unexpected compression", len(raw))
	}
	if flag := raw[6]; flag != 0 {
		t.Errorf("compression flag = %d, want 0 (maxproto sends uncompressed)", flag)
	}
}

// Ported from lz4_block_literals_only.
func TestLZ4BlockLiteralsOnly(t *testing.T) {
	src := []byte{0x50, 'h', 'e', 'l', 'l', 'o'} // token 0x50 = 5 literals
	out, err := lz4BlockDecompress(src, maxDecompressedLen)
	if err != nil {
		t.Fatalf("lz4BlockDecompress: %v", err)
	}
	if string(out) != "hello" {
		t.Errorf("out = %q, want %q", out, "hello")
	}
}

// Ported from lz4_block_with_match_copy: 1 literal 'a', then a back-reference of
// length 4 at offset 1 — the overlapping copy that a naive memmove gets wrong.
func TestLZ4BlockWithMatchCopy(t *testing.T) {
	src := []byte{0x10, 'a', 0x01, 0x00}
	out, err := lz4BlockDecompress(src, maxDecompressedLen)
	if err != nil {
		t.Fatalf("lz4BlockDecompress: %v", err)
	}
	if string(out) != "aaaaa" {
		t.Errorf("out = %q, want %q", out, "aaaaa")
	}
}

// Ported from lz4_block_via_sniffer_default_path: no magic prefix falls through
// to the block decoder.
func TestDecompressSniffsBlockByDefault(t *testing.T) {
	out, err := decompress([]byte{0x50, 'w', 'o', 'r', 'l', 'd'})
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if string(out) != "world" {
		t.Errorf("out = %q, want %q", out, "world")
	}
}

// Ported from lz4_frame_roundtrip_and_sniff.
func TestDecompressSniffsLZ4Frame(t *testing.T) {
	data := make([]byte, 500)
	for i := range data {
		data[i] = byte(i % 7)
	}

	var buf bytes.Buffer
	w := lz4.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		t.Fatalf("lz4 write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("lz4 close: %v", err)
	}

	framed := buf.Bytes()
	if want := []byte{0x04, 0x22, 0x4D, 0x18}; !bytes.Equal(framed[:4], want) {
		t.Fatalf("frame magic = % x, want % x", framed[:4], want)
	}
	out, err := decompress(framed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("roundtrip mismatch (%d bytes out, %d in)", len(out), len(data))
	}
}

// Ported from zstd_sniff_and_decompress.
func TestDecompressSniffsZstd(t *testing.T) {
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i % 13)
	}

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	compressed := enc.EncodeAll(data, nil)
	enc.Close()

	if want := []byte{0x28, 0xB5, 0x2F, 0xFD}; !bytes.Equal(compressed[:4], want) {
		t.Fatalf("zstd magic = % x, want % x", compressed[:4], want)
	}
	out, err := decompress(compressed)
	if err != nil {
		t.Fatalf("decompress: %v", err)
	}
	if !bytes.Equal(out, data) {
		t.Errorf("roundtrip mismatch (%d bytes out, %d in)", len(out), len(data))
	}
}

// Decompression-bomb ceiling. kolibri caps at 32 MiB
// (compress::MAX_DECOMPRESSED_SIZE), maxproto at 16 MiB — a deliberate
// difference, not a protocol one, since the cap is local policy.
func TestLZ4BlockRespectsSizeLimit(t *testing.T) {
	if _, err := lz4BlockDecompress([]byte{0x50, 'h', 'e', 'l', 'l', 'o'}, 3); err == nil {
		t.Error("expected a size-limit error on literals past the cap")
	}
	// A match copy must be capped too, not just the literal run.
	if _, err := lz4BlockDecompress([]byte{0x10, 'a', 0x01, 0x00}, 2); err == nil {
		t.Error("expected a size-limit error on a match copy past the cap")
	}
	if maxDecompressedLen != 16<<20 {
		t.Errorf("maxDecompressedLen = %d; update the comment above if this moved", maxDecompressedLen)
	}
}

// Malformed blocks must error, not panic or return silent garbage — the body is
// attacker-controlled if the TLS peer is.
func TestLZ4BlockRejectsMalformedInput(t *testing.T) {
	cases := []struct {
		name string
		src  []byte
	}{
		{"literals past end", []byte{0x50, 'h', 'i'}},
		{"zero match offset", []byte{0x10, 'a', 0x00, 0x00}},
		{"offset before start of output", []byte{0x10, 'a', 0x09, 0x00}},
		{"truncated offset", []byte{0x10, 'a', 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if out, err := lz4BlockDecompress(tc.src, maxDecompressedLen); err == nil {
				t.Errorf("no error, got %q", out)
			}
		})
	}
}

// readPacket must surface a short read rather than block or return a half packet.
func TestReadPacketTruncated(t *testing.T) {
	raw, err := packPacket(opMsgSend, 1, map[string]any{"a": 1})
	if err != nil {
		t.Fatalf("packPacket: %v", err)
	}
	for _, n := range []int{0, 4, headerSize, len(raw) - 1} {
		if _, err := readPacket(bytes.NewReader(raw[:n])); err == nil {
			t.Errorf("truncated to %d bytes: expected an error", n)
		}
	}
}

// Server maps arrive as map[any]any from msgpack; normalize must turn them into
// map[string]any recursively, since mint.go indexes responses by string key.
func TestNormalizeNestedMaps(t *testing.T) {
	body := map[any]any{
		"turn": map[any]any{
			"urls": []any{"turn:1.2.3.4:19302"},
		},
		7: "int key",
	}
	got, ok := normalize(body).(map[string]any)
	if !ok {
		t.Fatalf("type = %T, want map[string]any", normalize(body))
	}
	turn, ok := got["turn"].(map[string]any)
	if !ok {
		t.Fatalf("nested type = %T, want map[string]any", got["turn"])
	}
	if urls := toStrings(turn["urls"]); len(urls) != 1 || urls[0] != "turn:1.2.3.4:19302" {
		t.Errorf("urls = %#v", turn["urls"])
	}
	if got["7"] != "int key" {
		t.Errorf("non-string key was not stringified: %#v", got)
	}
}

// Regression: msgpack encodes integers in the narrowest form that fits, so a
// field is only int64 when its value needs 64 bits. toInt64 used to handle
// int64/uint64/float64/int only, which made every smaller value read as 0 —
// silently, since it returns a zero value rather than an error. CallsUserID
// survived only because MAX's internal ids happen to exceed 2^32.
//
// The table holds Go `int` on purpose: this msgpack encoder writes a Go int64
// full-width (0xd3) but an int compactly, so an int64 table would round-trip as
// int64 and never exercise the narrow path — the check below fails the test if
// that ever stops being true.
func TestToInt64HandlesNarrowMsgpackIntegers(t *testing.T) {
	narrowSeen := false
	for _, want := range []int{0, 1, 127, 128, 255, 300, 65535, 70000, 1 << 30, -1, -100, -40000, -(1 << 30)} {
		raw, err := packPacket(opMsgSend, 1, map[string]any{"n": want})
		if err != nil {
			t.Fatalf("packPacket: %v", err)
		}
		pkt, err := readPacket(bytes.NewReader(raw))
		if err != nil {
			t.Fatalf("readPacket: %v", err)
		}
		decoded := pkt.Payload.(map[string]any)["n"]
		if _, isInt64 := decoded.(int64); !isInt64 {
			narrowSeen = true
		}
		if got := toInt64(decoded); got != int64(want) {
			t.Errorf("round-tripped %d: decoded as %T, toInt64 = %d", want, decoded, got)
		}
	}
	if !narrowSeen {
		t.Fatal("every value round-tripped as int64 — this test no longer covers the narrow path")
	}
}

// Pins the contract directly, independent of what the encoder happens to emit.
func TestToInt64AcceptsEveryGoIntegerType(t *testing.T) {
	cases := []struct {
		v    any
		want int64
	}{
		{int8(-5), -5}, {int16(-300), -300}, {int32(-70000), -70000}, {int64(-(1 << 40)), -(1 << 40)},
		{int(-7), -7},
		{uint8(5), 5}, {uint16(300), 300}, {uint32(70000), 70000}, {uint64(1 << 40), 1 << 40},
		{uint(7), 7},
		{float32(2.5), 2}, {float64(2.9), 2},
		{"1099511627776", 1099511627776},
		{"not a number", 0},
		{nil, 0},
		{true, 0},
	}
	for _, tc := range cases {
		if got := toInt64(tc.v); got != tc.want {
			t.Errorf("toInt64(%T %v) = %d, want %d", tc.v, tc.v, got, tc.want)
		}
	}
}
