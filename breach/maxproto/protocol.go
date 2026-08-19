package maxproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"

	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

// Verbose enables wire-level logging.
var Verbose bool

func logf(format string, args ...any) {
	if Verbose {
		log.Printf(format, args...)
	}
}

// Wire format mirrors lib/core/protocol/packet.dart: a 10-byte header
// (ver, cmd, seq BE, opcode BE, packedLen BE = compFlag<<24 | bodyLen) plus a
// msgpack body. We send uncompressed (flag 0); responses are decompressed by
// magic (zstd / lz4 frame / lenient lz4 block).

const (
	headerSize         = 10
	protocolVer        = 10
	cmdRequest         = 0
	cmdOK              = 1
	cmdError           = 3
	maxDecompressedLen = 16 << 20
)

type Packet struct {
	Ver     uint8
	Cmd     uint8
	Seq     uint16
	Opcode  uint16
	Payload any
}

func (p *Packet) IsOK() bool    { return p.Cmd == cmdOK }
func (p *Packet) IsError() bool { return p.Cmd == cmdError }

func packPacket(opcode, seq uint16, payload any) ([]byte, error) {
	body, err := msgpack.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("msgpack marshal: %w", err)
	}
	if len(body) > 0xFFFFFF {
		return nil, fmt.Errorf("payload too large: %d", len(body))
	}
	out := make([]byte, headerSize+len(body))
	out[0] = protocolVer
	out[1] = cmdRequest
	binary.BigEndian.PutUint16(out[2:4], seq)
	binary.BigEndian.PutUint16(out[4:6], opcode)
	binary.BigEndian.PutUint32(out[6:10], uint32(len(body))&0xFFFFFF)
	copy(out[headerSize:], body)
	return out, nil
}

func readPacket(r io.Reader) (*Packet, error) {
	var header [headerSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	packedLen := binary.BigEndian.Uint32(header[6:10])
	compFlag := packedLen >> 24
	payloadLen := packedLen & 0xFFFFFF

	pkt := &Packet{
		Ver:    header[0],
		Cmd:    header[1],
		Seq:    binary.BigEndian.Uint16(header[2:4]),
		Opcode: binary.BigEndian.Uint16(header[4:6]),
	}
	if payloadLen == 0 {
		return pkt, nil
	}
	body := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if compFlag != 0 {
		d, err := decompress(body)
		if err != nil {
			return nil, err
		}
		body = d
	}

	dec := msgpack.NewDecoder(bytes.NewReader(body))
	dec.SetMapDecoder(func(d *msgpack.Decoder) (any, error) { return d.DecodeUntypedMap() })
	var payload any
	if err := dec.Decode(&payload); err != nil {
		return nil, fmt.Errorf("msgpack unmarshal (opcode %d): %w", pkt.Opcode, err)
	}
	pkt.Payload = normalize(payload)
	return pkt, nil
}

func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			t[k] = normalize(val)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[fmt.Sprint(k)] = normalize(val)
		}
		return m
	case []any:
		for i := range t {
			t[i] = normalize(t[i])
		}
		return t
	default:
		return v
	}
}

func decompress(src []byte) ([]byte, error) {
	if len(src) >= 4 && src[0] == 0x28 && src[1] == 0xB5 && src[2] == 0x2F && src[3] == 0xFD {
		dec, err := zstd.NewReader(nil)
		if err != nil {
			return nil, err
		}
		defer dec.Close()
		return dec.DecodeAll(src, nil)
	}
	if len(src) >= 4 && src[0] == 0x04 && src[1] == 0x22 && src[2] == 0x4D && src[3] == 0x18 {
		return io.ReadAll(lz4.NewReader(bytes.NewReader(src)))
	}
	return lz4BlockDecompress(src, maxDecompressedLen)
}

// lz4BlockDecompress is a lenient LZ4 block decoder ported from
// lib/core/protocol/lz4_block.dart; MAX blocks ignore the spec's end-of-block
// rules so the strict pierrec decoder corrupts large payloads.
func lz4BlockDecompress(src []byte, maxSize int) ([]byte, error) {
	out := make([]byte, 0, 1024)
	pos := 0
	for pos < len(src) {
		token := src[pos]
		pos++
		litLen := int(token >> 4)
		if litLen == 15 {
			for pos < len(src) {
				b := src[pos]
				pos++
				litLen += int(b)
				if b != 255 {
					break
				}
			}
		}
		if litLen > 0 {
			if len(out)+litLen > maxSize {
				return nil, fmt.Errorf("lz4: size limit")
			}
			if pos+litLen > len(src) {
				return nil, fmt.Errorf("lz4: literals past end")
			}
			out = append(out, src[pos:pos+litLen]...)
			pos += litLen
		}
		if pos >= len(src) {
			break
		}
		if pos+1 >= len(src) {
			return nil, fmt.Errorf("lz4: unexpected end")
		}
		offset := int(src[pos]) | int(src[pos+1])<<8
		pos += 2
		if offset == 0 {
			return nil, fmt.Errorf("lz4: offset 0")
		}
		matchLen := int(token&0x0F) + 4
		if token&0x0F == 0x0F {
			for pos < len(src) {
				b := src[pos]
				pos++
				matchLen += int(b)
				if b != 255 {
					break
				}
			}
		}
		start := len(out) - offset
		if start < 0 {
			return nil, fmt.Errorf("lz4: bad offset")
		}
		if len(out)+matchLen > maxSize {
			return nil, fmt.Errorf("lz4: size limit")
		}
		for i := 0; i < matchLen; i++ {
			out = append(out, out[start+i])
		}
	}
	return out, nil
}
