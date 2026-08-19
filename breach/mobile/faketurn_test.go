package breachmobile

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"

	"breach/media"
)

// This file implements just enough of the TURN wire protocol (Allocate
// challenge/auth, ChannelBind, Refresh) to drive the real turn.NewAlloc /
// Alloc.Keepalive code path in tests, plus a real UDP peer so a genuine
// DTLS-SRTP handshake (media.Client / media.Server) completes end to end. It
// supports exactly one live allocation at a time — enough to exercise
// replenish()/turnKeepaliveTick() one allocation at a time without racing
// concurrent opens onto the same channel/peer state.

const (
	ftAttrUsername      = 0x0006
	ftAttrErrorCode     = 0x0009
	ftAttrChannelNumber = 0x000C
	ftAttrRealm         = 0x0014
	ftAttrNonce         = 0x0015

	ftAllocate    = 0x0003
	ftRefresh     = 0x0004
	ftChannelBind = 0x0009

	ftAllocateOK = 0x0103
	ftRefreshOK  = 0x0104
	ftChannelOK  = 0x0109
)

func ftParseAttrs(p []byte) map[uint16][]byte {
	out := map[uint16][]byte{}
	i := 20
	for i+4 <= len(p) {
		t := binary.BigEndian.Uint16(p[i : i+2])
		l := int(binary.BigEndian.Uint16(p[i+2 : i+4]))
		if i+4+l > len(p) {
			break
		}
		if _, dup := out[t]; !dup {
			out[t] = p[i+4 : i+4+l]
		}
		i += 4 + l + (4-l%4)%4
	}
	return out
}

type ftMessage struct {
	typ   uint16
	tid   [12]byte
	attrs []byte
}

func (m *ftMessage) addAttr(t uint16, v []byte) {
	m.attrs = append(m.attrs, byte(t>>8), byte(t), byte(len(v)>>8), byte(len(v)))
	m.attrs = append(m.attrs, v...)
	for len(m.attrs)%4 != 0 {
		m.attrs = append(m.attrs, 0)
	}
}

func (m *ftMessage) bytes() []byte {
	out := make([]byte, 20+len(m.attrs))
	binary.BigEndian.PutUint16(out[0:2], m.typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(m.attrs)))
	binary.BigEndian.PutUint32(out[4:8], 0x2112A442)
	copy(out[8:20], m.tid[:])
	copy(out[20:], m.attrs)
	return out
}

func ftErrorAttr(code int) []byte {
	return []byte{0, 0, byte(code / 100), byte(code % 100)}
}

type fakeTurn struct {
	client *net.UDPConn
	toPeer *net.UDPConn
	peer   *net.UDPAddr

	mu         sync.Mutex
	channel    uint16
	clientAddr *net.UDPAddr

	allocateCode atomic.Int32 // STUN error code to return on Allocate; 0 = success
	refreshCode  atomic.Int32 // STUN error code to return on Refresh; 0 = success
}

func newFakeTurn(t *testing.T) *fakeTurn {
	t.Helper()
	loop := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	client, err := net.ListenUDP("udp", loop)
	if err != nil {
		t.Fatalf("listen client socket: %v", err)
	}
	toPeer, err := net.ListenUDP("udp", loop)
	if err != nil {
		t.Fatalf("listen peer-facing socket: %v", err)
	}
	peerConn, err := net.DialUDP("udp", nil, toPeer.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial peer socket: %v", err)
	}

	f := &fakeTurn{client: client, toPeer: toPeer, peer: peerConn.LocalAddr().(*net.UDPAddr)}
	t.Cleanup(func() {
		client.Close()
		toPeer.Close()
		peerConn.Close()
	})

	go f.serveControl()
	go f.relayFromPeer()
	go media.Server(peerConn) //nolint:errcheck // best-effort: test teardown races the handshake

	return f
}

func (f *fakeTurn) hostAddr() string       { return f.client.LocalAddr().String() }
func (f *fakeTurn) peerAddr() *net.UDPAddr { return f.peer }

// serveControl answers TURN control messages and relays channel-data to the peer.
func (f *fakeTurn) serveControl() {
	buf := make([]byte, 65536)
	for {
		n, addr, err := f.client.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.clientAddr = addr
		ch := f.channel
		f.mu.Unlock()

		if n >= 4 && ch != 0 && binary.BigEndian.Uint16(buf[0:2]) == ch {
			l := int(binary.BigEndian.Uint16(buf[2:4]))
			if 4+l <= n {
				payload := make([]byte, l)
				copy(payload, buf[4:4+l])
				f.toPeer.WriteToUDP(payload, f.peer)
			}
			continue
		}
		if n < 20 {
			continue
		}
		req := make([]byte, n)
		copy(req, buf[:n])
		f.handleControl(req, addr)
	}
}

func (f *fakeTurn) handleControl(req []byte, addr *net.UDPAddr) {
	typ := binary.BigEndian.Uint16(req[0:2])
	var tid [12]byte
	copy(tid[:], req[8:20])
	attrs := ftParseAttrs(req)

	switch typ {
	case ftAllocate:
		if _, authed := attrs[ftAttrUsername]; !authed {
			resp := &ftMessage{typ: ftAllocateOK, tid: tid}
			resp.addAttr(ftAttrRealm, []byte("test-realm"))
			resp.addAttr(ftAttrNonce, []byte("test-nonce"))
			f.client.WriteToUDP(resp.bytes(), addr)
			return
		}
		if code := f.allocateCode.Load(); code != 0 {
			resp := &ftMessage{typ: ftAllocate | 0x0110, tid: tid}
			resp.addAttr(ftAttrErrorCode, ftErrorAttr(int(code)))
			f.client.WriteToUDP(resp.bytes(), addr)
			return
		}
		f.client.WriteToUDP((&ftMessage{typ: ftAllocateOK, tid: tid}).bytes(), addr)

	case ftChannelBind:
		if chAttr, ok := attrs[ftAttrChannelNumber]; ok && len(chAttr) >= 2 {
			f.mu.Lock()
			f.channel = binary.BigEndian.Uint16(chAttr[0:2])
			f.mu.Unlock()
		}
		f.client.WriteToUDP((&ftMessage{typ: ftChannelOK, tid: tid}).bytes(), addr)

	case ftRefresh:
		if code := f.refreshCode.Load(); code != 0 {
			resp := &ftMessage{typ: ftRefresh | 0x0110, tid: tid}
			resp.addAttr(ftAttrErrorCode, ftErrorAttr(int(code)))
			f.client.WriteToUDP(resp.bytes(), addr)
			return
		}
		f.client.WriteToUDP((&ftMessage{typ: ftRefreshOK, tid: tid}).bytes(), addr)
	}
}

// relayFromPeer wraps datagrams arriving from the peer (DTLS handshake replies)
// back into ChannelData for the client.
func (f *fakeTurn) relayFromPeer() {
	buf := make([]byte, 65536)
	for {
		n, _, err := f.toPeer.ReadFromUDP(buf)
		if err != nil {
			return
		}
		f.mu.Lock()
		ch := f.channel
		addr := f.clientAddr
		f.mu.Unlock()
		if ch == 0 || addr == nil {
			continue
		}
		out := make([]byte, 4+n)
		binary.BigEndian.PutUint16(out[0:2], ch)
		binary.BigEndian.PutUint16(out[2:4], uint16(n))
		copy(out[4:], buf[:n])
		f.client.WriteToUDP(out, addr)
	}
}
