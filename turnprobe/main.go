package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

const magicCookie = 0x2112A442

const (
	attrMappedAddress      = 0x0001
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrChannelNumber      = 0x000C
	attrLifetime           = 0x000D
	attrXorPeerAddress     = 0x0012
	attrData               = 0x0013
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrXorRelayedAddress  = 0x0016
	attrRequestedTransport = 0x0019
	attrXorMappedAddress   = 0x0020
)

const (
	methodAllocateReq        = 0x0003
	methodAllocateSuccess    = 0x0103
	methodAllocateError      = 0x0113
	methodCreatePermReq      = 0x0008
	methodCreatePermSuccess  = 0x0108
	methodCreatePermError    = 0x0118
	methodSendIndication     = 0x0016
	methodDataIndication     = 0x0017
	methodChannelBindReq     = 0x0009
	methodChannelBindSuccess = 0x0109
)

type message struct {
	typ   uint16
	tid   [12]byte
	attrs []byte
}

func newTID() [12]byte {
	var t [12]byte
	rand.Read(t[:])
	return t
}

func (m *message) addAttr(t uint16, v []byte) {
	hdr := []byte{byte(t >> 8), byte(t), byte(len(v) >> 8), byte(len(v))}
	m.attrs = append(m.attrs, hdr...)
	m.attrs = append(m.attrs, v...)
	for len(m.attrs)%4 != 0 {
		m.attrs = append(m.attrs, 0)
	}
}

func (m *message) marshalWithLen(extra int) []byte {
	out := make([]byte, 20+len(m.attrs))
	binary.BigEndian.PutUint16(out[0:2], m.typ)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(m.attrs)+extra))
	binary.BigEndian.PutUint32(out[4:8], magicCookie)
	copy(out[8:20], m.tid[:])
	copy(out[20:], m.attrs)
	return out
}

func (m *message) bytes() []byte { return m.marshalWithLen(0) }

func (m *message) addMessageIntegrity(key []byte) {
	buf := m.marshalWithLen(24) // length must already count the MI attribute (4+20)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf)
	m.addAttr(attrMessageIntegrity, mac.Sum(nil))
}

func longTermKey(username, realm, password string) []byte {
	sum := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return sum[:]
}

func xorAddr(ip net.IP, port int) []byte {
	v4 := ip.To4()
	b := make([]byte, 8)
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], uint16(port)^0x2112)
	cookie := []byte{0x21, 0x12, 0xa4, 0x42}
	for i := 0; i < 4; i++ {
		b[4+i] = v4[i] ^ cookie[i]
	}
	return b
}

func parseAttrs(p []byte) map[uint16][]byte {
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

func errorCode(v []byte) string {
	if len(v) < 4 {
		return "?"
	}
	code := int(v[2])*100 + int(v[3])
	return fmt.Sprintf("%d %s", code, string(v[4:]))
}

func main() {
	turn := flag.String("turn", "", "TURN server host:port")
	user := flag.String("user", "", "TURN username")
	pass := flag.String("pass", "", "TURN credential")
	peerPort := flag.Int("echoPort", 45678, "local UDP echo port (also the peer port)")
	peerIP := flag.String("peerIP", "185.238.191.17", "public IP the TURN server should relay to")
	bench := flag.Bool("bench", false, "run throughput benchmark instead of the single round-trip probe")
	n := flag.Int("n", 4000, "bench: number of packets")
	size := flag.Int("size", 1024, "bench: payload bytes per packet")
	pps := flag.Int("pps", 0, "bench: packets/sec pacing per stream (0 = blast)")
	flag.IntVar(&fillMode, "fill", 0, "bench payload: 0=zeros 1=random 2=dtls-like")
	streams := flag.Int("streams", 1, "bench: number of parallel TURN allocations")
	flag.Parse()

	if *turn == "" || *user == "" || *pass == "" {
		log.Fatal("need -turn -user -pass")
	}

	if *bench {
		if err := runBench(*turn, *user, *pass, net.ParseIP(*peerIP), *peerPort, *n, *size, *pps, *streams); err != nil {
			log.Fatalf("\n❌ BENCH FAILED: %v", err)
		}
		return
	}

	go runEchoServer(*peerPort)
	time.Sleep(300 * time.Millisecond)

	if err := probe(*turn, *user, *pass, net.ParseIP(*peerIP), *peerPort); err != nil {
		log.Fatalf("\n❌ RELAY TEST FAILED: %v", err)
	}
}

func runEchoServer(port int) {
	addr := &net.UDPAddr{IP: net.IPv4zero, Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("echo server bind: %v", err)
	}
	fmt.Printf("echo server listening on :%d\n", port)
	buf := make([]byte, 2048)
	for {
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		fmt.Printf("  [echo] got %d bytes from %s (TURN relay) -> echoing back\n", n, src)
		conn.WriteToUDP(buf[:n], src)
	}
}

func probe(turnAddr, user, pass string, peerIP net.IP, peerPort int) error {
	conn, err := net.Dial("udp", turnAddr)
	if err != nil {
		return fmt.Errorf("dial turn: %w", err)
	}
	defer conn.Close()

	read := func() ([]byte, error) {
		conn.SetReadDeadline(time.Now().Add(6 * time.Second))
		b := make([]byte, 2048)
		n, err := conn.Read(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}

	// 1. Unauthenticated Allocate -> expect 401 with REALM + NONCE.
	a0 := &message{typ: methodAllocateReq, tid: newTID()}
	a0.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	conn.Write(a0.bytes())

	resp, err := read()
	if err != nil {
		return fmt.Errorf("no reply to initial Allocate: %w", err)
	}
	at := parseAttrs(resp)
	realm := string(at[attrRealm])
	nonce := at[attrNonce]
	fmt.Printf("✓ Allocate challenged: realm=%q nonce=%d bytes\n", realm, len(nonce))
	if realm == "" || len(nonce) == 0 {
		return fmt.Errorf("expected 401 realm/nonce, got type=0x%04x %s",
			binary.BigEndian.Uint16(resp[0:2]), errorCode(at[attrErrorCode]))
	}

	key := longTermKey(user, realm, pass)

	// 2. Authenticated Allocate.
	a1 := &message{typ: methodAllocateReq, tid: newTID()}
	a1.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	a1.addAttr(attrUsername, []byte(user))
	a1.addAttr(attrRealm, []byte(realm))
	a1.addAttr(attrNonce, nonce)
	a1.addMessageIntegrity(key)
	conn.Write(a1.bytes())

	resp, err = read()
	if err != nil {
		return fmt.Errorf("no reply to authed Allocate: %w", err)
	}
	typ := binary.BigEndian.Uint16(resp[0:2])
	at = parseAttrs(resp)
	if typ != methodAllocateSuccess {
		return fmt.Errorf("Allocate rejected: type=0x%04x err=%s", typ, errorCode(at[attrErrorCode]))
	}
	relayed := at[attrXorRelayedAddress]
	fmt.Printf("✓ Allocate OK — relayed address granted (%d-byte XOR-RELAYED-ADDRESS)\n", len(relayed))

	// 3. CreatePermission for our ARBITRARY peer (this VPS's public ip:port).
	cp := &message{typ: methodCreatePermReq, tid: newTID()}
	cp.addAttr(attrXorPeerAddress, xorAddr(peerIP, peerPort))
	cp.addAttr(attrUsername, []byte(user))
	cp.addAttr(attrRealm, []byte(realm))
	cp.addAttr(attrNonce, nonce)
	cp.addMessageIntegrity(key)
	conn.Write(cp.bytes())

	resp, err = read()
	if err != nil {
		return fmt.Errorf("no reply to CreatePermission: %w", err)
	}
	typ = binary.BigEndian.Uint16(resp[0:2])
	at = parseAttrs(resp)
	if typ != methodCreatePermSuccess {
		return fmt.Errorf("CreatePermission to %s:%d REJECTED: type=0x%04x err=%s "+
			"(TURN restricts peers — tunnel to arbitrary VPS would NOT work)",
			peerIP, peerPort, typ, errorCode(at[attrErrorCode]))
	}
	fmt.Printf("✓ CreatePermission OK for arbitrary peer %s:%d\n", peerIP, peerPort)

	// 4. Send indication carrying a payload to the peer; echo server bounces it back.
	payload := []byte(fmt.Sprintf("MAXTURN-PROBE-%x", newTID()))
	si := &message{typ: methodSendIndication, tid: newTID()}
	si.addAttr(attrXorPeerAddress, xorAddr(peerIP, peerPort))
	si.addAttr(attrData, payload)
	conn.Write(si.bytes())
	fmt.Printf("→ sent %q via TURN relay to peer\n", payload)

	// 5. Expect a Data indication carrying the echoed payload.
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		resp, err = read()
		if err != nil {
			break
		}
		typ = binary.BigEndian.Uint16(resp[0:2])
		if typ != methodDataIndication {
			continue
		}
		at = parseAttrs(resp)
		if bytes.Equal(at[attrData], payload) {
			fmt.Printf("✓ Data indication received — payload round-tripped through MAX TURN\n")
			fmt.Printf("\n✅ RELAY TEST PASSED: MAX TURN relays UDP to an arbitrary peer (your VPS).\n")
			fmt.Printf("   This is exactly what a vk-turn-proxy-style tunnel needs.\n")
			return nil
		}
		fmt.Printf("  (data indication with unexpected payload: %q)\n", at[attrData])
	}
	return fmt.Errorf("permission granted but no relayed data came back "+
		"(relay to %s:%d blocked, or inbound UDP filtered)", peerIP, peerPort)
}
