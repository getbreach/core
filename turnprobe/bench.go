package main

import (
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type echoStats struct {
	packets atomic.Int64
	bytes   atomic.Int64
}

func benchEcho(port int, st *echoStats) (*net.UDPConn, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, err
	}
	conn.SetReadBuffer(8 << 20)
	conn.SetWriteBuffer(8 << 20)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, src, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			st.packets.Add(1)
			st.bytes.Add(int64(n))
			conn.WriteToUDP(buf[:n], src)
		}
	}()
	return conn, nil
}

func channelData(channel uint16, data []byte) []byte {
	out := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(out[0:2], channel)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(data)))
	copy(out[4:], data)
	return out
}

func authedAllocate(conn net.Conn, user, pass string) (realm string, nonce []byte, key []byte, err error) {
	read := func() ([]byte, error) {
		conn.SetReadDeadline(time.Now().Add(6 * time.Second))
		b := make([]byte, 2048)
		n, e := conn.Read(b)
		if e != nil {
			return nil, e
		}
		return b[:n], nil
	}

	a0 := &message{typ: methodAllocateReq, tid: newTID()}
	a0.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	conn.Write(a0.bytes())
	resp, err := read()
	if err != nil {
		return "", nil, nil, fmt.Errorf("initial allocate: %w", err)
	}
	at := parseAttrs(resp)
	realm = string(at[attrRealm])
	nonce = at[attrNonce]
	if realm == "" || len(nonce) == 0 {
		return "", nil, nil, fmt.Errorf("no realm/nonce in challenge")
	}
	key = longTermKey(user, realm, pass)

	a1 := &message{typ: methodAllocateReq, tid: newTID()}
	a1.addAttr(attrRequestedTransport, []byte{17, 0, 0, 0})
	a1.addAttr(attrUsername, []byte(user))
	a1.addAttr(attrRealm, []byte(realm))
	a1.addAttr(attrNonce, nonce)
	a1.addMessageIntegrity(key)
	conn.Write(a1.bytes())
	resp, err = read()
	if err != nil {
		return "", nil, nil, fmt.Errorf("authed allocate: %w", err)
	}
	if binary.BigEndian.Uint16(resp[0:2]) != methodAllocateSuccess {
		return "", nil, nil, fmt.Errorf("allocate rejected: %s", errorCode(parseAttrs(resp)[attrErrorCode]))
	}
	return realm, nonce, key, nil
}

type benchResult struct {
	sent     int
	reached  int64
	rtt      int64
	rttBytes int64
	dur      time.Duration
}

func benchOne(turnAddr, user, pass string, peerIP net.IP, peerPort, n, size, pps int) (benchResult, error) {
	st := &echoStats{}
	echoConn, err := benchEcho(peerPort, st)
	if err != nil {
		return benchResult{}, fmt.Errorf("echo bind: %w", err)
	}
	defer echoConn.Close()

	conn, err := net.Dial("udp", turnAddr)
	if err != nil {
		return benchResult{}, err
	}
	defer conn.Close()
	if uc, ok := conn.(*net.UDPConn); ok {
		uc.SetWriteBuffer(8 << 20)
		uc.SetReadBuffer(8 << 20)
	}

	realm, nonce, key, err := authedAllocate(conn, user, pass)
	if err != nil {
		return benchResult{}, err
	}

	const channel = 0x4000
	cb := &message{typ: methodChannelBindReq, tid: newTID()}
	cb.addAttr(attrChannelNumber, []byte{channel >> 8, channel & 0xff, 0, 0})
	cb.addAttr(attrXorPeerAddress, xorAddr(peerIP, peerPort))
	cb.addAttr(attrUsername, []byte(user))
	cb.addAttr(attrRealm, []byte(realm))
	cb.addAttr(attrNonce, nonce)
	cb.addMessageIntegrity(key)
	conn.Write(cb.bytes())
	conn.SetReadDeadline(time.Now().Add(6 * time.Second))
	rb := make([]byte, 2048)
	rn, err := conn.Read(rb)
	if err != nil {
		return benchResult{}, fmt.Errorf("channelbind reply: %w", err)
	}
	if binary.BigEndian.Uint16(rb[0:2]) != methodChannelBindSuccess {
		return benchResult{}, fmt.Errorf("ChannelBind rejected: %s", errorCode(parseAttrs(rb[:rn])[attrErrorCode]))
	}

	if size < 8 {
		size = 8
	}
	var clientRecv, clientBytes atomic.Int64
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			m, e := conn.Read(buf)
			if e != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}
			if m >= 4 && binary.BigEndian.Uint16(buf[0:2]) == channel {
				clientRecv.Add(1)
				clientBytes.Add(int64(m - 4))
			}
		}
	}()

	payload := make([]byte, size)
	switch fillMode {
	case 1:
		crand.Read(payload)
	case 2:
		crand.Read(payload)
		payload[0] = 0x17 // DTLS application_data content type
		payload[1] = 0xfe
		payload[2] = 0xfd // DTLS 1.2
	}
	var interval time.Duration
	if pps > 0 {
		interval = time.Second / time.Duration(pps)
	}

	start := time.Now()
	next := start
	for i := 0; i < n; i++ {
		binary.BigEndian.PutUint64(payload[0:8], uint64(i))
		conn.Write(channelData(channel, payload))
		if interval > 0 {
			next = next.Add(interval)
			if d := time.Until(next); d > 0 {
				time.Sleep(d)
			}
		}
	}
	dur := time.Since(start)

	time.Sleep(3 * time.Second)
	close(done)

	return benchResult{
		sent:     n,
		reached:  st.packets.Load(),
		rtt:      clientRecv.Load(),
		rttBytes: clientBytes.Load(),
		dur:      dur,
	}, nil
}

var fillMode int

func mbps(bytes int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(bytes) * 8 / 1e6 / d.Seconds()
}

func runBench(turnAddr, user, pass string, peerIP net.IP, peerPort, n, size, pps, streams int) error {
	if streams < 1 {
		streams = 1
	}
	fmt.Printf("→ %d parallel stream(s), %d pkts × %d B each, pacing %d pps/stream\n", streams, n, size, pps)

	results := make([]benchResult, streams)
	errs := make([]error, streams)
	var wg sync.WaitGroup
	for s := 0; s < streams; s++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx], errs[idx] = benchOne(turnAddr, user, pass, peerIP, peerPort+idx, n, size, pps)
		}(s)
	}
	wg.Wait()

	var totReached, totRtt, totRttBytes int64
	var maxDur time.Duration
	live := 0
	for s := 0; s < streams; s++ {
		if errs[s] != nil {
			fmt.Printf("  stream %d FAILED: %v\n", s, errs[s])
			continue
		}
		live++
		r := results[s]
		totReached += r.reached
		totRtt += r.rtt
		totRttBytes += r.rttBytes
		if r.dur > maxDur {
			maxDur = r.dur
		}
	}
	if live == 0 {
		return fmt.Errorf("all streams failed")
	}

	totalSent := int64(n) * int64(live)
	upBytes := totReached * int64(size)

	fmt.Printf("\n─── throughput (%d live stream%s) ───────────────────\n", live, plural(live))
	fmt.Printf("sent total      : %d pkts in %s\n", totalSent, maxDur.Round(time.Millisecond))
	fmt.Printf("reached peer    : %d pkts (%.1f%% upload loss)\n",
		totReached, 100*float64(totalSent-totReached)/float64(totalSent))
	fmt.Printf("round-tripped   : %d pkts (%.1f%% loop loss)\n",
		totRtt, 100*float64(totalSent-totRtt)/float64(totalSent))
	fmt.Printf("AGG upload      : %.1f Mbit/s (client→TURN→peer, all streams)\n", mbps(upBytes, maxDur))
	fmt.Printf("AGG round-trip  : %.1f Mbit/s (both legs, all streams)\n", mbps(totRttBytes*2, maxDur))
	if live > 0 {
		fmt.Printf("per-stream upload: ~%.1f Mbit/s avg\n", mbps(upBytes, maxDur)/float64(live))
	}
	fmt.Printf("──────────────────────────────────────────────────\n")
	return nil
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
