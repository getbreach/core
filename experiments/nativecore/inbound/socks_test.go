package inbound_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"breach-nativecore/inbound"
	"breach-nativecore/internal/hy2test"
	"golang.org/x/net/proxy"
)

func TestSOCKSTCPUDPAndShutdown(t *testing.T) {
	client := hy2test.Client(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- inbound.ServeSOCKS(ctx, ln, client) }()
	t.Cleanup(func() { cancel(); <-done })
	// A peer which never sends a SOCKS greeting must also be closed on stop.
	silent, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer silent.Close()
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		c, err := echo.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	dialer, err := proxy.SOCKS5("tcp", ln.Addr().String(), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	c, err := dialer.Dial("tcp", net.JoinHostPort("localhost", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	want := bytes.Repeat([]byte("SOCKS over Hy2"), 100)
	if _, err := c.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("TCP: %v", err)
	}

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	ctrl.SetDeadline(time.Now().Add(3 * time.Second))
	ctrl.Write([]byte{5, 1, 0})
	var greeting [2]byte
	if _, err := io.ReadFull(ctrl, greeting[:]); err != nil || greeting != [2]byte{5, 0} {
		t.Fatalf("greeting: %v", err)
	}
	ctrl.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	var reply [10]byte
	if _, err := io.ReadFull(ctrl, reply[:]); err != nil || reply[1] != 0 || reply[3] != 1 {
		t.Fatalf("UDP association: %v", err)
	}
	relay := &net.UDPAddr{IP: net.IP(reply[4:8]), Port: int(binary.BigEndian.Uint16(reply[8:]))}
	u, err := net.DialUDP("udp4", nil, relay)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(3 * time.Second))
	udpEcho, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go func() {
		b := make([]byte, 4096)
		n, a, e := udpEcho.ReadFromUDP(b)
		if e == nil {
			udpEcho.WriteToUDP(b[:n], a)
		}
	}()
	want = bytes.Repeat([]byte("u"), 3000)
	packet := []byte{0, 0, 0, 1, 127, 0, 0, 1}
	packet = binary.BigEndian.AppendUint16(packet, uint16(udpEcho.LocalAddr().(*net.UDPAddr).Port))
	packet = append(packet, want...)
	if _, err := u.Write(packet); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := u.Read(buf)
	if err != nil || n < 10 || !bytes.Equal(buf[10:n], want) {
		t.Fatalf("UDP echo: n=%d error=%v", n, err)
	}
	cancel()
	silent.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := silent.Read(make([]byte, 1)); err == nil {
		t.Fatal("silent peer survived shutdown")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("silent peer was not closed")
	}
}
