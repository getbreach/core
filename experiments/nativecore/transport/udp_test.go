package transport

import (
	"bytes"
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"breach-nativecore/hy2"
	"breach-nativecore/internal/hy2test"
)

// Exercise real Hy2 through the pipe: a legacy qtun marker must never be added.
func TestHysteriaThroughUnmarkedPipe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exit, tls := hy2test.Server(t)
	pipe, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	backend, err := net.Dial("udp", exit.String())
	if err != nil {
		t.Fatal(err)
	}
	defer backend.Close()
	var packets atomic.Int64
	firstPeer := make(chan net.Addr, 1)
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 65536)
		first := true
		for {
			n, peer, err := pipe.ReadFrom(buf)
			if err != nil {
				return
			}
			if n == 0 || buf[0] == 0 {
				continue
			}
			packets.Add(1)
			if first {
				firstPeer <- peer
				first = false
			}
			backend.Write(buf[:n])
		}
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		var peer net.Addr
		select {
		case peer = <-firstPeer:
		case <-ctx.Done():
			return
		}
		buf := make([]byte, 65536)
		for {
			n, err := backend.Read(buf)
			if err != nil {
				return
			}
			pipe.WriteTo(buf[:n], peer)
		}
	}()
	t.Cleanup(func() { cancel(); pipe.Close(); backend.Close(); <-done; <-done })
	c, peer, err := Open(pipe.LocalAddr().String(), "pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	client, err := hy2.Dial(ctx, c, peer, "test-password", tls)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	s, err := client.OpenUDP(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if packets.Load() < 2 {
		t.Fatal("Hy2 did not traverse unmarked pipe")
	}
}

func TestPipeRejectsUnexpectedSources(t *testing.T) {
	peer, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	c, _, err := Open(peer.LocalAddr().String(), "pipe")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	meter := &Meter{}
	c.SetMeter(meter)
	other, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	local := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: c.LocalAddr().(*net.UDPAddr).Port}
	other.WriteTo([]byte("forged"), local)
	peer.WriteTo([]byte("valid"), local)
	c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 64)
	n, _, err := c.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf[:n], []byte("valid")) {
		t.Fatalf("accepted %q", buf[:n])
	}
	if got := meter.Snapshot(); got.DownBytes != 5 || got.DownPackets != 1 {
		t.Fatalf("meter counted rejected packets: %+v", got)
	}
	if _, err = c.WriteTo([]byte("send"), peer.LocalAddr()); err != nil {
		t.Fatal(err)
	}
	if _, err = c.WriteTo([]byte("rejected"), other.LocalAddr()); err == nil {
		t.Fatal("accepted unexpected destination")
	}
	if got := meter.Snapshot(); got.UpBytes != 4 || got.UpPackets != 1 {
		t.Fatalf("meter counted rejected writes: %+v", got)
	}
}
