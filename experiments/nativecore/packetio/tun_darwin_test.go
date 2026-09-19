//go:build darwin && !ios

package packetio

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testTUNPair(t *testing.T) (*TUN, *os.File) {
	t.Helper()
	fds, e := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if e != nil {
		t.Fatal(e)
	}
	for _, fd := range fds {
		unix.CloseOnExec(fd)
		if e = unix.SetNonblock(fd, true); e != nil {
			t.Fatal(e)
		}
	}
	a, b := os.NewFile(uintptr(fds[0]), "test-utun"), os.NewFile(uintptr(fds[1]), "test-kernel")
	t.Cleanup(func() { a.Close(); b.Close() })
	a.SetDeadline(time.Now().Add(time.Second))
	b.SetDeadline(time.Now().Add(time.Second))
	return &TUN{file: a, name: "utun-test"}, b
}

func TestUTUNFraming(t *testing.T) {
	for _, v := range []byte{4, 6} {
		t.Run(string(rune('0'+v)), func(t *testing.T) {
			tun, kernel := testTUNPair(t)
			p := bytes.Repeat([]byte{0x12}, 1500)
			p[0] = v << 4
			if n, e := tun.WritePacket(p); e != nil || n != len(p) {
				t.Fatalf("write %d: %v", n, e)
			}
			b := make([]byte, 1600)
			n, e := kernel.Read(b)
			if e != nil {
				t.Fatal(e)
			}
			family := uint32(unix.AF_INET)
			if v == 6 {
				family = unix.AF_INET6
			}
			if binary.BigEndian.Uint32(b[:4]) != family || !bytes.Equal(b[4:n], p) {
				t.Fatal("wrong utun framing")
			}
			if _, e = kernel.Write(b[:n]); e != nil {
				t.Fatal(e)
			}
			n, e = tun.ReadPacket(b)
			if e != nil || !bytes.Equal(b[:n], p) {
				t.Fatalf("read packet: %v", e)
			}
		})
	}
}

func TestUTUNMalformedFrameAndShortBuffer(t *testing.T) {
	tun, kernel := testTUNPair(t)
	kernel.Write([]byte{0, 0, 0, unix.AF_INET6, 0x45})
	if _, e := tun.ReadPacket(make([]byte, 20)); e == nil {
		t.Fatal("accepted family mismatch")
	}
	kernel.Write([]byte{0, 0, 0, unix.AF_INET, 0x45, 0, 0, 0})
	if _, e := tun.ReadPacket(make([]byte, 1)); !errors.Is(e, io.ErrShortBuffer) {
		t.Fatalf("short buffer: %v", e)
	}
	if _, e := tun.WritePacket([]byte{0x10}); e == nil {
		t.Fatal("accepted non-IP packet")
	}
}

func TestUTUNCloseUnblocksRead(t *testing.T) {
	tun, _ := testTUNPair(t)
	tun.file.SetReadDeadline(time.Time{})
	done := make(chan error, 1)
	go func() { _, e := tun.ReadPacket(make([]byte, 4096)); done <- e }()
	tun.Close()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("read after close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close left ReadPacket blocked")
	}
}
