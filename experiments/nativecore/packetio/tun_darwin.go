//go:build darwin && !ios

package packetio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// Darwin utun packets carry a four-byte, network-order AF_INET/AF_INET6 header.
// The portable bridge only sees the IP packet after that header.
type TUN struct {
	file              *os.File
	name              string
	readMu, writeMu   sync.Mutex
	readBuf, writeBuf [65539]byte
}

func utunUnit(name string) (uint32, error) {
	if name == "" || name == "auto" || name == "utun" || name == "breach0" {
		return 0, nil
	}
	if !strings.HasPrefix(name, "utun") {
		return 0, errors.New("macOS interface must be auto or utunN")
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(name, "utun"), 10, 16)
	if err != nil {
		return 0, errors.New("macOS interface must be auto or utunN")
	}
	return uint32(n) + 1, nil
}

func OpenTUN(name string) (*TUN, error) {
	unit, err := utunUnit(name)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */)
	if err != nil {
		return nil, fmt.Errorf("utun socket (requires root): %w", err)
	}
	unix.CloseOnExec(fd)
	ok := false
	defer func() {
		if !ok {
			unix.Close(fd)
		}
	}()
	var info unix.CtlInfo
	copy(info.Name[:], "com.apple.net.utun_control")
	if err = unix.IoctlCtlInfo(fd, &info); err != nil {
		return nil, fmt.Errorf("utun control: %w", err)
	}
	if err = unix.Connect(fd, &unix.SockaddrCtl{ID: info.Id, Unit: unit}); err != nil {
		return nil, fmt.Errorf("connect utun (requires root): %w", err)
	}
	actual, err := unix.GetsockoptString(fd, 2, 2 /* UTUN_OPT_IFNAME */)
	if err != nil {
		return nil, err
	}
	if err = unix.SetNonblock(fd, true); err != nil {
		return nil, err
	}
	t := &TUN{file: os.NewFile(uintptr(fd), "utun"), name: strings.TrimRight(actual, "\x00")}
	ok = true
	return t, nil
}

func (t *TUN) Name() string { return t.name }
func (t *TUN) Close() error { return t.file.Close() }

func (t *TUN) ReadPacket(p []byte) (int, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	n, err := t.file.Read(t.readBuf[:])
	if err != nil {
		return 0, err
	}
	if n < 5 {
		return 0, errors.New("short utun frame")
	}
	family := binary.BigEndian.Uint32(t.readBuf[:4])
	version := t.readBuf[4] >> 4
	if !((family == unix.AF_INET && version == 4) || (family == unix.AF_INET6 && version == 6)) {
		return 0, errors.New("utun address family does not match IP packet")
	}
	if n-4 > len(p) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, t.readBuf[4:n]), nil
}

func (t *TUN) WritePacket(p []byte) (int, error) {
	if len(p) == 0 || len(p) > 65535 {
		return 0, errors.New("invalid utun packet size")
	}
	var family uint32
	switch p[0] >> 4 {
	case 4:
		family = unix.AF_INET
	case 6:
		family = unix.AF_INET6
	default:
		return 0, errors.New("utun requires IPv4 or IPv6")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	binary.BigEndian.PutUint32(t.writeBuf[:4], family)
	copy(t.writeBuf[4:], p)
	n, err := t.file.Write(t.writeBuf[:len(p)+4])
	if err != nil {
		return 0, err
	}
	if n != len(p)+4 {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}
