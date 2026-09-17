//go:build linux && !android

package packetio

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type TUN struct {
	file *os.File
	name string
}

// OpenTUN creates a non-persistent interface. Address, MTU and routes are set by
// the operator in an isolated test namespace; it never changes the host's DNS.
func OpenTUN(name string) (*TUN, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ {
		return nil, fmt.Errorf("invalid TUN name")
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return nil, fmt.Errorf("invalid TUN name")
		}
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	req, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	req.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, req); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &TUN{file: os.NewFile(uintptr(fd), "/dev/net/tun"), name: req.Name()}, nil
}

func (t *TUN) Name() string                      { return t.name }
func (t *TUN) ReadPacket(p []byte) (int, error)  { return t.file.Read(p) }
func (t *TUN) WritePacket(p []byte) (int, error) { return t.file.Write(p) }
func (t *TUN) Close() error                      { return t.file.Close() }
