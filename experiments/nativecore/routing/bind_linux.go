//go:build linux && !android

package routing

import (
	"golang.org/x/sys/unix"
	"net"
	"syscall"
)

// InterfaceControl pins direct sockets to a physical Linux interface. The caller
// must leave a usable route on that interface when routing other traffic to TUN.
func InterfaceControl(name string) (Control, error) {
	if _, e := net.InterfaceByName(name); e != nil {
		return nil, e
	}
	return func(_, _ string, raw syscall.RawConn) error {
		var sockErr error
		if e := raw.Control(func(fd uintptr) {
			sockErr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, name)
		}); e != nil {
			return e
		}
		return sockErr
	}, nil
}
