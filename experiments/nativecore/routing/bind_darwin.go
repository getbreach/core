//go:build darwin && !ios

package routing

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// InterfaceControl uses interface-scoped routing, so the outer transport and
// direct flows bypass the split default routes on utun. auto follows the
// original default route, which automatic TUN setup deliberately leaves intact.
func InterfaceControl(name string) (Control, error) {
	var mu sync.Mutex
	var index int
	var checked time.Time
	resolve := func() (int, error) {
		mu.Lock()
		defer mu.Unlock()
		if index != 0 && time.Since(checked) < 2*time.Second {
			return index, nil
		}
		selected := name
		if name == "auto" {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			out, err := exec.CommandContext(ctx, "/sbin/route", "-n", "get", "default").Output()
			if err != nil {
				return 0, fmt.Errorf("detect physical default interface: %w", err)
			}
			selected, err = defaultInterface(string(out))
			if err != nil {
				return 0, err
			}
		}
		i, err := net.InterfaceByName(selected)
		if err != nil {
			return 0, err
		}
		if i.Flags&net.FlagUp == 0 {
			return 0, errors.New("outbound interface is down")
		}
		if name == "auto" && (i.Flags&net.FlagLoopback != 0 || strings.HasPrefix(i.Name, "utun")) {
			return 0, errors.New("automatic outbound interface is a tunnel; specify the physical directInterface")
		}
		index, checked = i.Index, time.Now()
		return index, nil
	}
	if _, err := resolve(); err != nil {
		return nil, err
	}
	return func(_, _ string, raw syscall.RawConn) error {
		i, err := resolve()
		if err != nil {
			return err
		}
		var sockErr error
		err = raw.Control(func(fd uintptr) {
			addr, e := unix.Getsockname(int(fd))
			if e != nil {
				sockErr = e
				return
			}
			switch addr.(type) {
			case *unix.SockaddrInet4:
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, i)
			case *unix.SockaddrInet6:
				sockErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, i)
			default:
				sockErr = errors.New("cannot bind non-IP socket to outbound interface")
			}
		})
		if err != nil {
			return err
		}
		return sockErr
	}, nil
}

func defaultInterface(s string) (string, error) {
	for _, line := range strings.Split(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "interface:" {
			return fields[1], nil
		}
	}
	return "", errors.New("default route has no interface")
}
