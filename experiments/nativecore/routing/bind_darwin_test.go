//go:build darwin && !ios

package routing

import (
	"context"
	"net"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinInterfaceBinding(t *testing.T) {
	i, e := net.InterfaceByName("lo0")
	if e != nil {
		t.Fatal(e)
	}
	ctrl, e := InterfaceControl("lo0")
	if e != nil {
		t.Fatal(e)
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			lc := net.ListenConfig{Control: func(n, a string, c syscall.RawConn) error {
				if e := ctrl(n, a, c); e != nil {
					return e
				}
				var e error
				c.Control(func(fd uintptr) {
					level, opt := unix.IPPROTO_IP, unix.IP_BOUND_IF
					if network == "udp6" {
						level, opt = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
					}
					var got int
					got, e = unix.GetsockoptInt(int(fd), level, opt)
					if e == nil && got != i.Index {
						t.Errorf("bound if=%d want %d", got, i.Index)
					}
				})
				return e
			}}
			pc, e := lc.ListenPacket(context.Background(), network, ":0")
			if e != nil {
				t.Fatal(e)
			}
			pc.Close()
		})
	}
}
