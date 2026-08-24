package qtun

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

// Destination policy.
//
// The exit dials on a client's behalf, which makes it a confused deputy unless
// something says where it may go. Its loopback carries the Clash API and the
// management daemon, and its bridge sits on a private network — an authenticated
// client could otherwise ask the exit to fetch 127.0.0.1:51822 or scan the
// host's LAN, using the exit's own credentials and its position inside the
// network. Refusing everything that is not public internet is the whole fix.
//
// The check runs on the RESOLVED address (via Dialer.Control for TCP), not on
// the name, so a hostname that resolves to 127.0.0.1 is refused too.

// ErrBlockedDestination is returned for an address the exit refuses to reach.
var ErrBlockedDestination = errors.New("qtun: destination is not a public address")

// publicOnly reports whether an address may be dialled on a client's behalf.
func publicOnly(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	a := addr.Unmap()
	switch {
	case a.IsLoopback(), // the exit's own admin plane
		a.IsPrivate(),          // RFC1918 / ULA: the host's LAN and docker bridge
		a.IsLinkLocalUnicast(), // 169.254/16 — cloud metadata lives here
		a.IsLinkLocalMulticast(),
		a.IsInterfaceLocalMulticast(),
		a.IsMulticast(),
		a.IsUnspecified():
		return false
	}
	// Carrier-grade NAT: not "private" by Go's definition, but not somewhere a
	// client has any business reaching through us either.
	if a.Is4() && a.As4()[0] == 100 && a.As4()[1] >= 64 && a.As4()[1] <= 127 {
		return false
	}
	return true
}

// allowedHostPort checks an already-resolved "host:port".
func allowedHostPort(hostPort string) bool {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false // not a literal: the caller resolves first
	}
	return publicOnly(addr)
}

// publicDialer is the exit's outbound dialer. The policy is enforced in Control,
// which runs after resolution and immediately before connect, so a name that
// resolves into a forbidden range is caught as well.
func publicDialer(timeout time.Duration, allowPrivate bool) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if allowPrivate {
		return d
	}
	d.Control = func(_, address string, _ syscall.RawConn) error {
		if !allowedHostPort(address) {
			return ErrBlockedDestination
		}
		return nil
	}
	return d
}

// resolveAllowed resolves a UDP target and applies the same policy.
func resolveAllowed(target string, allowPrivate bool) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return nil, err
	}
	if allowPrivate {
		return addr, nil
	}
	ip, ok := netip.AddrFromSlice(addr.IP)
	if !ok || !publicOnly(ip) {
		return nil, ErrBlockedDestination
	}
	return addr, nil
}
