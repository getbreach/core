//go:build darwin && !ios

package systemtun

import (
	"context"
	"strings"
	"testing"
	"time"

	"breach-nativecore/packetio"
)

// Reproduce the route selection that breaks bound TURN sockets, using only a
// documentation subnet instead of capturing all of the machine's traffic.
func TestMacOSScopedBypass(t *testing.T) {
	requireDNSIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tun, err := packetio.OpenTUN("auto")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	run := func(args ...string) string {
		t.Helper()
		out, err := runCommand(ctx, "/sbin/route", args...)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	physical, err := parseGatewayRoute(run("-n", "get", "-inet", "default"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runCommand(ctx, "/sbin/ifconfig", tun.Name(), "inet", "198.19.255.1", "198.19.255.2", "up"); err != nil {
		t.Fatal(err)
	}
	// Closing utun removes this route even if the test fails.
	run("-n", "add", "-inet", "-net", "203.0.113.0/24", "-interface", tun.Name())
	if out := run("-n", "get", "203.0.113.1"); !strings.Contains(out, "interface: "+tun.Name()) {
		t.Fatalf("test destination did not enter utun: %s", out)
	}
	_, before := runCommand(ctx, "/sbin/route", "-n", "get", "-ifscope", physical.iface, "203.0.113.1")
	t.Logf("bound route before installing bypass: %v", before)
	s := &Session{run: runCommand}
	defer func() {
		// Remove capture first, then the temporary scoped defaults.
		tun.Close()
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := s.setupBypass(ctx, "auto"); err != nil {
		t.Fatal(err)
	}
	out := run("-n", "get", "-ifscope", physical.iface, "203.0.113.1")
	after, err := parseGatewayRoute(out)
	if err != nil || after.iface != physical.iface || after.gateway != physical.gateway || !after.scoped {
		t.Fatalf("bound route did not preserve the physical gateway: %s (%v)", out, err)
	}
}
