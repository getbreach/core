//go:build darwin && !ios

package systemtun

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func requireDNSIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("BREACH_NATIVE_MAC_TUN_TEST") != "1" {
		t.Skip("use scripts/macos-tun.sh for privileged integration tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
}

func recordExists(t *testing.T, key string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, "/usr/sbin/scutil")
	c.Stdin = strings.NewReader("show " + key + "\nquit\n")
	b, e := c.Output()
	if e != nil {
		t.Fatal(e)
	}
	return strings.Contains(string(b), "ServerAddresses")
}

func awaitRemoval(t *testing.T, key string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for recordExists(t, key) {
		if time.Now().After(deadline) {
			t.Fatal("temporary DNS record survived owner exit")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestTemporaryDNSLifetime(t *testing.T) {
	requireDNSIntegration(t)
	lease, e := startDNSDomain(context.Background(), "192.0.2.53", "breach-native-test.invalid")
	if e != nil {
		t.Fatal(e)
	}
	defer lease.Close()
	key := lease.(*dnsProcess).key
	if !recordExists(t, key) {
		t.Fatal("DNS record missing")
	}
	lease.Close()
	awaitRemoval(t, key)
}

func TestTemporaryDNSAfterCrash(t *testing.T) {
	requireDNSIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	path, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	c := exec.CommandContext(ctx, path, "-test.run=^TestDNSCrashHelper$")
	c.Env = append(os.Environ(), "BREACH_DNS_CRASH_HELPER=1")
	stdout, e := c.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { c.Process.Kill(); c.Wait() }()
	key, e := bufio.NewReader(stdout).ReadString('\n')
	if e != nil {
		t.Fatal(e)
	}
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "State:/Network/Service/Breach-") {
		t.Fatalf("unexpected helper output %q", key)
	}
	if !recordExists(t, key) {
		t.Fatal("helper did not install DNS")
	}
	c.Process.Kill()
	c.Wait()
	awaitRemoval(t, key)
}

func TestDNSCrashHelper(t *testing.T) {
	if os.Getenv("BREACH_DNS_CRASH_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	requireDNSIntegration(t)
	lease, e := startDNSDomain(context.Background(), "192.0.2.53", "breach-native-crash-test.invalid")
	if e != nil {
		t.Fatal(e)
	}
	fmt.Println(lease.(*dnsProcess).key)
	// Intentionally no deferred cleanup: the parent sends SIGKILL.
	<-time.After(time.Minute)
}
