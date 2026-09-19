//go:build darwin && !ios

package systemtun

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Uses a scoped copy of the physical default, never redirects ordinary
// traffic. Existing OS-owned scoped defaults must survive both lifetimes.
func TestRouteGuardianKernelCleanup(t *testing.T) {
	requireDNSIntegration(t)
	for _, crash := range []bool{false, true} {
		name := "close"
		if crash {
			name = "parent_SIGKILL"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			m := newRouteManager(runCommand)
			physical, err := m.query(ctx, "-inet", "")
			if err != nil {
				t.Fatal(err)
			}
			before, err := m.query(ctx, "-inet", physical.iface)
			if err != nil {
				t.Fatal(err)
			}
			exe, _ := os.Executable()
			cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRouteGuardianOwnerHelper$")
			if !crash {
				cmd = guardianTestCommand(t, "", false)
			}
			cmd.Env = append(os.Environ(), "BREACH_GUARDIAN_OWNER=1", "BREACH_GUARDIAN_HELPER=1", "BREACH_GUARDIAN_REAL=1")
			if crash {
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				cmd.Stderr = os.Stderr
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { cmd.Process.Kill(); cmd.Wait() }()
				r := bufio.NewReader(stdout)
				if _, err = r.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
				line, err := r.ReadString('\n')
				if err != nil || strings.TrimSpace(line) != "ready" {
					t.Fatalf("owner not ready: %q %v", line, err)
				}
				cmd.Process.Kill()
				cmd.Wait()
			} else {
				g, err := startGuardianCommand(cmd)
				if err != nil {
					t.Fatal(err)
				}
				defer g.Close()
				if _, err = g.Sync(ctx, "auto"); err != nil {
					t.Fatal(err)
				}
				if err = g.Close(); err != nil {
					t.Fatal(err)
				}
			}
			deadline := time.Now().Add(8 * time.Second)
			for {
				after, err := m.query(ctx, "-inet", physical.iface)
				if err == nil && after == before {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("scoped route not restored: before=%+v after=%+v err=%v", before, after, err)
				}
				time.Sleep(50 * time.Millisecond)
			}
		})
	}
}

// Guarantee this test creates a route even on runners with an existing scoped
// physical default. An empty bridge has no ports and does not carry user traffic.
func TestRouteGuardianKernelCleanupOwned(t *testing.T) {
	requireDNSIntegration(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runCommand(ctx, "/sbin/ifconfig", "bridge", "create")
	if err != nil {
		t.Fatal(err)
	}
	iface := strings.TrimSpace(out)
	if !regexp.MustCompile(`^bridge[0-9]+$`).MatchString(iface) {
		t.Fatalf("unexpected bridge name %q", iface)
	}
	defer func() {
		if _, err := runCommand(context.Background(), "/sbin/ifconfig", iface, "destroy"); err != nil {
			t.Error(err)
		}
	}()
	if _, err = runCommand(ctx, "/sbin/ifconfig", iface, "inet", "198.19.254.1", "netmask", "255.255.255.252", "up"); err != nil {
		t.Fatal(err)
	}
	m := newRouteManager(runCommand)
	want := scopedRoute{family: "-inet", gatewayRoute: gatewayRoute{iface: iface, gateway: "198.19.254.2", scoped: true}}
	assertAbsent := func(t *testing.T) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for {
			r, err := m.query(ctx, "-inet", iface)
			if errors.Is(err, errRouteNotFound) || (err == nil && !r.scoped) {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("owned route survived: %+v %v", r, err)
			}
			time.Sleep(25 * time.Millisecond)
		}
	}
	assertPresent := func(t *testing.T) {
		t.Helper()
		r, err := m.query(ctx, "-inet", iface)
		if err != nil || !sameScoped(r, want) {
			t.Fatalf("guardian did not create its own scoped route: %+v %v", r, err)
		}
		t.Logf("verified newly created scoped default on %s via %s", iface, r.gateway)
	}
	assertAbsent(t)
	for _, crash := range []bool{false, true} {
		name := "close"
		if crash {
			name = "parent_SIGKILL"
		}
		t.Run(name, func(t *testing.T) {
			if !crash {
				cmd := guardianTestCommand(t, "", false)
				cmd.Env = append(cmd.Env, "BREACH_GUARDIAN_REAL=1", "BREACH_GUARDIAN_TEST_BRIDGE="+iface)
				g, err := startGuardianCommand(cmd)
				if err != nil {
					t.Fatal(err)
				}
				defer g.Close()
				if _, err = g.Sync(ctx, "auto"); err != nil {
					t.Fatal(err)
				}
				assertPresent(t)
				if err = g.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				exe, _ := os.Executable()
				cmd := exec.CommandContext(ctx, exe, "-test.run=^TestRouteGuardianOwnerHelper$")
				cmd.Env = append(os.Environ(), "BREACH_GUARDIAN_OWNER=1", "BREACH_GUARDIAN_REAL=1", "BREACH_GUARDIAN_TEST_BRIDGE="+iface)
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					t.Fatal(err)
				}
				cmd.Stderr = os.Stderr
				if err = cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { cmd.Process.Kill(); cmd.Wait() }()
				r := bufio.NewReader(stdout)
				if _, err = r.ReadString('\n'); err != nil {
					t.Fatal(err)
				}
				line, err := r.ReadString('\n')
				if err != nil || strings.TrimSpace(line) != "ready" {
					t.Fatalf("owner not ready: %q %v", line, err)
				}
				assertPresent(t)
				cmd.Process.Kill()
				cmd.Wait()
			}
			assertAbsent(t)
		})
	}
}
