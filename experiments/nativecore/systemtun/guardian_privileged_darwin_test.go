//go:build darwin && !ios

package systemtun

import (
	"bufio"
	"context"
	"os"
	"os/exec"
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
