//go:build darwin && !ios

package systemtun

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func guardianTestCommand(t *testing.T, path string, slow bool) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestRouteGuardianHelper$")
	cmd.Env = append(os.Environ(), "BREACH_GUARDIAN_HELPER=1", "BREACH_GUARDIAN_EVENTS="+path, fmt.Sprintf("BREACH_GUARDIAN_SLOW=%t", slow))
	return cmd
}

func TestRouteGuardianHelper(t *testing.T) {
	if os.Getenv("BREACH_GUARDIAN_HELPER") != "1" {
		t.Skip("subprocess helper")
	}
	if os.Getenv("BREACH_GUARDIAN_REAL") == "1" {
		if iface := os.Getenv("BREACH_GUARDIAN_TEST_BRIDGE"); iface != "" {
			if os.Geteuid() != 0 {
				t.Fatal("kernel guardian fixture requires root")
			}
			// Substitute only discovery of the physical gateway. All scoped
			// queries, additions and deletions go to the real kernel table.
			manager := newRouteManager(func(ctx context.Context, path string, args ...string) (string, error) {
				if len(args) == 4 && args[1] == "get" && args[3] == "default" {
					if args[2] == "-inet6" {
						return "", errRouteNotFound
					}
					return fmt.Sprintf("gateway: 198.19.254.2\ninterface: %s\nflags: <UP,GATEWAY>\n", iface), nil
				}
				return runCommand(ctx, path, args...)
			})
			if err := serveRouteGuardian(os.Stdin, os.Stdout, manager); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
		if err := RunRouteGuardian(os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	table := testRouteTable()
	f, err := os.OpenFile(os.Getenv("BREACH_GUARDIAN_EVENTS"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	manager := newRouteManager(func(ctx context.Context, path string, args ...string) (string, error) {
		out, err := table.run(ctx, path, args...)
		if err == nil && args[1] != "get" {
			fmt.Fprintln(f, args[1])
			f.Sync()
			// Parent can be killed between successful mutation and recording
			// ownership/reply. The surviving guardian must finish and undo it.
			if args[1] == "add" && os.Getenv("BREACH_GUARDIAN_SLOW") == "true" {
				time.Sleep(400 * time.Millisecond)
			}
		}
		return out, err
	})
	err = serveRouteGuardian(os.Stdin, os.Stdout, manager)
	fmt.Fprintln(f, "closed")
	f.Close()
	// An EPIPE after parent SIGKILL is expected, cleanup has already run.
	_ = err
	os.Exit(0)
}

func TestRouteGuardianOwnerHelper(t *testing.T) {
	if os.Getenv("BREACH_GUARDIAN_OWNER") != "1" {
		t.Skip("subprocess helper")
	}
	g, err := startGuardianCommand(guardianTestCommand(t, os.Getenv("BREACH_GUARDIAN_EVENTS"), true))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(g.cmd.Process.Pid)
	if _, err = g.Sync(context.Background(), "auto"); err != nil {
		t.Fatal(err)
	}
	fmt.Println("ready")
	select {}
}

func awaitGuardianEvents(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), want) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("guardian events=%q, wanted %q", b, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRouteGuardianClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	g, err := startGuardianCommand(guardianTestCommand(t, path, false))
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	first, err := g.Sync(context.Background(), "auto")
	if err != nil {
		t.Fatal(err)
	}
	second, err := g.Sync(context.Background(), "auto")
	if err != nil || second != first {
		t.Fatalf("repeat sync %q %v", second, err)
	}
	if err = g.Close(); err != nil {
		t.Fatal(err)
	}
	awaitGuardianEvents(t, path, "add\ndelete\nclosed\n")
}

func TestRouteGuardianAfterParentSIGKILL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events")
	exe, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner := exec.CommandContext(ctx, exe, "-test.run=^TestRouteGuardianOwnerHelper$")
	owner.Env = append(os.Environ(), "BREACH_GUARDIAN_OWNER=1", "BREACH_GUARDIAN_EVENTS="+path)
	stdout, err := owner.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	owner.Stderr = os.Stderr
	if err = owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { owner.Process.Kill(); owner.Wait() }()
	// Ensure the guardian has a cleanup fallback even when the test fails.
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err = fmt.Sscan(line, &pid); err != nil || pid <= 0 {
		t.Fatalf("guardian pid %q", line)
	}
	cleaned := false
	defer func() {
		if !cleaned {
			p, _ := os.FindProcess(pid)
			p.Kill()
		}
	}()
	awaitGuardianEvents(t, path, "add\n")
	owner.Process.Kill()
	owner.Wait()
	awaitGuardianEvents(t, path, "add\ndelete\nclosed\n")
	cleaned = true
}
