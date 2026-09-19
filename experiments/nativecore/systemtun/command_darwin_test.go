//go:build darwin && !ios

package systemtun

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRouteZeroExitErrors(t *testing.T) {
	for _, tc := range []struct {
		name, stderr string
		missing      bool
	}{
		{"missing get", "route: writing to routing socket: not in table\n", true},
		{"removed interface", "route: bad interface name\n", true},
		{"duplicate add", "route: writing to routing socket: File exists\n", false},
		{"permission", "route: writing to routing socket: Operation not permitted\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := commandOutput("/sbin/route", nil, "", tc.stderr, nil)
			if err == nil || out != "" || errors.Is(err, errRouteNotFound) != tc.missing {
				t.Fatalf("exit 0 with stderr: out=%q err=%v", out, err)
			}
		})
	}
}

func TestBypassWithoutIPv6Route(t *testing.T) {
	var changes []string
	s := &Session{run: func(_ context.Context, name string, args ...string) (string, error) {
		if args[1] == "get" {
			if args[2] == "-inet6" {
				// Actual macOS response: exit 0, no stdout, diagnostic on stderr.
				return commandOutput(name, args, "", "route: writing to routing socket: not in table\n", nil)
			}
			return testDefaultRoute(args)
		}
		changes = append(changes, strings.Join(args, " "))
		return "", nil
	}}
	if err := s.setupBypass(context.Background(), "auto"); err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0] != "-n add -inet default 192.0.2.1 -ifscope en1" {
		t.Fatalf("expected IPv4 bypass only: %v", changes)
	}
}

func TestBypassDoesNotIgnoreIPv6CommandFailure(t *testing.T) {
	want := errors.New("command failed")
	s := &Session{run: func(_ context.Context, _ string, args ...string) (string, error) {
		if args[1] == "get" {
			if args[2] == "-inet6" {
				return "", want
			}
			return testDefaultRoute(args)
		}
		return "", nil
	}}
	if err := s.setupBypass(context.Background(), "auto"); !errors.Is(err, want) {
		t.Fatalf("unexpected result: %v", err)
	}
}

// Read the real route utility output while intercepting all writes. No root,
// default route, interface, or DNS changes are needed to cover discovery.
func TestBypassCurrentNetworkReadOnly(t *testing.T) {
	ctx := context.Background()
	out, err := runCommand(ctx, "/sbin/route", "-n", "get", "-inet", "default")
	if err != nil {
		t.Skipf("no physical IPv4 network: %v", err)
	}
	if _, err := parseGatewayRoute(out); err != nil {
		t.Skipf("no physical IPv4 gateway: %v", err)
	}
	s := &Session{run: func(ctx context.Context, name string, args ...string) (string, error) {
		if name != "/sbin/route" {
			t.Fatalf("unexpected command: %s", name)
		}
		if args[1] == "get" {
			return runCommand(ctx, name, args...)
		}
		if args[1] != "add" {
			t.Fatalf("unexpected mutation: %v", args)
		}
		t.Logf("would install: %v", args)
		return "", nil
	}}
	if err := s.setupBypass(ctx, "auto"); err != nil {
		t.Fatal(err)
	}
}
