//go:build darwin && !ios

package systemtun

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

type testLease struct {
	closed bool
	done   chan struct{}
}

func (l *testLease) Close() error          { l.closed = true; return nil }
func (l *testLease) Done() <-chan struct{} { return l.done }

func TestSetupRollsBackOnlyAddedRoutes(t *testing.T) {
	for _, failure := range []int{1, 2, 3, 4, 5, 6, 7, 8} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			var added, removed []string
			calls := 0
			want := errors.New("injected failure")
			run := func(_ context.Context, path string, args ...string) (string, error) {
				if path == "/sbin/route" && args[1] == "get" {
					return testDefaultRoute(args)
				}
				if path == "/sbin/route" && args[1] == "delete" {
					removed = append(removed, strings.Join(args[2:], " "))
					return "", nil
				}
				calls++
				if calls == failure {
					return "", want
				}
				if path == "/sbin/route" {
					added = append(added, strings.Join(args[2:], " "))
				}
				return "", nil
			}
			_, e := setup(context.Background(), "utun42", 1280, "auto", trackScopedRoutes(run), func(context.Context, string) (dnsLease, error) { return nil, want })
			if !errors.Is(e, want) {
				t.Fatalf("got %v", e)
			}
			for i, j := 0, len(added)-1; i < j; i, j = i+1, j-1 {
				added[i], added[j] = added[j], added[i]
			}
			if !reflect.DeepEqual(added, removed) {
				t.Fatalf("added %v removed %v", added, removed)
			}
		})
	}
}

func TestSetupLeavesDefaultGatewayAndPersistentDNSIntact(t *testing.T) {
	lease := &testLease{done: make(chan struct{})}
	var commands []string
	run := func(_ context.Context, path string, args ...string) (string, error) {
		if path == "/sbin/route" && args[1] == "get" {
			return testDefaultRoute(args)
		}
		commands = append(commands, path+" "+strings.Join(args, " "))
		return "", nil
	}
	s, e := setup(context.Background(), "utun42", 1280, "auto", trackScopedRoutes(run), func(context.Context, string) (dnsLease, error) { return lease, nil })
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	n := len(commands)
	s.Close()
	if len(commands) != n || !lease.closed {
		t.Fatal("cleanup not idempotent")
	}
	for _, c := range commands {
		if (strings.Contains(c, " default") && !strings.Contains(c, "-ifscope en1")) || strings.Contains(c, "networksetup") {
			t.Fatalf("persistent settings changed: %s", c)
		}
	}
}

// No physical IPv6 and no pre-existing interface-scoped IPv4 default.
func testDefaultRoute(args []string) (string, error) {
	if args[2] == "-inet6" {
		return "", errRouteNotFound
	}
	return "destination: default\ngateway: 192.0.2.1\ninterface: en1\nflags: <UP,GATEWAY,DONE,STATIC,GLOBAL>\n", nil
}

func TestBypassReusesExistingScopedRoute(t *testing.T) {
	s := &Session{run: func(_ context.Context, _ string, args ...string) (string, error) {
		if args[1] != "get" {
			t.Fatalf("changed an existing route: %v", args)
		}
		out, err := testDefaultRoute(args)
		return strings.ReplaceAll(out, "GLOBAL", "IFSCOPE"), err
	}}
	if err := s.setupBypass(context.Background(), "auto"); err != nil {
		t.Fatal(err)
	}
	if len(s.undo) != 0 {
		t.Fatal("must not own pre-existing routes")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestBypassBeforeCaptureAndCleanupAfter(t *testing.T) {
	var changes []string
	s, err := setup(context.Background(), "utun42", 1280, "auto", trackScopedRoutes(func(_ context.Context, path string, args ...string) (string, error) {
		if path == "/sbin/route" && args[1] == "get" {
			return testDefaultRoute(args)
		}
		changes = append(changes, strings.Join(args, " "))
		return "", nil
	}), func(context.Context, string) (dnsLease, error) { return &testLease{done: make(chan struct{})}, nil })
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	if !strings.Contains(changes[0], "add -inet default 192.0.2.1 -ifscope en1") || !strings.Contains(changes[len(changes)-1], "delete -inet default 192.0.2.1 -ifscope en1") {
		t.Fatalf("bypass must enclose capture route lifetime: %v", changes)
	}
}

func TestParseGatewayRoute(t *testing.T) {
	for _, tc := range []struct {
		output        string
		valid, scoped bool
	}{
		{"gateway: 192.0.2.1\ninterface: en1\nflags: <UP,GATEWAY,GLOBAL>", true, false},
		{"gateway: fe80::1%en0\ninterface: en0\nflags: <UP,GATEWAY,IFSCOPE>", true, true},
		{"gateway: link#12\ninterface: utun4", false, false},
		{"gateway: 192.0.2.1\ninterface: utun4", false, false},
		{"gateway: 192.0.2.1", false, false},
	} {
		r, e := parseGatewayRoute(tc.output)
		if (e == nil) != tc.valid || (e == nil && r.scoped != tc.scoped) {
			t.Fatalf("parse %q: %+v, %v", tc.output, r, e)
		}
	}
}

// Model successful route mutations so cleanup can verify ownership first.
func trackScopedRoutes(run command) command {
	owned := map[string]string{}
	return func(ctx context.Context, path string, args ...string) (string, error) {
		out, err := run(ctx, path, args...)
		if err != nil || path != "/sbin/route" {
			return out, err
		}
		if len(args) == 7 && args[3] == "default" && args[5] == "-ifscope" {
			key := args[2] + "/" + args[6]
			if args[1] == "add" {
				owned[key] = args[4]
			}
			if args[1] == "delete" {
				delete(owned, key)
			}
		}
		if len(args) == 6 && args[1] == "get" && args[4] == "-ifscope" {
			if gateway := owned[args[2]+"/"+args[5]]; gateway != "" {
				return fmt.Sprintf("gateway: %s\ninterface: %s\nflags: <UP,GATEWAY,IFSCOPE>\n", gateway, args[5]), nil
			}
		}
		return out, nil
	}
}
