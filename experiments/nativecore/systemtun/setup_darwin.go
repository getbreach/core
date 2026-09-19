//go:build darwin && !ios

// Package systemtun configures temporary, interface-owned routes and DNS.
// It never edits the physical interface's persistent DNS/default gateway.
package systemtun

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const DNSAddress = "198.19.255.2"

var errRouteNotFound = errors.New("route not in table")

type command func(context.Context, string, ...string) (string, error)
type dnsLease interface {
	Close() error
	Done() <-chan struct{}
}
type Session struct {
	mu                          sync.Mutex
	closed                      bool
	bypass                      routeLease
	snapshot, outboundInterface string
	done                        chan struct{}
	stop                        chan struct{}
	once                        sync.Once
	dns                         dnsLease
	run                         command
	undo                        [][]string
	err                         error
}

func Supported() bool { return true }

func runCommand(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	return commandOutput(name, args, string(out), stderr.String(), err)
}

func commandOutput(name string, args []string, stdout, stderr string, err error) (string, error) {
	// Darwin route get may print a routing-socket error and still exit 0.
	// Keep stderr separate so it cannot be mistaken for a route description.
	if name == "/sbin/route" {
		if strings.Contains(stderr, "not in table") || strings.Contains(stderr, "bad interface name") {
			err = errors.Join(err, errRouteNotFound)
		} else if strings.TrimSpace(stderr) != "" && err == nil {
			err = errors.New("route reported an error despite exit status 0")
		}
	}
	if err != nil {
		return "", fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stdout+stderr))
	}
	return stdout, nil
}

func Setup(ctx context.Context, name string, mtu int, outboundInterface string) (*Session, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("automatic macOS TUN setup requires root")
	}
	guard, err := startRouteGuardian()
	if err != nil {
		return nil, err
	}
	return setupWithBypass(ctx, name, mtu, outboundInterface, runCommand, startDNS, guard)
}

// Caller owns the utun fd and MUST close it after failure or Session.Close.
// Closing that fd is also the crash-safe cleanup for interface-owned routes.
func setup(ctx context.Context, name string, mtu int, outboundInterface string, run command, dns func(context.Context, string) (dnsLease, error)) (*Session, error) {
	return setupWithBypass(ctx, name, mtu, outboundInterface, run, dns, newRouteManager(run))
}

func setupWithBypass(ctx context.Context, name string, mtu int, outboundInterface string, run command, dns func(context.Context, string) (dnsLease, error), bypass routeLease) (*Session, error) {
	if !regexp.MustCompile(`^utun[0-9]+$`).MatchString(name) || mtu < 1280 || mtu > 65535 {
		bypass.Close()
		return nil, errors.New("invalid utun name or MTU")
	}
	s := &Session{run: run, bypass: bypass, done: make(chan struct{}), stop: make(chan struct{})}
	fail := func(e error) (*Session, error) { return nil, errors.Join(e, s.Close()) }
	if e := s.setupBypass(ctx, outboundInterface); e != nil {
		return fail(e)
	}
	if _, e := run(ctx, "/sbin/ifconfig", name, "inet", "198.19.255.1", "198.19.255.2", "netmask", "255.255.255.252", "mtu", strconv.Itoa(mtu), "up"); e != nil {
		return fail(e)
	}
	if _, e := run(ctx, "/sbin/ifconfig", name, "inet6", "fd00:198:19::1", "prefixlen", "126"); e != nil {
		return fail(e)
	}
	for _, route := range [][]string{{"-inet", "0.0.0.0/1"}, {"-inet", "128.0.0.0/1"}, {"-inet6", "::/1"}, {"-inet6", "8000::/1"}} {
		args := []string{"-n", "add", route[0], "-net", route[1], "-interface", name}
		if e := s.addRoute(ctx, args); e != nil {
			return fail(e)
		}
	}
	lease, e := dns(ctx, DNSAddress)
	if e != nil {
		return fail(e)
	}
	s.dns = lease
	go func() {
		select {
		case <-s.dns.Done():
		case <-s.bypass.Done():
		case <-s.stop:
		}
		close(s.done)
	}()
	return s, nil
}

func (s *Session) Done() <-chan struct{} {
	return s.done
}

// Refresh repairs missing/replaced scoped defaults and reports gateway changes.
// A temporary loss of the physical network is retried by the engine.
func (s *Session) Refresh(ctx context.Context) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false, errors.New("TUN network session closed")
	}
	before := s.snapshot
	err := s.setupBypass(ctx, s.outboundInterface)
	return err == nil && before != s.snapshot, err
}

func (s *Session) Close() error {
	s.once.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.closed = true
		if s.stop != nil {
			close(s.stop)
		}
		if s.dns != nil {
			s.err = errors.Join(s.err, s.dns.Close())
		}
		for i := len(s.undo) - 1; i >= 0; i-- {
			// Use an independent deadline: shutdown usually follows cancellation.
			_, e := s.run(context.Background(), "/sbin/route", s.undo[i]...)
			if e != nil && !errors.Is(e, errRouteNotFound) {
				s.err = errors.Join(s.err, e)
			}
		}
		if s.bypass != nil {
			s.err = errors.Join(s.err, s.bypass.Close())
		}
	})
	return s.err
}
