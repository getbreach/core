package dashboard

import (
	"context"
	"errors"
	"fmt"

	"breach-nativecore/engine"
	"breach-nativecore/systemtun"
)

// Mode changes replace local inbounds sequentially. Their cleanup completes
// before the next one starts; the shared TURN/Hy2 runtime remains alive.
type engineRunner func(context.Context, engine.Config, func(string, ...any), *engine.Monitor) error

type session struct {
	parent             context.Context
	base, cfg          engine.Config
	run                engineRunner
	logf               func(string, ...any)
	monitor            *engine.Monitor
	cancel             context.CancelFunc
	done               <-chan error
	pending, fallback  *engine.Config
	transition, notice string
	exiting            bool
}

func newSession(ctx context.Context, cfg engine.Config, logf func(string, ...any), run engineRunner) *session {
	if systemtun.Supported() && cfg.DirectInterface == "" {
		cfg.DirectInterface = "auto"
	}
	s := &session{parent: ctx, base: cfg, run: run, logf: logf}
	s.start(cfg)
	return s
}
func (s *session) start(cfg engine.Config) {
	ctx, cancel := context.WithCancel(s.parent)
	s.cfg, s.cancel = cfg, cancel
	if s.monitor == nil {
		s.monitor = &engine.Monitor{}
	}
	done := make(chan error, 1)
	s.done = done
	monitor := s.monitor
	go func() { done <- s.run(ctx, cfg, s.logf, monitor) }()
}
func (s *session) target(root, supported bool) (engine.Config, error) {
	cfg := s.base
	if s.cfg.Inbound == "tun" {
		cfg.Inbound, cfg.AutoRoute = "socks", false
		if cfg.SOCKSListen == "" {
			cfg.SOCKSListen = "127.0.0.1:1080"
		}
	} else {
		if !supported {
			return cfg, errors.New("TUN switching is currently available on macOS")
		}
		if !root {
			return cfg, errors.New("TUN needs root: restart this TUI with sudo; proxy stays running")
		}
		cfg.Inbound = "tun"
		if s.base.Inbound != "tun" {
			cfg.AutoRoute = true
		}
		if cfg.Interface == "" {
			cfg.Interface = "auto"
		}
		if cfg.AutoRoute && (!cfg.Routing.DNS.FakeIP || cfg.Routing.DNS.StateFile == "") {
			return cfg, errors.New("TUN needs FakeIP + stateFile: start TUI with config.macos.json; proxy stays running")
		}
	}
	return cfg, cfg.Validate()
}
func (s *session) switchMode(root, supported bool) {
	if s.exiting || s.transition != "" {
		return
	}
	cfg, err := s.target(root, supported)
	if err != nil {
		s.notice = err.Error()
		s.logf("Mode switch: %v", err)
		return
	}
	s.notice = ""
	previous := s.cfg
	// Only roll back to an engine that was actually serving before the switch.
	if s.monitor.Snapshot().Phase == "online" {
		s.fallback = &previous
	}
	s.pending = &cfg
	s.transition = "Switching to " + modeName(cfg.Inbound) + " · cleaning up current mode"
	s.logf("Switching %s -> %s; replacing local inbound; keeping TURN/Hy2", modeName(s.cfg.Inbound), modeName(cfg.Inbound))
	if s.done != nil {
		s.cancel()
	} else {
		s.finished(nil)
	}
}
func (s *session) finished(err error) {
	s.cancel()
	s.done = nil
	if s.exiting || s.parent.Err() != nil {
		return
	}
	if s.pending != nil {
		next := *s.pending
		s.pending = nil
		s.transition = "Starting " + modeName(next.Inbound)
		s.start(next)
		return
	}
	if err == nil {
		err = errors.New("engine stopped")
	}
	if s.fallback != nil {
		previous := *s.fallback
		s.fallback = nil
		s.notice = fmt.Sprintf("%s failed: %v; restoring %s", modeName(s.cfg.Inbound), err, modeName(previous.Inbound))
		s.logf("%s", s.notice)
		s.transition = "Restoring " + modeName(previous.Inbound)
		s.start(previous)
		return
	}
	s.transition = ""
	s.notice = err.Error()
	s.logf("Engine stopped: %v", err)
}
func (s *session) snapshot() engine.Snapshot {
	snapshot := s.monitor.Snapshot()
	if s.pending == nil && snapshot.Phase == "online" {
		if s.transition != "" {
			s.logf("%s mode ready", modeName(s.cfg.Inbound))
		}
		s.fallback = nil
		s.transition = ""
	}
	return snapshot
}
func (s *session) stop() {
	s.exiting = true
	s.pending = nil
	s.fallback = nil
	s.cancel()
}
func (s *session) close() {
	s.stop()
	if s.done != nil {
		<-s.done
		s.done = nil
	}
}
func modeName(inbound string) string {
	if inbound == "tun" {
		return "TUN"
	}
	return "PROXY"
}
