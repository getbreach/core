// Package dashboard provides an interactive, in-process view of the engine.
package dashboard

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"breach-nativecore/engine"
	"breach-nativecore/systemtun"
)

func Run(parent context.Context, cfg engine.Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.AutoRoute && os.Geteuid() != 0 {
		return errors.New("automatic macOS TUN requires root; run breach tui with sudo")
	}
	t, err := openTerminal()
	if err != nil {
		return err
	}
	defer t.close()
	if _, err = fmt.Fprint(os.Stdout, "\x1b[?1049h\x1b[?25l\x1b[2J\x1b[H"); err != nil {
		return err
	}
	defer fmt.Fprint(os.Stdout, "\x1b[0m\x1b[?25h\x1b[?1049l")
	j := newJournal(cfg)
	previousLog := log.Writer()
	log.SetOutput(j)
	defer log.SetOutput(previousLog)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	shared := engine.NewRuntime(ctx)
	defer shared.Close()
	sessions := newSession(ctx, cfg, j.logf, shared.RunObserved)
	samples := make(chan resources, 1)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		sampler := resourceSampler{}
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			sample := sampler.sample(ctx)
			select {
			case samples <- sample:
			default:
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	// Keep the terminal intact until engine.Run has finished all cleanup.
	defer func() { cancel(); sessions.close(); workers.Wait() }()
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	paused, stopping, showLogs := false, false, true
	parentDone := parent.Done()
	var ioErr error
	var edit *poolEditor
	stop := func() {
		edit = nil
		stopping = true
		paused = false
		parentDone = nil
		sessions.stop()
		cancel()
	}
	resource := runtimeResources()
	rates := rateMeter{}
	current := view{config: cfg}
	lastRate := time.Time{}
	for {
		select {
		case err := <-sessions.done:
			sessions.finished(err)
		case <-parentDone:
			stop()
		case sample := <-samples:
			resource = sample
		case <-tick.C:
			if !stopping {
				keys, err := t.keys()
				if err != nil {
					ioErr = err
					stop()
				}
				for _, key := range keys {
					if edit != nil && key != 'q' && key != 'Q' && key != 3 {
						switch key {
						case 27:
							edit = nil
						case '\r', '\n':
							if err := sessions.monitor.SetPoolLimits(edit.mints, edit.streams); err != nil {
								edit.error = err.Error()
							} else {
								edit = nil
							}
						default:
							edit.key(key)
						}
						continue
					}
					switch key {
					case 'q', 'Q', 3:
						stop()
					case 't', 'T':
						if !stopping {
							pool := sessions.snapshot().Pool
							if pool.Mints > 0 && pool.Streams > 0 {
								paused = false
								edit = &poolEditor{mints: pool.Mints, streams: pool.Streams, accounts: max(1, pool.Target/(pool.Mints*pool.Streams))}
							} else {
								sessions.notice = "Pool settings require a running embedded TURN transport"
							}
						}
					case 'm', 'M':
						if !stopping {
							paused = false
							sessions.switchMode(os.Geteuid() == 0, systemtun.Supported())
						}
					case 'p', 'P':
						if !stopping && sessions.transition == "" {
							paused = !paused
						}
					case 'l', 'L':
						showLogs = !showLogs
					}
				}
			}
		}
		if stopping && sessions.done == nil {
			return ioErr
		}
		now := time.Now()
		snapshot := sessions.snapshot()
		if now.Sub(lastRate) >= time.Second {
			rates.sample(now, snapshot.Wire)
			lastRate = now
		}
		if !paused || stopping || sessions.transition != "" {
			warning := snapshot.LastError
			if resource.Error != "" {
				warning = resource.Error
			}
			if snapshot.NetworkError != "" {
				warning = snapshot.NetworkError
			}
			if sessions.notice != "" {
				warning = sessions.notice
			}
			current = view{transition: sessions.transition, config: sessions.cfg, status: snapshot, resources: resource, rate: rates, logs: j.tail(40), warning: j.redact(warning)}
			if !snapshot.Started.IsZero() {
				current.uptime = now.Sub(snapshot.Started)
			}
		}
		current.poolEdit = edit
		w, h := t.size()
		lines := render(current, w, h, paused, stopping, showLogs)
		// Erase the tail of every row when a value becomes shorter.
		frame := "\x1b[H" + strings.Join(lines, "\x1b[K\r\n") + "\x1b[K\x1b[J"
		if _, err := fmt.Fprint(os.Stdout, frame); err != nil && !stopping {
			ioErr = err
			stop()
		}
	}
}
