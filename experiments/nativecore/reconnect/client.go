// Package reconnect keeps one authenticated outbound session alive. It never
// replays application bytes: flows on a lost session must be opened again.
package reconnect

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"breach-nativecore/outbound"
)

type Session interface {
	outbound.Outbound
	Close() error
}

type Options struct {
	DialTimeout time.Duration
	MinBackoff  time.Duration
	MaxBackoff  time.Duration
	// Permanent identifies authentication/configuration failures, not a network outage.
	Permanent func(error) bool
	Logf      func(string, ...any)
}

type Status struct {
	Connected  bool   `json:"connected"`
	Attempts   uint64 `json:"attempts"`
	Reconnects uint64 `json:"reconnects"`
	LastError  string `json:"lastError,omitempty"`
}

type Client struct {
	ctx           context.Context
	cancel        context.CancelFunc
	dial          func(context.Context) (Session, error)
	opts          Options
	done          chan struct{}
	wake          chan struct{}
	mu            sync.Mutex
	cur           Session
	ready         chan struct{}
	attemptCancel context.CancelFunc
	epoch         uint64
	terminal      error
	status        Status
}

// New starts the worker. WaitReady bounds initial startup separately from the
// worker lifetime. Close always cancels and joins that worker.
func New(ctx context.Context, dial func(context.Context) (Session, error), opts Options) *Client {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff < opts.MinBackoff {
		opts.MaxBackoff = 15 * time.Second
		if opts.MaxBackoff < opts.MinBackoff {
			opts.MaxBackoff = opts.MinBackoff
		}
	}
	if opts.Logf == nil {
		opts.Logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Client{ctx: ctx, cancel: cancel, dial: dial, opts: opts, done: make(chan struct{}), wake: make(chan struct{}, 1), ready: make(chan struct{})}
	go r.run()
	return r
}

func (r *Client) run() {
	defer close(r.done)
	defer func() {
		r.mu.Lock()
		c := r.cur
		r.cur = nil
		r.status.Connected = false
		r.mu.Unlock()
		if c != nil {
			c.Close()
		}
	}()
	backoff := r.opts.MinBackoff
	connectedBefore := false
	for r.ctx.Err() == nil {
		// A queued reset is satisfied by the fresh dial below.
		select {
		case <-r.wake:
		default:
		}
		dctx, cancel := context.WithTimeout(r.ctx, r.opts.DialTimeout)
		r.mu.Lock()
		epoch := r.epoch
		r.attemptCancel = cancel
		r.status.Attempts++
		r.mu.Unlock()
		c, err := r.dial(dctx)
		cancel()
		r.mu.Lock()
		r.attemptCancel = nil
		stale := epoch != r.epoch || r.ctx.Err() != nil
		r.mu.Unlock()
		if stale {
			if c != nil {
				c.Close()
			}
			continue
		}
		if err == nil && c == nil {
			err = errors.New("dial returned no session")
		}
		var mon outbound.Datagrams
		if err == nil {
			mon, err = c.OpenUDP(r.ctx)
		}
		if err == nil {
			r.mu.Lock()
			stale = epoch != r.epoch || r.ctx.Err() != nil
			if !stale {
				r.cur = c
				r.status.Connected = true
				r.status.LastError = ""
				if connectedBefore {
					r.status.Reconnects++
				}
				close(r.ready)
			}
			r.mu.Unlock()
			if stale {
				mon.Close()
				c.Close()
				continue
			}
			connectedBefore = true
			backoff = r.opts.MinBackoff
			r.opts.Logf("Hy2 authenticated; TCP and UDP available")
			// Session loss wakes every UDP receiver; no application payload is sent.
			_, _, err = mon.ReadFrom(r.ctx)
			mon.Close()
			r.mu.Lock()
			if r.cur == c {
				r.cur = nil
				r.ready = make(chan struct{})
				r.status.Connected = false
			}
			r.mu.Unlock()
			if err == nil {
				err = errors.New("session monitor ended")
			}
		}
		if c != nil {
			c.Close()
		}
		if r.ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		r.status.LastError = err.Error()
		permanent := r.opts.Permanent != nil && r.opts.Permanent(err)
		if permanent {
			r.terminal = err
		}
		r.mu.Unlock()
		if permanent {
			r.opts.Logf("Hy2 stopped: %v", err)
			return
		}
		// Jitter avoids clients hitting the same relay simultaneously after an outage.
		delay := time.Duration(float64(backoff) * (0.8 + rand.Float64()*0.4))
		r.opts.Logf("Hy2 unavailable: %v; retry in %s", err, delay.Round(time.Millisecond))
		timer := time.NewTimer(delay)
		select {
		case <-r.ctx.Done():
		case <-r.wake:
		case <-timer.C:
		}
		timer.Stop()
		backoff = min(backoff*2, r.opts.MaxBackoff)
	}
}

// Reset invalidates an in-flight authentication as well as the active session.
// Call after updating/rebuilding the underlying network transport.
func (r *Client) Reset() {
	r.mu.Lock()
	r.epoch++
	c, cancel := r.cur, r.attemptCancel
	if c != nil {
		r.cur = nil
		r.ready = make(chan struct{})
		r.status.Connected = false
	}
	r.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if c != nil {
		c.Close()
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *Client) session(ctx context.Context) (Session, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.ctx.Err() != nil {
			return nil, net.ErrClosed
		}
		r.mu.Lock()
		c, ready, terminal := r.cur, r.ready, r.terminal
		r.mu.Unlock()
		if terminal != nil {
			return nil, terminal
		}
		if c != nil {
			return c, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-r.ctx.Done():
			return nil, net.ErrClosed
		case <-r.done:
			return nil, r.Err()
		case <-ready:
		}
	}
}

func (r *Client) WaitReady(ctx context.Context) error { _, err := r.session(ctx); return err }
func (r *Client) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.session(ctx)
	if err != nil {
		return nil, err
	}
	return c.DialTCP(ctx, target)
}
func (r *Client) OpenUDP(ctx context.Context) (outbound.Datagrams, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := r.session(ctx)
	if err != nil {
		return nil, err
	}
	return c.OpenUDP(ctx)
}
func (r *Client) Status() Status        { r.mu.Lock(); defer r.mu.Unlock(); return r.status }
func (r *Client) Done() <-chan struct{} { return r.done }
func (r *Client) Err() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminal != nil {
		return fmt.Errorf("Hy2: %w", r.terminal)
	}
	return net.ErrClosed
}
func (r *Client) Close() error {
	r.cancel()
	r.mu.Lock()
	c := r.cur
	r.mu.Unlock()
	if c != nil {
		c.Close()
	}
	<-r.done
	return nil
}
