package breachmobile

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"breach/maxproto"
)

func resizeTestCore(t *testing.T) (*core, []*fakeTurn) {
	// The existing fixture models one allocation, so give every opened stream
	// its own real TURN/DTLS relay while exercising the normal pool lifecycle.
	var relays []*fakeTurn
	for i := 0; i < 24; i++ {
		relays = append(relays, newFakeTurn(t))
	}
	c := newCore(&maxproto.Config{Token: "resize-test", Streams: 2, Mints: 2, TurnTransport: "udp"}, relays[0].peerAddr())

	var next atomic.Int32
	c.openAllocation = func(cr *maxproto.Creds, i int) (*stream, error) {
		ft := relays[int(next.Add(1)-1)%len(relays)]
		copy := *cr
		copy.TurnHosts = []string{ft.hostAddr()}
		s, err := c.openOne(&copy, i)
		if err != nil {
			t.Logf("allocation fixture: %v", err)
		}
		if s != nil {
			s.cred = cr
		}
		return s, err
	}
	var creds []*maxproto.Creds
	for i := 0; i < 3; i++ {
		creds = append(creds, &maxproto.Creds{TurnHosts: []string{relays[0].hostAddr()}, Username: "user", Credential: "pass", ExpiresAt: time.Now().Add(time.Hour)})
	}
	c.credentialGroups = map[string][]*maxproto.Creds{"resize-test": creds}
	t.Cleanup(c.stop)
	return c, relays
}

// UDP fixture setup may lose an initial datagram under parallel race builds.
// Exercise the reconciler's retry contract instead of requiring one-pass I/O.
func settlePool(t *testing.T, c *core) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		c.buildPool(false)
		if c.limits().Applied {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pool did not converge: %+v error=%v", c.limits(), c.lastErr.Load())
}

func TestHotPoolResizeReusesAllocationsAndCredentials(t *testing.T) {
	c, ft := resizeTestCore(t)
	settlePool(t, c)
	if c.p.length() != 4 || !c.limits().Applied {
		t.Fatalf("initial pool: %+v live=%d", c.limits(), c.p.length())
	}
	original := c.p.snapshot()
	if err := c.setLimits(1, 1); err != nil {
		t.Fatal(err)
	}
	settlePool(t, c)
	kept := c.p.snapshot()
	if len(kept) != 1 || !c.limits().Applied {
		t.Fatal("shrink failed")
	}
	reused := false
	for _, s := range original {
		if s == kept[0] {
			reused = true
			continue
		}
		if streamOpen(s) {
			t.Fatal("removed allocation not closed")
		}
	}
	if !reused {
		t.Fatal("shrink replaced all allocations")
	}
	if err := c.setLimits(2, 3); err != nil {
		t.Fatal(err)
	}
	settlePool(t, c)
	if c.p.length() != 6 || !c.limits().Applied || !streamOpen(kept[0]) {
		t.Fatal("growth did not preserve existing stream")
	}
	if len(c.credentialGroups["resize-test"]) != 3 {
		t.Fatal("unused valid credentials discarded")
	}
	// Quota during expansion must leave the working pool and credentials intact.
	for _, relay := range ft {
		relay.allocateCode.Store(486)
	}
	if err := c.setLimits(2, 4); err != nil {
		t.Fatal(err)
	}
	c.buildPool(false)
	if c.p.length() != 6 || c.limits().Applied || !streamOpen(kept[0]) {
		t.Fatal("failed growth interrupted old pool or falsely reported success")
	}
}
func TestPoolResizeValidationAndConcurrentRequests(t *testing.T) {
	c, _ := resizeTestCore(t)
	original := c.requested.Load()
	for _, v := range [][2]int{{0, 1}, {1, 0}, {17, 1}, {1, 17}} {
		if c.setLimits(v[0], v[1]) == nil {
			t.Fatal("invalid limits accepted")
		}
	}
	if c.requested.Load() != original {
		t.Fatal("invalid request changed settings")
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = c.setLimits(1+j%3, 1+j%3)
				_ = c.limits()
			}
		}()
	}
	c.buildPool(false)
	wg.Wait()
	_ = c.setLimits(2, 2)
	settlePool(t, c)
	if got := c.limits(); !got.Applied || got.Target != 4 || c.p.length() != 4 {
		t.Fatalf("latest request not applied: %+v", got)
	}
	c.cancel()
	if c.setLimits(1, 1) == nil {
		t.Fatal("accepted request after shutdown")
	}
}

func TestPoolReplaceDoesNotResurrectRemovedStream(t *testing.T) {
	a := &stream{done: make(chan struct{})}
	b := &stream{done: make(chan struct{})}
	p := &pool{streams: []*stream{a, b}}
	retained := map[*stream]bool{a: true, b: true}
	p.remove(a) // A health check won the race while resize was opening streams.
	_, live := p.replace([]*stream{a, b}, retained)
	if len(live) != 1 || live[0] != b {
		t.Fatal("removed allocation resurrected")
	}
}

func TestStopCancelsPendingResize(t *testing.T) {
	c, _ := resizeTestCore(t)
	entered := make(chan struct{}, 4)
	c.openAllocation = func(*maxproto.Creds, int) (*stream, error) {
		entered <- struct{}{}
		<-c.ctx.Done()
		return nil, c.ctx.Err()
	}
	built := make(chan struct{})
	go func() { defer close(built); c.buildPool(false) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("build never started")
	}
	stopped := make(chan struct{})
	go func() { c.stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("stop stuck during resize")
	}
	<-built
	if c.p.length() != 0 {
		t.Fatal("allocation published after stop")
	}
}
