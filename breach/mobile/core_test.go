package breachmobile

import (
	"encoding/json"
	"testing"
	"time"

	"breach/maxproto"
)

// --- pool: pure, no network ---

func TestPoolAddPickRemove(t *testing.T) {
	p := &pool{}
	a, b := &stream{}, &stream{}
	p.add(a)
	p.add(b)
	if got := p.length(); got != 2 {
		t.Fatalf("length() = %d, want 2", got)
	}
	if got := p.pick(); got != a && got != b {
		t.Fatalf("pick() returned a stream not in the pool")
	}
	if !p.remove(a) {
		t.Fatalf("remove(a) = false, want true (a is in the pool)")
	}
	if p.remove(a) {
		t.Fatalf("remove(a) = true on second call, want false (already removed)")
	}
	if got := p.length(); got != 1 {
		t.Fatalf("length() after remove = %d, want 1", got)
	}
	if got := p.snapshot(); len(got) != 1 || got[0] != b {
		t.Fatalf("snapshot() = %v, want [b]", got)
	}
}

func TestPoolPickEmpty(t *testing.T) {
	p := &pool{}
	if got := p.pick(); got != nil {
		t.Fatalf("pick() on empty pool = %v, want nil", got)
	}
}

func TestPoolSetReturnsOld(t *testing.T) {
	p := &pool{}
	a := &stream{}
	p.add(a)
	old := p.set([]*stream{{}, {}})
	if len(old) != 1 || old[0] != a {
		t.Fatalf("set() returned %v, want [a]", old)
	}
	if got := p.length(); got != 2 {
		t.Fatalf("length() after set = %d, want 2", got)
	}
}

// --- updateHealthyCount: pure, no network ---

func TestUpdateHealthyCount(t *testing.T) {
	c := newCore(&maxproto.Config{}, nil)
	fresh, stale := &stream{}, &stream{}
	fresh.lastRx.Store(time.Now().UnixNano())
	stale.lastRx.Store(time.Now().Add(-30 * time.Second).UnixNano())
	c.p.add(fresh)
	c.p.add(stale)

	c.updateHealthyCount()

	if got := c.allocations.Load(); got != 1 {
		t.Fatalf("allocations = %d, want 1 (only the fresh stream counts as healthy)", got)
	}
}

func TestUpdateHealthyCountClearsLastError(t *testing.T) {
	c := newCore(&maxproto.Config{}, nil)
	c.setErr("boom")
	s := &stream{}
	s.lastRx.Store(time.Now().UnixNano())
	c.p.add(s)

	c.updateHealthyCount()

	if got, _ := c.lastErr.Load().(string); got != "" {
		t.Fatalf("lastErr = %q, want cleared once a healthy allocation appears", got)
	}
}

// --- stream.isStale: pure ---

func TestStreamIsStale(t *testing.T) {
	now := time.Now()

	fresh := &stream{createdAt: now}
	fresh.lastRx.Store(now.Add(-2 * time.Second).UnixNano())
	if fresh.isStale(now) {
		t.Fatalf("stream with recent rx must not be stale")
	}

	deadSinceRx := &stream{createdAt: now.Add(-time.Minute)}
	deadSinceRx.lastRx.Store(now.Add(-13 * time.Second).UnixNano())
	if !deadSinceRx.isStale(now) {
		t.Fatalf("stream with rx 13s ago must be stale (12s cutoff)")
	}

	neverRxYoung := &stream{createdAt: now.Add(-5 * time.Second)}
	if neverRxYoung.isStale(now) {
		t.Fatalf("a brand-new stream that hasn't received yet must not be stale before 15s")
	}

	neverRxOld := &stream{createdAt: now.Add(-16 * time.Second)}
	if !neverRxOld.isStale(now) {
		t.Fatalf("a stream that never received anything in 16s must be stale (15s grace)")
	}
}

// --- nextReplenishDelay: pure ---

func TestNextReplenishDelay(t *testing.T) {
	cases := []struct {
		name     string
		cur      time.Duration
		atTarget bool
		progress bool
		want     time.Duration
	}{
		{"at target always slows to 30s", 2 * time.Second, true, false, 30 * time.Second},
		{"progress resets to 2s", 20 * time.Second, false, true, 2 * time.Second},
		{"no progress doubles", 5 * time.Second, false, false, 10 * time.Second},
		{"no progress caps at 30s", 20 * time.Second, false, false, 30 * time.Second},
		{"no progress never exceeds cap", 30 * time.Second, false, false, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nextReplenishDelay(tc.cur, tc.atTarget, tc.progress); got != tc.want {
				t.Fatalf("nextReplenishDelay(%v, atTarget=%v, progress=%v) = %v, want %v",
					tc.cur, tc.atTarget, tc.progress, got, tc.want)
			}
		})
	}
}

// --- integration: real turn.NewAlloc + real DTLS-SRTP handshake against fakeTurn ---

func newTestCoreWithCreds(t *testing.T, ft *fakeTurn, target int64) *core {
	t.Helper()
	c := newCore(&maxproto.Config{}, ft.peerAddr())
	c.creds = []*maxproto.Creds{{
		TurnHosts:  []string{ft.hostAddr()},
		Username:   "user",
		Credential: "pass",
		ExpiresAt:  time.Now().Add(time.Hour),
	}}
	c.targetAllocs.Store(target)
	t.Cleanup(c.stop)
	return c
}

func TestReplenishFillsPoolToTarget(t *testing.T) {
	ft := newFakeTurn(t)
	c := newTestCoreWithCreds(t, ft, 1)

	result := c.replenish()

	if result.opened != 1 {
		t.Fatalf("replenish().opened = %d, want 1 (real Allocate+ChannelBind+DTLS should succeed)", result.opened)
	}
	if got := c.p.length(); got != 1 {
		t.Fatalf("pool length = %d, want 1", got)
	}
}

func TestReplenishReportsQuotaExhaustion(t *testing.T) {
	ft := newFakeTurn(t)
	ft.allocateCode.Store(486)
	c := newTestCoreWithCreds(t, ft, 1)

	result := c.replenish()

	if result.opened != 0 {
		t.Fatalf("replenish().opened = %d, want 0 (server rejects every Allocate with 486)", result.opened)
	}
	if result.quota == 0 {
		t.Fatalf("replenish().quota = 0, want >0 so replenishLoop knows to re-mint instead of retrying the same creds")
	}
	if got := c.p.length(); got != 0 {
		t.Fatalf("pool length = %d, want 0", got)
	}
}

func TestTurnKeepaliveTickDropsAfterTwoFailures(t *testing.T) {
	ft := newFakeTurn(t)
	c := newTestCoreWithCreds(t, ft, 1)
	if result := c.replenish(); result.opened != 1 {
		t.Fatalf("setup: replenish().opened = %d, want 1", result.opened)
	}
	s := c.p.snapshot()[0]

	ft.refreshCode.Store(486)

	c.turnKeepaliveTick()
	if got := c.p.length(); got != 1 {
		t.Fatalf("pool length after 1st refresh failure = %d, want 1 (single failures must not drop it)", got)
	}
	if s.refreshFails != 1 {
		t.Fatalf("refreshFails after 1st failure = %d, want 1", s.refreshFails)
	}

	c.turnKeepaliveTick()
	if got := c.p.length(); got != 0 {
		t.Fatalf("pool length after 2nd consecutive refresh failure = %d, want 0 (dropped)", got)
	}
}

func TestTurnKeepaliveTickResetsFailureCountOnSuccess(t *testing.T) {
	ft := newFakeTurn(t)
	c := newTestCoreWithCreds(t, ft, 1)
	if result := c.replenish(); result.opened != 1 {
		t.Fatalf("setup: replenish().opened = %d, want 1", result.opened)
	}
	s := c.p.snapshot()[0]

	ft.refreshCode.Store(486)
	c.turnKeepaliveTick()
	if s.refreshFails != 1 {
		t.Fatalf("refreshFails = %d, want 1 after one failure", s.refreshFails)
	}

	ft.refreshCode.Store(0)
	c.turnKeepaliveTick()
	if s.refreshFails != 0 {
		t.Fatalf("refreshFails = %d, want reset to 0 after a successful refresh", s.refreshFails)
	}
	if got := c.p.length(); got != 1 {
		t.Fatalf("pool length = %d, want 1 (a recovered allocation must not be dropped)", got)
	}
}

func TestDropStreamRemovesFromPoolAndUpdatesHealthyCount(t *testing.T) {
	ft := newFakeTurn(t)
	c := newTestCoreWithCreds(t, ft, 1)
	if result := c.replenish(); result.opened != 1 {
		t.Fatalf("setup: replenish().opened = %d, want 1", result.opened)
	}
	s := c.p.snapshot()[0]
	s.lastRx.Store(time.Now().UnixNano())
	c.updateHealthyCount()
	if got := c.allocations.Load(); got != 1 {
		t.Fatalf("allocations = %d, want 1 before drop", got)
	}

	c.dropStream(s)

	if got := c.p.length(); got != 0 {
		t.Fatalf("pool length after dropStream = %d, want 0", got)
	}
	if got := c.allocations.Load(); got != 0 {
		t.Fatalf("allocations after dropStream = %d, want 0", got)
	}
}

func TestDiagEmptyStoppedTunnel(t *testing.T) {
	tun := &Tunnel{stopped: true}
	var d tunnelDiag
	if err := json.Unmarshal([]byte(tun.Diag()), &d); err != nil {
		t.Fatalf("Diag() JSON: %v", err)
	}
	if d.Version != 1 || len(d.Streams) != 0 || d.Allocations != 0 {
		t.Fatalf("Diag() = %+v, want empty v1 diag", d)
	}
}

func TestDiagIncludesStreamsAndCounters(t *testing.T) {
	now := time.Now()
	c := newCore(&maxproto.Config{}, nil)
	fresh := &stream{createdAt: now.Add(-time.Second)}
	fresh.lastRx.Store(now.Add(-500 * time.Millisecond).UnixNano())
	fresh.txPackets.Store(3)
	fresh.txBytes.Store(300)
	fresh.rxPackets.Store(2)
	fresh.rxBytes.Store(200)
	stale := &stream{createdAt: now.Add(-time.Minute)}
	stale.lastRx.Store(now.Add(-20 * time.Second).UnixNano())
	stale.refreshFails = 1
	c.p.add(fresh)
	c.p.add(stale)
	c.targetAllocs.Store(2)
	c.credsExpiry.Store(123)
	c.updateHealthyCount()
	tun := &Tunnel{core: c}

	var d tunnelDiag
	if err := json.Unmarshal([]byte(tun.Diag()), &d); err != nil {
		t.Fatalf("Diag() JSON: %v", err)
	}
	if d.Allocations != 1 || d.TargetAllocations != 2 || d.CredsExpireUnix != 123 {
		t.Fatalf("diag summary = %+v", d)
	}
	if len(d.Streams) != 2 {
		t.Fatalf("len(streams) = %d, want 2", len(d.Streams))
	}
	if !d.Streams[0].Healthy || d.Streams[0].Stale || d.Streams[0].TxPackets != 3 || d.Streams[0].RxBytes != 200 {
		t.Fatalf("fresh stream diag = %+v", d.Streams[0])
	}
	if d.Streams[1].Healthy || !d.Streams[1].Stale || d.Streams[1].RefreshFails != 1 {
		t.Fatalf("stale stream diag = %+v", d.Streams[1])
	}
}

func TestDiagEventRingCaps(t *testing.T) {
	c := newCore(&maxproto.Config{}, nil)
	for i := 0; i < diagEventLimit+10; i++ {
		c.diag.add("info", "event")
	}
	if got := len(c.diag.snapshot()); got != diagEventLimit {
		t.Fatalf("diag event count = %d, want %d", got, diagEventLimit)
	}
}
