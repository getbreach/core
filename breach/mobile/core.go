package breachmobile

// core.go ports breach/cmd/client into a start/stoppable struct for the mobile
// wrapper. It mints MAX TURN credentials, opens a pool of TURN allocations each
// running a DTLS-SRTP session, shards the local WireGuard UDP across them, and
// keeps every allocation alive (SRTP keepalive + TURN refresh) and re-minted.
// The ONLY behavioural change versus cmd/client is that every outbound socket is
// protected from the VpnService (via the turn/maxproto Control hooks) and the
// lifecycle is cancellable. The protocol/transport is unchanged.

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"breach/maxproto"
	"breach/media"
	"breach/provider"
	"breach/turn"
)

const diagEventLimit = 64

type stream struct {
	cred         *maxproto.Creds
	a            *turn.Alloc
	sess         *media.Session
	refreshFails int
	createdAt    time.Time
	lastRx       atomic.Int64
	txPackets    atomic.Int64
	txBytes      atomic.Int64
	rxPackets    atomic.Int64
	rxBytes      atomic.Int64
	done         chan struct{}
	closeOnce    sync.Once
	turnMu       sync.Mutex
}

type diagEvent struct {
	TimeUnix int64  `json:"timeUnix"`
	Level    string `json:"level"`
	Message  string `json:"message"`
}

type diagLog struct {
	mu     sync.Mutex
	events []diagEvent
}

func (d *diagLog) add(level, message string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events = append(d.events, diagEvent{TimeUnix: time.Now().Unix(), Level: level, Message: message})
	if len(d.events) > diagEventLimit {
		d.events = append([]diagEvent(nil), d.events[len(d.events)-diagEventLimit:]...)
	}
}

func (d *diagLog) snapshot() []diagEvent {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]diagEvent(nil), d.events...)
}

// close frees the TURN allocation on the server (releases the credential's quota
// immediately) so a reconnect reusing a cached credential doesn't hit 486.
func (s *stream) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.turnMu.Lock()
		s.a.Deallocate()
		s.turnMu.Unlock()
	})
}

func (s *stream) abort() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.a.Close()
	})
}

func (s *stream) keepTURNAlive() error {
	s.turnMu.Lock()
	defer s.turnMu.Unlock()
	return s.a.Keepalive()
}

type replenishResult struct {
	opened int
	quota  int
}

// stripeChunk keeps a burst of consecutive packets on one allocation before the
// round-robin advances. Per-packet striping across relays of differing RTT
// reorders the inner flow badly; WireGuard tolerates it (wide replay window) but
// the inner TCP reads reordering as loss and collapses, and QUIC-based inner
// protocols (Hysteria2) punish it harder still. A burst per relay keeps each
// flow near-ordered while load stays spread; a full sweep of the pool stays
// inside WireGuard's replay window.
const stripeChunk = 16

type pool struct {
	mu      sync.RWMutex
	streams []*stream
	rr      uint64
}

func (p *pool) set(s []*stream) []*stream {
	p.mu.Lock()
	old := p.streams
	p.streams = s
	p.mu.Unlock()
	return old
}

// replace keeps a retained allocation only if it is still in the live pool.
// A health check may have removed it while a resize was opening other streams.
func (p *pool) replace(candidates []*stream, retained map[*stream]bool) (old, live []*stream) {
	p.mu.Lock()
	defer p.mu.Unlock()
	present := make(map[*stream]bool, len(p.streams))
	for _, s := range p.streams {
		present[s] = true
	}
	for _, s := range candidates {
		if streamOpen(s) && (!retained[s] || present[s]) {
			live = append(live, s)
		}
	}
	old = p.streams
	if len(live) > 0 {
		p.streams = live
	} else {
		old = nil
	}
	return
}

func (p *pool) snapshot() []*stream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]*stream(nil), p.streams...)
}

func (p *pool) pick() *stream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.streams) == 0 {
		return nil
	}
	i := atomic.AddUint64(&p.rr, 1)
	// Divide BEFORE narrowing: on a 32-bit int, converting the raw counter first
	// wraps negative after tens of billions of packets and panics. Kept in uint64.
	return p.streams[(i/stripeChunk)%uint64(len(p.streams))]
}

func (p *pool) add(s *stream) {
	p.mu.Lock()
	p.streams = append(p.streams, s)
	p.mu.Unlock()
}

// remove drops s from the pool (by identity). Returns true if it was present —
// callers use that to close/deallocate exactly once under concurrent death signals.
func (p *pool) remove(s *stream) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, x := range p.streams {
		if x == s {
			p.streams = append(p.streams[:i], p.streams[i+1:]...)
			return true
		}
	}
	return false
}

func (p *pool) length() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.streams)
}

// core is one running breach client instance.
type core struct {
	cfg           *maxproto.Config  // MAX identity (nil in wb mode)
	providerName  string            // "max" | "wb"
	wbMinters     []provider.Minter // wb mode: one minter per WB session/chat
	credCacheDir  string            // wb mode: MAX reads this from cfg instead
	turnTransport string            // default client<->relay transport; creds.Transport wins
	peer          *net.UDPAddr
	nStreams      int
	nMints        int
	ka            time.Duration

	clientID [8]byte
	wgConn   *net.UDPConn
	wgClient atomic.Pointer[net.UDPAddr]
	p        *pool

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	openAllocation func(*maxproto.Creds, int) (*stream, error)

	logf func(string) // mirrors pool build progress to the app Logs screen

	requested        atomic.Pointer[poolSettings]
	applied          atomic.Uint64
	credentialGroups map[string][]*maxproto.Creds // buildMu

	buildMu      sync.Mutex        // serializes buildPool (start/remint/emergency-rebuild)
	credsMu      sync.Mutex        // guards creds
	creds        []*maxproto.Creds // still-valid creds, reused to replenish dead allocations
	targetAllocs atomic.Int64      // desired live allocation count (accounts×mints×streams achieved at build)
	reconcile    chan struct{}

	// stats
	upPackets   atomic.Int64
	downData    atomic.Int64
	upBytes     atomic.Int64
	downBytes   atomic.Int64
	allocations atomic.Int64
	credsExpiry atomic.Int64 // unix seconds; earliest TURN cred expiry in the pool
	lastErr     atomic.Value // string
	diag        diagLog
}

// clampKeepalive turns a config keepalive value (ms) into a sane interval:
// 0 (unset) -> 50ms default; otherwise clamped to [20,500]ms so the UI can't
// push a value that either floods MAX (too low) or lets the throttle re-engage
// (too high).
func clampKeepalive(ms int) time.Duration {
	if ms <= 0 {
		ms = 50
	}
	if ms < 20 {
		ms = 20
	}
	if ms > 500 {
		ms = 500
	}
	return time.Duration(ms) * time.Millisecond
}

func newCore(cfg *maxproto.Config, peer *net.UDPAddr) *core {
	ctx, cancel := context.WithCancel(context.Background())
	c := &core{cfg: cfg, peer: peer, p: &pool{}, ctx: ctx, cancel: cancel, reconcile: make(chan struct{}, 1)}
	c.nStreams = cfg.Streams
	if c.nStreams <= 0 {
		c.nStreams = 4
	}
	c.nMints = cfg.Mints
	if c.nMints <= 0 {
		c.nMints = 1
	}
	c.ka = clampKeepalive(cfg.KeepaliveMs)
	c.providerName = "max"
	c.turnTransport = cfg.TurnTransport
	rand.Read(c.clientID[:])
	c.lastErr.Store("")
	c.logf = func(string) {}
	c.initLimits()
	c.openAllocation = c.openOne
	return c
}

// newCoreWB builds a core that mints via a provider.Minter (WB) instead of MAX.
// Tunnel params are explicit (there is no maxproto.Config); everything below
// minting — pool, DTLS-SRTP, keepalive, replenish — is the shared MAX path.
func newCoreWB(minters []provider.Minter, peer *net.UDPAddr, streams, mints, keepaliveMs int, transport, credCacheDir string) *core {
	ctx, cancel := context.WithCancel(context.Background())
	c := &core{peer: peer, p: &pool{}, ctx: ctx, cancel: cancel, reconcile: make(chan struct{}, 1)}
	c.providerName = "wb"
	c.wbMinters = minters
	c.credCacheDir = credCacheDir
	c.nStreams = streams
	if c.nStreams <= 0 {
		c.nStreams = 4
	}
	c.nMints = mints
	if c.nMints <= 0 {
		c.nMints = 1
	}
	c.ka = clampKeepalive(keepaliveMs)
	if transport == "" {
		transport = "auto"
	}
	c.turnTransport = transport
	rand.Read(c.clientID[:])
	c.lastErr.Store("")
	c.logf = func(string) {}
	c.initLimits()
	c.openAllocation = c.openOne
	return c
}

func (c *core) log(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	if c.logf != nil {
		c.logf(msg)
	}
	c.diag.add("info", msg)
}

func (c *core) setErr(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	c.lastErr.Store(msg)
	c.diag.add("error", msg)
}

func (c *core) start(wgListen string) error {
	laddr, err := net.ResolveUDPAddr("udp", wgListen)
	if err != nil {
		return fmt.Errorf("resolve wg-listen %s: %w", wgListen, err)
	}
	// The mouth is loopback only; it must NOT be protected (it is the internal
	// hand-off to wireguard-go, not traffic that should bypass the tun).
	c.wgConn, err = net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", wgListen, err)
	}
	c.wgConn.SetReadBuffer(16 << 20)
	c.wgConn.SetWriteBuffer(16 << 20)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.buildPool(false)
	}()

	c.wg.Add(1)
	go c.turnKeepaliveLoop()
	c.wg.Add(1)
	go c.healthLoop()
	c.wg.Add(1)
	go c.remintLoop()
	c.wg.Add(1)
	go c.replenishLoop()
	c.wg.Add(1)
	go c.uplinkLoop()
	return nil
}

func (c *core) stop() {
	c.cancel()
	if c.wgConn != nil {
		c.wgConn.Close() // unblocks uplinkLoop's ReadFromUDP
	}
	// Wait for pool mutations before the final drain. No builder may publish
	// a stream after this point, otherwise its reader could keep wg.Wait alive.
	c.buildMu.Lock()
	for _, s := range c.p.set(nil) {
		s.close()
	}
	c.buildMu.Unlock()
	c.wg.Wait()
}

// uplinkLoop reads WireGuard's encrypted packets from the mouth and relays each
// across a picked allocation as SRTP "media", tagged with the clientID.
func (c *core) uplinkLoop() {
	defer c.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, src, err := c.wgConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				c.setErr("wg read: %v", err)
				return
			}
		}
		c.wgClient.Store(src)
		if s := c.p.pick(); s != nil {
			msg := make([]byte, len(c.clientID)+n)
			copy(msg, c.clientID[:])
			copy(msg[len(c.clientID):], buf[:n])
			if wire, err := s.sess.Protect(media.PTData, msg); err == nil {
				if s.a.Send(wire) == nil {
					c.upPackets.Add(1)
					c.upBytes.Add(int64(n))
					s.txPackets.Add(1)
					s.txBytes.Add(int64(n))
				}
			}
		}
	}
}

func (c *core) buildPool(freshMint bool) time.Time {
	if !c.buildMu.TryLock() {
		return time.Time{}
	}
	defer c.buildMu.Unlock()
	if c.ctx.Err() != nil {
		return time.Time{}
	}
	settings := c.requested.Load()
	c.nMints, c.nStreams = settings.Mints, settings.Streams
	c.log("building allocation pool (freshMint=%t)", freshMint)
	earliest := time.Time{}
	var newStreams []*stream
	var newStreamsMu sync.Mutex
	previous := c.p.snapshot()
	retained := make(map[*stream]bool)
	for _, s := range previous {
		retained[s] = true
	}
	committed := false
	defer func() {
		if !committed {
			for _, s := range newStreams {
				if !retained[s] {
					s.close()
				}
			}
		}
	}()

	type openResult struct {
		opened int
		quota  int
	}

	openCred := func(creds *maxproto.Creds) openResult {
		var wg sync.WaitGroup
		var opened atomic.Int64
		var quota atomic.Int64
		reused := 0
		for _, s := range previous {
			if s.cred == creds && streamOpen(s) && !s.isStale(time.Now()) && reused < c.nStreams {
				newStreams = append(newStreams, s)
				reused++
				opened.Add(1)
			}
		}
		for i := reused; i < c.nStreams; i++ {
			idx := i
			wg.Add(1)
			go func() {
				defer wg.Done()
				s, err := c.openAllocation(creds, idx)
				if err != nil {
					if turn.ErrorCode(err) == 486 {
						quota.Add(1)
					}
					return
				}
				newStreamsMu.Lock()
				newStreams = append(newStreams, s)
				newStreamsMu.Unlock()
				c.activate(s)
				opened.Add(1)
			}()
		}
		wg.Wait()
		return openResult{opened: int(opened.Load()), quota: int(quota.Load())}
	}

	var allCreds []*maxproto.Creds
	if c.providerName == "wb" {
		for mi, mtr := range c.wbMinters {
			// Same cache the MAX path uses — the on-disk format is provider-agnostic
			// (provider.Creds IS maxproto.Creds), only the key differs. Reusing a
			// still-valid credential is what keeps a reconnect from placing another
			// call: WB mints by ringing the chat's peer, so an uncached reconnect is
			// a real notification on someone else's phone.
			key := mtr.CacheKey()
			var cached []*maxproto.Creds
			if !freshMint {
				cached = c.cachedCreds(c.credCacheDir, key)
			}
			c.log("wb minter%d: %d valid cached creds (mints=%d streams=%d)", mi, len(cached), c.nMints, c.nStreams)
			var usable []*maxproto.Creds
			for m := 0; m < c.nMints; m++ {
				select {
				case <-c.ctx.Done():
					return earliest
				default:
				}
				var creds *maxproto.Creds
				fromCache := m < len(cached)
				if fromCache {
					creds = cached[m]
				} else {
					c.log("wb minter%d cred%d: minting (no cache)...", mi, m)
					nc, err := mtr.Mint("")
					if err != nil {
						c.log("wb minter%d cred%d: mint FAILED: %v", mi, m, err)
						c.setErr("wb mint failed: %v", err)
						continue
					}
					creds = nc
				}
				result := openCred(creds)
				src := "cache"
				if !fromCache {
					src = "mint"
				}
				c.log("wb minter%d cred%d (%s): %d/%d allocations up", mi, m, src, result.opened, c.nStreams)
				if result.opened == 0 && result.quota > 0 && fromCache {
					// The cached credential is spent: its relay still answers but has no
					// allocations left for it. Only a fresh mint fixes that.
					c.log("wb minter%d cred%d: cached cred quota exhausted, re-minting...", mi, m)
					if nc, err := mtr.Mint(""); err == nil {
						creds = nc
						result = openCred(creds)
						c.log("wb minter%d cred%d (remint): %d/%d allocations up", mi, m, result.opened, c.nStreams)
					} else {
						c.log("wb minter%d cred%d: re-mint FAILED: %v", mi, m, err)
						c.setErr("wb re-mint failed: %v", err)
					}
				}
				if result.quota < c.nStreams || result.opened > 0 {
					usable = append(usable, creds)
					if earliest.IsZero() || creds.ExpiresAt.Before(earliest) {
						earliest = creds.ExpiresAt
					}
				}
			}
			c.rememberCreds(c.credCacheDir, key, usable, cached)
			allCreds = append(allCreds, usable...)
		}
	} else {
		accounts := c.cfg.MintAccounts()
		for ai, acfg := range accounts {
			var cached []*maxproto.Creds
			if !freshMint {
				cached = c.cachedCreds(c.cfg.CredCacheDir, acfg.Token)
			}
			c.log("acct%d: %d valid cached creds (mints=%d streams=%d)", ai, len(cached), c.nMints, c.nStreams)
			var usable []*maxproto.Creds
			// Each mint creates its own group call by default so it gets its own MAX
			// throttle bucket (throughput scales with mints). ReuseGroupCall instead
			// re-joins one conference across this account's mints (seeded from a cached
			// cred across restarts) — fewer calls, but a single shared bucket.
			reuseLink := ""
			if c.cfg.ReuseGroupCall {
				for _, cc := range cached {
					if cc != nil && cc.JoinLink != "" {
						reuseLink = cc.JoinLink
						break
					}
				}
			}
			for m := 0; m < c.nMints; m++ {
				select {
				case <-c.ctx.Done():
					return earliest
				default:
				}
				var creds *maxproto.Creds
				fromCache := m < len(cached)
				if fromCache {
					creds = cached[m]
				} else {
					c.log("acct%d cred%d: minting (no cache)...", ai, m)
					nc, err := maxproto.MintFrom(acfg, reuseLink)
					if err != nil {
						c.log("acct%d cred%d: mint FAILED: %v", ai, m, err)
						c.setErr("mint acct%d failed: %v", ai, err)
						break
					}
					creds = nc
					if c.cfg.ReuseGroupCall {
						reuseLink = nc.JoinLink
					}
				}
				result := openCred(creds)
				src := "cache"
				if !fromCache {
					src = "mint"
				}
				c.log("acct%d cred%d (%s): %d/%d allocations up", ai, m, src, result.opened, c.nStreams)
				if result.opened == 0 && result.quota > 0 && fromCache {
					// Force a FRESH conference here: re-joining the old link returns the
					// SAME (exhausted) credential, so a refresh needs a new conference.
					c.log("acct%d cred%d: cached cred quota exhausted, re-minting (new conference)...", ai, m)
					if nc, err := maxproto.MintFrom(acfg, ""); err == nil {
						creds = nc
						if c.cfg.ReuseGroupCall {
							reuseLink = nc.JoinLink
						}
						result = openCred(creds)
						c.log("acct%d cred%d (remint): %d/%d allocations up", ai, m, result.opened, c.nStreams)
					} else {
						c.log("acct%d cred%d: re-mint FAILED: %v", ai, m, err)
						c.setErr("re-mint acct%d failed: %v", ai, err)
					}
				}
				if result.quota < c.nStreams || result.opened > 0 {
					usable = append(usable, creds)
					if earliest.IsZero() || creds.ExpiresAt.Before(earliest) {
						earliest = creds.ExpiresAt
					}
				}
			}
			c.rememberCreds(c.cfg.CredCacheDir, acfg.Token, usable, cached)
			allCreds = append(allCreds, usable...)
		}
	}

	if c.ctx.Err() != nil {
		return earliest
	}
	live := newStreams[:0]
	for _, s := range newStreams {
		if streamOpen(s) {
			live = append(live, s)
		}
	}
	newStreams = live
	if len(newStreams) > 0 {
		oldStreams, selectedStreams := c.p.replace(newStreams, retained)
		newStreams = selectedStreams
		selected := make(map[*stream]bool, len(newStreams))
		for _, s := range newStreams {
			selected[s] = true
		}
		for _, s := range oldStreams {
			if !selected[s] {
				s.close()
			}
		}
		committed = len(newStreams) > 0
		c.log("allocation pool active: %d stream(s); existing allocations reused", len(newStreams))
	}

	if len(allCreds) > 0 {
		c.credsMu.Lock()
		c.creds = allCreds
		c.credsMu.Unlock()

	}
	target := c.accountCount() * c.nMints * c.nStreams
	c.targetAllocs.Store(int64(target))
	if committed && c.p.length() == target {
		c.applied.Store(settings.Version)
	}
	c.updateHealthyCount()
	if !earliest.IsZero() {
		c.credsExpiry.Store(earliest.Unix())
	}
	return earliest
}

func (c *core) openOne(creds *maxproto.Creds, i int) (*stream, error) {
	hosts := creds.TurnHosts
	if len(hosts) == 0 {
		return nil, fmt.Errorf("credential has no TURN hosts")
	}
	host := hosts[i%len(hosts)]
	tr := creds.Transport
	if tr == "" {
		tr = c.turnTransport
	}
	a, err := turn.NewAlloc(host, creds.Username, creds.Credential, c.peer, 0x4000, tr)
	if err != nil {
		c.setErr("alloc (%s): %v", host, err)
		return nil, err
	}
	stopCancel := context.AfterFunc(c.ctx, func() { a.Close() })
	defer stopCancel()
	handshakeCtx, stopHandshake := context.WithTimeout(c.ctx, 10*time.Second)
	defer stopHandshake()
	sess, err := media.ClientContext(handshakeCtx, a.NetConn())
	if err != nil {
		c.setErr("dtls (%s): %v", host, err)
		a.Close()
		return nil, err
	}
	return &stream{cred: creds, a: a, sess: sess, createdAt: time.Now(), done: make(chan struct{})}, nil
}

// activate wires a live stream's reader + keepalive goroutines.
func (c *core) activate(s *stream) {
	c.startReader(s)
	c.wg.Add(1)
	go c.keepalive(s)
}

// dropStream removes a dead allocation from the pool (idempotent) and frees it,
// keeping the live count honest so pick() stops selecting a zombie.
func (c *core) dropStream(s *stream) {
	removed := c.p.remove(s)
	// A new stream may fail before a resize publishes it into the pool.
	s.abort()
	if removed {
		c.updateHealthyCount()
		c.log("allocation died -> %d in pool (target %d)", c.p.length(), c.targetAllocs.Load())
		c.wakeReconciler()
	}
}

// replenishLoop keeps the pool at targetAllocs: it reopens dead allocations on the
// still-valid creds (no re-mint), and if the pool has emptied entirely it does a
// full rebuild (which re-mints as needed). Runs continuously so the tunnel always
// self-heals in the background.
func (c *core) replenishLoop() {
	defer c.wg.Done()
	delay := 2 * time.Second
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-c.reconcile:
		case <-timer.C:
		}

		target := c.targetAllocs.Load()
		progress := false
		if c.requested.Load().Version != c.applied.Load() || target == 0 {
			before := c.p.length()
			c.buildPool(false)
			progress = c.p.length() > before
		} else if int64(c.p.length()) < target {
			result := c.replenish()
			progress = result.opened > 0
			if result.opened == 0 && result.quota > 0 {
				c.log("TURN quota exhausted -> rebuilding with fresh credentials")
				before := c.p.length()
				c.buildPool(true)
				progress = c.p.length() > before
			}
		}

		atTarget := int64(c.p.length()) >= c.targetAllocs.Load() && c.targetAllocs.Load() > 0
		delay = nextReplenishDelay(delay, atTarget, progress)
		timer.Reset(delay)
	}
}

// nextReplenishDelay computes replenishLoop's next poll interval: slow (30s)
// once the pool is at target, fast (2s) while actively making progress, and
// exponential backoff (capped at 30s) while stalled with nothing to show for it.
func nextReplenishDelay(cur time.Duration, atTarget, progress bool) time.Duration {
	switch {
	case atTarget:
		return 30 * time.Second
	case progress:
		return 2 * time.Second
	default:
		d := cur * 2
		if d > 30*time.Second {
			d = 30 * time.Second
		}
		return d
	}
}

// replenish opens the missing allocations on the cached creds; returns how many
// it actually opened this pass.
func (c *core) replenish() replenishResult {
	if !c.buildMu.TryLock() {
		return replenishResult{}
	}
	defer c.buildMu.Unlock()
	target := int(c.targetAllocs.Load())
	need := target - c.p.length()
	if need <= 0 {
		return replenishResult{}
	}
	c.credsMu.Lock()
	creds := append([]*maxproto.Creds(nil), c.creds...)
	c.credsMu.Unlock()
	if len(creds) == 0 {
		return replenishResult{}
	}
	// Open the missing allocations CONCURRENTLY: each open may have to wait out a
	// TURN timeout (e.g. right after connectivity returns), so opening 20+ serially
	// would take minutes — in parallel the whole pool recovers in one round-trip.
	var wg sync.WaitGroup
	var opened atomic.Int64
	var quota atomic.Int64
	type vacancy struct {
		cr  *maxproto.Creds
		idx int
	}
	var missing []vacancy
	active := c.p.snapshot()
	for _, cr := range creds {
		count := 0
		for _, s := range active {
			if s.cred == cr && streamOpen(s) {
				count++
			}
		}
		for idx := count; idx < c.nStreams && len(missing) < need; idx++ {
			missing = append(missing, vacancy{cr, idx})
		}
	}
	for _, slot := range missing {
		if c.ctx.Err() != nil {
			break
		}
		cr, idx := slot.cr, slot.idx
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := c.openAllocation(cr, idx)
			if err != nil {
				if turn.ErrorCode(err) == 486 {
					quota.Add(1)
				}
				return
			}
			if c.ctx.Err() != nil { // shutting down between open and add -> don't leak
				s.close()
				return
			}
			c.p.add(s)
			c.activate(s)
			opened.Add(1)
		}()
	}
	wg.Wait()
	if opened.Load() > 0 {
		n := c.p.length()
		c.log("replenished %d allocation(s) -> %d live (target %d)", opened.Load(), n, target)
	} else if quota.Load() > 0 {
		c.log("replenish hit TURN quota on %d allocation attempt(s)", quota.Load())
	}
	c.updateHealthyCount()
	return replenishResult{opened: int(opened.Load()), quota: int(quota.Load())}
}

// startReader drains one stream's inbound to the WireGuard client, dropping
// keepalive RTP packets and anything not framed as our data.
func (c *core) startReader(s *stream) {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		for raw := range s.a.In() {
			if !media.IsRTP(raw) {
				continue
			}
			pt, payload, err := s.sess.Unprotect(raw)
			if err != nil {
				continue
			}
			first := s.lastRx.Swap(time.Now().UnixNano()) == 0
			if first {
				c.updateHealthyCount()
			}
			if pt != media.PTData {
				continue
			}
			c.downData.Add(1)
			c.downBytes.Add(int64(len(payload)))
			s.rxPackets.Add(1)
			s.rxBytes.Add(int64(len(payload)))
			if cl := c.wgClient.Load(); cl != nil {
				c.wgConn.WriteToUDP(payload, cl)
			}
		}
		// In() closed -> the allocation's socket is gone. Drop it (unless we're
		// shutting down, in which case it was already removed by stop()).
		if c.ctx.Err() == nil {
			c.dropStream(s)
		}
	}()
}

// staleDeadline is when s should be considered dead: 12s after its last
// confirmed-received packet, or 15s after creation if it has never received one
// (giving a fresh allocation slightly longer to complete its first round-trip).
func (s *stream) staleDeadline() time.Time {
	if lastRx := s.lastRx.Load(); lastRx > 0 {
		return time.Unix(0, lastRx).Add(12 * time.Second)
	}
	return s.createdAt.Add(15 * time.Second)
}

func (s *stream) isStale(now time.Time) bool {
	return now.After(s.staleDeadline())
}

func (c *core) healthLoop() {
	defer c.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-ticker.C:
			for _, s := range c.p.snapshot() {
				if s.isStale(now) {
					c.dropStream(s)
				}
			}
			c.updateHealthyCount()
		}
	}
}

func (c *core) updateHealthyCount() {
	cutoff := time.Now().Add(-8 * time.Second).UnixNano()
	var healthy int64
	for _, s := range c.p.snapshot() {
		if s.lastRx.Load() >= cutoff {
			healthy++
		}
	}
	previous := c.allocations.Swap(healthy)
	if previous == 0 && healthy > 0 {
		c.lastErr.Store("")
	}
}

func (c *core) wakeReconciler() {
	select {
	case c.reconcile <- struct{}{}:
	default:
	}
}

func (c *core) networkChanged() {
	for _, s := range c.p.set(nil) {
		s.abort()
	}
	c.allocations.Store(0)
	// UDP reachability can flip on a network change (cellular↔Wi-Fi, VPN up/down),
	// so re-probe UDP instead of staying pinned to the TCP fallback.
	turn.ResetTransportProbe()
	c.log("network recovered -> rebuilding allocation pool")
	c.wakeReconciler()
}

// keepalive sends small SRTP "media" packets so MAX keeps this allocation's
// client->server direction unthrottled even when real upstream is idle.
func (c *core) keepalive(s *stream) {
	defer c.wg.Done()
	t := time.NewTicker(c.ka)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-s.done:
			return
		case <-t.C:
			wire, err := s.sess.Protect(media.PTKeepalive, c.clientID[:])
			if err != nil {
				c.dropStream(s) // SRTP session broken -> genuinely unusable
				return
			}
			// A Send error is a transient network condition; do NOT drop here. A real
			// network change is handled by a full VPN reconnect (app side), and a
			// genuinely dead relay is caught by turnKeepaliveLoop (refresh 2x). This
			// avoids tearing the whole pool down on a brief blip.
			_ = s.a.Send(wire)
		}
	}
}

// turnKeepaliveLoop refreshes each allocation + channel binding well before their
// ~600s TURN lifetime expires. The 60s cadence also DETECTS relay-side deaths fast
// (a refresh failure is the only reliable signal — the SRTP keepalive's UDP Send
// never errors when the relay silently drops an allocation) so replenishLoop can
// replace them promptly.
func (c *core) turnKeepaliveLoop() {
	defer c.wg.Done()
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.turnKeepaliveTick()
		}
	}
}

// turnKeepaliveTick refreshes every pooled allocation once. A refresh failure
// means either the relay dropped this allocation, or bursty mobile loss ate the
// refresh; it's dropped only after 2 in a row so a single lost packet doesn't
// kill a healthy allocation.
func (c *core) turnKeepaliveTick() {
	for _, s := range c.p.snapshot() {
		if err := s.keepTURNAlive(); err != nil {
			s.refreshFails++
			c.setErr("turn keepalive: %v", err)
			if s.refreshFails >= 2 {
				c.dropStream(s)
			}
		} else {
			s.refreshFails = 0
		}
	}
}

func (c *core) remintLoop() {
	defer c.wg.Done()
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			exp := c.credsExpiry.Load()
			if exp == 0 || time.Until(time.Unix(exp, 0)) > 20*time.Minute {
				continue // pool not built yet, or creds still fresh
			}
			c.buildPool(false)
		}
	}
}
