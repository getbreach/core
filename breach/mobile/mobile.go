// Package breachmobile is the gomobile-facing wrapper around the breach tunnel
// TRANSPORT core. It exposes a tiny surface (StartTransport/Stop/Stat +
// Protector + Logger) so an Android VpnService can drive the MAX-TURN transport
// without reimplementing the MAX/TURN/DTLS-SRTP protocol.
//
// In the sing-box architecture the inner protocol (WireGuard/Hysteria2), the tun
// and routing all live in sing-box (libbox); breach only relays UDP over MAX
// TURN. sing-box's inner-protocol endpoint points at the local "mouth"
// (wgListen, default 127.0.0.1:51821) and breach relays it to the exit server.
package breachmobile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"breach/maxproto"
	"breach/provider"
	"breach/turn"
	"breach/wbproto"
)

// activeCore points at the one running core so the app can poll the LIVE
// allocation count even while StartTransport is still blocking in buildPool
// (it only returns the *Tunnel after the pool is up). Lets the UI show
// allocations climbing during "Connecting".
var activeCore atomic.Pointer[core]

// LiveAllocations returns the running transport's current live allocation count
// (0 if none). Safe to poll at any time, including during connect.
func LiveAllocations() int64 {
	if c := activeCore.Load(); c != nil {
		return c.allocations.Load()
	}
	return 0
}

// CancelStarting aborts an in-progress StartTransport so a user can stop while the
// UI is still "Connecting". Cancels the core's context; start() then returns fast
// with an error instead of blocking up to ~30s for the first allocation.
func CancelStarting() {
	if c := activeCore.Load(); c != nil {
		c.cancel()
	}
}

// Protector lets Go ask the Android VpnService to exclude a socket fd from the
// VPN (VpnService.protect). The transport MUST protect every socket it opens to
// a MAX TURN edge / the exit server / minting / DNS, or that traffic loops into
// the tun and deadlocks — the #1 correctness item on Android.
type Protector interface {
	Protect(fd int) bool
}

// Logger receives core log lines for the app's Logs screen. May be a no-op.
type Logger interface {
	Log(line string)
}

// Tunnel is a running transport handle returned by StartTransport.
type Tunnel struct {
	core      *core
	log       Logger
	startedAt time.Time

	mu        sync.Mutex
	lastWhen  time.Time
	lastUp    int64
	lastDown  int64
	lastUpB   int64
	lastDownB int64
	stopped   bool
}

var protectMu sync.Mutex

// StartTransport launches the breach transport with a JSON config (same schema as
// breach/config.example.json: token/deviceId/server/streams/mints/dns/mintMode/…
// plus wgListen). It opens the local mouth on wgListen and relays it over MAX
// TURN to the exit. Every outbound socket the core opens is run through
// p.Protect(fd). The inner protocol (WireGuard/Hysteria2) is NOT handled here —
// sing-box dials the mouth.
func StartTransport(configJSON string, p Protector, l Logger) (*Tunnel, error) {
	logf := func(s string) {
		if l != nil {
			l.Log(s)
		}
	}

	var probe struct {
		Provider string `json:"provider"`
	}
	_ = json.Unmarshal([]byte(configJSON), &probe)
	switch probe.Provider {
	case "", "max":
		return startMAX(configJSON, p, logf, l)
	case "wb":
		return startWB(configJSON, p, logf, l)
	default:
		return nil, fmt.Errorf("config: unknown provider %q (want max|wb)", probe.Provider)
	}
}

// startMAX is the original MAX-TURN transport path.
func startMAX(configJSON string, p Protector, logf func(string), l Logger) (*Tunnel, error) {
	mc, err := maxproto.ParseConfig([]byte(configJSON))
	if err != nil {
		return nil, err
	}
	server := mc.Server
	if server == "" {
		return nil, fmt.Errorf("config: \"server\" (exit ip:port) is required")
	}
	wgListen := mc.WGListen
	if wgListen == "" {
		wgListen = "127.0.0.1:51821"
	}
	peer, err := net.ResolveUDPAddr("udp", server)
	if err != nil {
		return nil, fmt.Errorf("resolve server %s: %w", server, err)
	}
	logf(fmt.Sprintf("transport starting: provider=max server=%s mouth=%s streams=%d mints=%d mintMode=%s",
		server, wgListen, mc.Streams, mc.Mints, mc.MintMode))
	co := newCore(mc, peer)
	return launch(co, wgListen, mc.DNS, p, logf, l)
}

// startWB mints through WB Chat instead of MAX. The WB session lives at a path in
// the app's private storage ("wbSession"); wbproto's token refresh persists there.
// Minting itself happens inside co.start (buildPool), after launch has installed
// the socket-protect + DNS hooks, so the WB API calls bypass the tun.
func startWB(configJSON string, p Protector, logf func(string), l Logger) (*Tunnel, error) {
	var wc struct {
		Server      string `json:"server"`
		WGListen    string `json:"wgListen"`
		Streams     int    `json:"streams"`
		Mints       int    `json:"mints"`
		KeepaliveMs int    `json:"keepaliveMs"`
		DNS         string `json:"dns"`
		Transport   string `json:"turnTransport"`
		WBSession   string `json:"wbSession"`
		WBChat      string `json:"wbChat"`
		WBCallee    string `json:"wbCallee"`
		WBCallType  string `json:"wbCallType"`
		CredCache   string `json:"credCacheDir"`
	}
	if err := json.Unmarshal([]byte(configJSON), &wc); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if wc.Server == "" {
		return nil, fmt.Errorf("config: \"server\" (exit ip:port) is required")
	}
	wgListen := wc.WGListen
	if wgListen == "" {
		wgListen = "127.0.0.1:51821"
	}
	peer, err := net.ResolveUDPAddr("udp", wc.Server)
	if err != nil {
		return nil, fmt.Errorf("resolve server %s: %w", wc.Server, err)
	}
	m, err := wbproto.NewMinter(wc.WBSession, wc.WBChat, wc.WBCallee, wc.WBCallType, wc.Transport)
	if err != nil {
		return nil, fmt.Errorf("wb: %w", err)
	}
	logf(fmt.Sprintf("transport starting: provider=wb server=%s mouth=%s streams=%d mints=%d chat=%s",
		wc.Server, wgListen, wc.Streams, wc.Mints, wc.WBChat))
	co := newCoreWB([]provider.Minter{m}, peer, wc.Streams, wc.Mints, wc.KeepaliveMs, wc.Transport, wc.CredCache)
	return launch(co, wgListen, wc.DNS, p, logf, l)
}

// launch installs the socket-protect + DNS hooks, starts the core (blocks until
// the first pool build), and returns the Tunnel handle. Shared by both providers.
func launch(co *core, wgListen, dns string, p Protector, logf func(string), l Logger) (*Tunnel, error) {
	// Install the socket-protection hooks, read by turn.NewAlloc, maxproto.Dial and
	// wbproto's HTTP. Serialized: one transport runs at a time.
	protectMu.Lock()
	ctrl := protectControl(p, logf)
	turn.Control = ctrl
	maxproto.Control = ctrl
	wbproto.Control = ctrl
	protectMu.Unlock()

	// Android has no /etc/resolv.conf; resolve API hosts via an explicit DNS over a
	// protected socket so the query bypasses the tun.
	if dns == "" {
		dns = "77.88.8.8:53"
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 8 * time.Second, Control: ctrl}
			return d.DialContext(ctx, "udp", dns)
		},
	}

	co.logf = logf
	activeCore.Store(co) // expose live count during the blocking buildPool
	if err := co.start(wgListen); err != nil {
		activeCore.Store(nil)
		clearHooks()
		return nil, fmt.Errorf("transport start: %w", err)
	}
	logf(fmt.Sprintf("transport running: mouth=%s", wgListen))
	now := time.Now()
	return &Tunnel{core: co, log: l, startedAt: now, lastWhen: now}, nil
}

// Stat returns a JSON snapshot for the UI:
// {allocations, clients, upPps, downPps, mbps, upBytes, downBytes, lastError}.
func (t *Tunnel) Stat() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || t.core == nil {
		return `{"allocations":0,"targetAllocations":0,"clients":0,"upPps":0,"downPps":0,"mbps":0,"lastError":""}`
	}

	up := t.core.upPackets.Load()
	down := t.core.downData.Load()
	upB := t.core.upBytes.Load()
	downB := t.core.downBytes.Load()

	now := time.Now()
	dt := now.Sub(t.lastWhen).Seconds()
	upPps, downPps, mbps := int64(0), int64(0), 0.0
	if dt >= 0.2 {
		upPps = int64(float64(up-t.lastUp) / dt)
		downPps = int64(float64(down-t.lastDown) / dt)
		mbps = float64((upB+downB)-(t.lastUpB+t.lastDownB)) * 8 / 1e6 / dt
		t.lastWhen = now
		t.lastUp = up
		t.lastDown = down
		t.lastUpB = upB
		t.lastDownB = downB
	}

	le, _ := t.core.lastErr.Load().(string)
	return fmt.Sprintf(`{"allocations":%d,"targetAllocations":%d,"clients":1,"upPps":%d,"downPps":%d,"mbps":%g,"upBytes":%d,"downBytes":%d,"credsExpireUnix":%d,"lastError":%q}`,
		t.core.allocations.Load(), t.core.targetAllocs.Load(), upPps, downPps, mbps, upB, downB, t.core.credsExpiry.Load(), le)
}

type tunnelDiag struct {
	Version           int          `json:"version"`
	Allocations       int64        `json:"allocations"`
	TargetAllocations int64        `json:"targetAllocations"`
	CredsExpireUnix   int64        `json:"credsExpireUnix"`
	LastError         string       `json:"lastError"`
	Streams           []streamDiag `json:"streams"`
	Events            []diagEvent  `json:"events"`
}

type streamDiag struct {
	Index        int   `json:"index"`
	AgeMs        int64 `json:"ageMs"`
	LastRxAgeMs  int64 `json:"lastRxAgeMs"`
	Healthy      bool  `json:"healthy"`
	Stale        bool  `json:"stale"`
	RefreshFails int   `json:"refreshFails"`
	TxPackets    int64 `json:"txPackets"`
	RxPackets    int64 `json:"rxPackets"`
	TxBytes      int64 `json:"txBytes"`
	RxBytes      int64 `json:"rxBytes"`
}

func emptyDiag() string {
	return `{"version":1,"allocations":0,"targetAllocations":0,"credsExpireUnix":0,"lastError":"","streams":[],"events":[]}`
}

// Diag returns a versioned per-stream transport-health snapshot for the UI.
func (t *Tunnel) Diag() string {
	t.mu.Lock()
	stopped := t.stopped || t.core == nil
	core := t.core
	t.mu.Unlock()
	if stopped {
		return emptyDiag()
	}

	now := time.Now()
	healthyCutoff := now.Add(-8 * time.Second).UnixNano()
	streams := core.p.snapshot()
	sd := make([]streamDiag, 0, len(streams))
	for i, s := range streams {
		lastRx := s.lastRx.Load()
		lastRxAgeMs := int64(-1)
		if lastRx > 0 {
			lastRxAgeMs = now.Sub(time.Unix(0, lastRx)).Milliseconds()
		}
		sd = append(sd, streamDiag{
			Index:        i,
			AgeMs:        now.Sub(s.createdAt).Milliseconds(),
			LastRxAgeMs:  lastRxAgeMs,
			Healthy:      lastRx >= healthyCutoff,
			Stale:        s.isStale(now),
			RefreshFails: s.refreshFails,
			TxPackets:    s.txPackets.Load(),
			RxPackets:    s.rxPackets.Load(),
			TxBytes:      s.txBytes.Load(),
			RxBytes:      s.rxBytes.Load(),
		})
	}
	le, _ := core.lastErr.Load().(string)
	out := tunnelDiag{
		Version:           1,
		Allocations:       core.allocations.Load(),
		TargetAllocations: core.targetAllocs.Load(),
		CredsExpireUnix:   core.credsExpiry.Load(),
		LastError:         le,
		Streams:           sd,
		Events:            core.diag.snapshot(),
	}
	b, err := json.Marshal(out)
	if err != nil {
		return emptyDiag()
	}
	return string(b)
}

func (t *Tunnel) NetworkChanged() {
	t.mu.Lock()
	if t.stopped || t.core == nil {
		t.mu.Unlock()
		return
	}
	core := t.core
	t.mu.Unlock()
	core.networkChanged()
}

// Stop tears down the transport core (cancels loops, closes sockets).
func (t *Tunnel) Stop() {
	t.mu.Lock()
	if t.stopped {
		t.mu.Unlock()
		return
	}
	t.stopped = true
	co, l := t.core, t.log
	t.mu.Unlock()

	// Only clear the global protection hooks if THIS core still owns them. On a
	// fast reconnect a new StartTransport has already Stored its own core into
	// activeCore and reinstalled the hooks; this (old) core's teardown can finish
	// seconds later, and clearing then would strip the NEW core's socket
	// protection. The CAS succeeds only when we're still the active core.
	stillActive := true
	if co != nil {
		stillActive = activeCore.CompareAndSwap(co, nil)
		co.stop()
	}
	if l != nil {
		l.Log("transport stopped")
	}
	if stillActive {
		clearHooks()
	}
}

func clearHooks() {
	protectMu.Lock()
	turn.Control = nil
	maxproto.Control = nil
	protectMu.Unlock()
}

// protectControl builds a syscall Control hook that protects every fd the core
// opens via the VpnService.
func protectControl(p Protector, logf func(string)) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var ctrlErr error
		err := c.Control(func(fd uintptr) {
			if !p.Protect(int(fd)) {
				ctrlErr = fmt.Errorf("protect(fd=%d) failed for %s %s", fd, network, address)
				logf(ctrlErr.Error())
			}
		})
		if err != nil {
			return err
		}
		return ctrlErr
	}
}
