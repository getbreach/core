//go:build mgmt

package mgmt

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Per-user Hysteria2 accounting.
//
// WireGuard hands us per-peer counters for free (`wg show wg0 dump`); Hysteria2
// has nothing equivalent, so an Hy2-only exit reported rx=0/tx=0/offline for
// every client forever. sing-box's Clash API is the only place that knows both
// the byte counts and which authenticated user a connection belongs to, so this
// poller reads it and maintains cumulative totals for `stats` to join against.
//
// Why a poller and not a straight read: /connections is a LIVE snapshot whose
// per-connection counters are cumulative-since-open, and a connection vanishes
// the moment it closes. So totals are integrated as deltas per connection id.
// Consequence worth knowing: a connection that opens AND closes entirely between
// two polls is never seen, which undercounts very short connections. Good enough
// to show a user's data use; not billing-grade.
//
// Totals survive restarts (persisted to disk and reloaded), which matters here
// because sing-box is restarted on every provision/remove — its own counters
// reset each time, ours must not.

const (
	hy2PollInterval = 1 * time.Second
	hy2FlushEvery   = 15 * time.Second
	// A user counts as online while sing-box still holds a connection for them.
	// Written as a timestamp so `stats` can apply its own staleness window.
	hy2StatsFile = "hy2_stats"
)

type hy2User struct {
	up       uint64
	down     uint64
	lastSeen int64 // unix seconds; 0 = never
}

type hy2Poller struct {
	confDir string
	port    int

	mu    sync.Mutex
	users map[string]*hy2User
	// Last seen counters per connection id, to turn cumulative-per-connection
	// numbers into deltas.
	conns map[string]struct{ up, down uint64 }
	// The first snapshot after start is a BASELINE, not traffic. This poller is
	// restart-supervised independently of sing-box, so after a mgmt-only restart
	// the totals come back from disk while sing-box still holds connections whose
	// counters have been running for hours. Without priming, that first poll would
	// re-add each live connection's entire since-open byte count on top of the
	// totals that already include it — a permanent, self-amplifying overcount.
	// Priming instead loses only what was transferred since the last flush.
	primed bool
}

// startHy2Poller launches the Clash-API poller in the background. It is
// best-effort: if the API never comes up (sing-box not running, no clash secret
// yet) it just keeps retrying, and `stats` falls back to WireGuard-only numbers.
func startHy2Poller(ctx context.Context, confDir string, port int) *hy2Poller {
	p := &hy2Poller{
		confDir: confDir,
		port:    port,
		users:   map[string]*hy2User{},
		conns:   map[string]struct{ up, down uint64 }{},
	}
	p.load()
	go p.run(ctx)
	return p
}

func (p *hy2Poller) run(ctx context.Context) {
	tick := time.NewTicker(hy2PollInterval)
	defer tick.Stop()
	flush := time.NewTicker(hy2FlushEvery)
	defer flush.Stop()

	client := &http.Client{Timeout: 5 * time.Second}
	warned := false
	for {
		select {
		case <-ctx.Done():
			// Bank what has accrued since the last flush instead of losing it on
			// every graceful stop (docker restart, image upgrade).
			p.save()
			return
		case <-tick.C:
			if err := p.poll(client); err != nil {
				if !warned {
					// Once, not every second: a down API is normal at boot.
					log.Printf("breach-mgmt: Hy2 stats unavailable (%v); per-user Hy2 traffic will stay 0 until it comes up", err)
					warned = true
				}
				continue
			}
			warned = false
		case <-flush.C:
			p.save()
		}
	}
}

// clashConn is the subset of a /connections entry we need. "user" is present
// because the image patches sing-box's Clash serializer to emit it.
type clashConn struct {
	ID       string `json:"id"`
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
	Metadata struct {
		User string `json:"user"`
	} `json:"metadata"`
	// Fallback when an unpatched sing-box is in the image: a route rule of the
	// form `auth_user=NAME => ...` still names the user.
	Rule string `json:"rule"`
}

func (p *hy2Poller) poll(client *http.Client) error {
	secret, err := os.ReadFile(filepath.Join(p.confDir, "clash-secret"))
	if err != nil {
		return fmt.Errorf("clash secret: %w", err)
	}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/connections", p.port), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(secret)))
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("clash api: %s", resp.Status)
	}
	var body struct {
		Connections []clashConn `json:"connections"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}

	now := time.Now().Unix()
	seen := make(map[string]struct{}, len(body.Connections))

	p.mu.Lock()
	defer p.mu.Unlock()
	// Record baselines but bank no bytes on the first successful snapshot.
	priming := !p.primed
	p.primed = true
	for _, c := range body.Connections {
		user := c.Metadata.User
		if user == "" {
			user = userFromRule(c.Rule)
		}
		if user == "" {
			continue // unattributable (unnamed user); counted nowhere rather than wrongly
		}
		seen[c.ID] = struct{}{}

		prev := p.conns[c.ID]
		// A counter that went backwards means the id was reused or the
		// connection restarted; treat the current value as the whole delta.
		dUp, dDown := c.Upload, c.Download
		if c.Upload >= prev.up {
			dUp = c.Upload - prev.up
		}
		if c.Download >= prev.down {
			dDown = c.Download - prev.down
		}
		p.conns[c.ID] = struct{ up, down uint64 }{c.Upload, c.Download}

		u := p.users[user]
		if u == nil {
			u = &hy2User{}
			p.users[user] = u
		}
		if !priming {
			u.up += dUp
			u.down += dDown
		}
		// Liveness is recorded even while priming, so online state is right at once.
		u.lastSeen = now
	}
	// Forget closed connections; their final delta is already banked.
	for id := range p.conns {
		if _, ok := seen[id]; !ok {
			delete(p.conns, id)
		}
	}
	return nil
}

// userFromRule pulls NAME out of a Clash `rule` string like
// `auth_user=NAME => route(direct)`. Only used when the serializer patch is
// absent and the operator routes per user.
func userFromRule(rule string) string {
	const key = "auth_user="
	i := strings.Index(rule, key)
	if i < 0 {
		return ""
	}
	rest := rule[i+len(key):]
	if j := strings.IndexAny(rest, " \t"); j >= 0 {
		rest = rest[:j]
	}
	return strings.Trim(rest, "[]")
}

// save writes the totals as TSV — "name<TAB>up<TAB>down<TAB>lastSeen" — because
// the consumer is stats.sh, an awk script. Written via a temp file + rename so a
// reader never sees a half-written table.
func (p *hy2Poller) save() {
	// Drop users that are no longer in the registry, so a recycled NAME does not
	// inherit the previous holder's totals and "online" state — client names like
	// "phone" get reused constantly, and remove-client cannot do this itself (the
	// next flush would just write the name back out of memory).
	known, ok := p.registryNames()

	p.mu.Lock()
	var b strings.Builder
	for name, u := range p.users {
		// Only prune when the registry was actually readable: treating a transient
		// read error as "no clients exist" would wipe every total on disk.
		if ok {
			if _, live := known[name]; !live {
				delete(p.users, name)
				continue
			}
		}
		fmt.Fprintf(&b, "%s\t%d\t%d\t%d\n", name, u.up, u.down, u.lastSeen)
	}
	p.mu.Unlock()

	path := filepath.Join(p.confDir, hy2StatsFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0o600); err != nil {
		log.Printf("breach-mgmt: write %s: %v", hy2StatsFile, err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("breach-mgmt: rename %s: %v", hy2StatsFile, err)
	}
}

// registryNames reads the client registry ($CONF_DIR/clients, TSV whose first
// field is the name). The bool reports whether the read succeeded — callers must
// not treat a failure as an empty registry.
func (p *hy2Poller) registryNames() (map[string]struct{}, bool) {
	f, err := os.Open(filepath.Join(p.confDir, "clients"))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	names := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		name, _, _ := strings.Cut(sc.Text(), "\t")
		if name != "" {
			names[name] = struct{}{}
		}
	}
	if sc.Err() != nil {
		return nil, false
	}
	return names, true
}

// load restores totals written by a previous run, so restarting the container
// (or sing-box) doesn't reset every user's data use to zero.
func (p *hy2Poller) load() {
	f, err := os.Open(filepath.Join(p.confDir, hy2StatsFile))
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), "\t")
		if len(parts) != 4 || parts[0] == "" {
			continue
		}
		up, _ := strconv.ParseUint(parts[1], 10, 64)
		down, _ := strconv.ParseUint(parts[2], 10, 64)
		seen, _ := strconv.ParseInt(parts[3], 10, 64)
		p.users[parts[0]] = &hy2User{up: up, down: down, lastSeen: seen}
	}
}
