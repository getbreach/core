//go:build mgmt

package mgmt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fakeClash serves a scripted sequence of /connections snapshots.
type fakeClash struct {
	snapshots [][]clashConn
	i         int
	gotAuth   string
}

func (f *fakeClash) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.gotAuth = r.Header.Get("Authorization")
		snap := []clashConn{}
		if f.i < len(f.snapshots) {
			snap = f.snapshots[f.i]
			f.i++
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"connections": snap})
	}
}

func conn(id, user string, up, down uint64) clashConn {
	c := clashConn{ID: id, Upload: up, Download: down}
	c.Metadata.User = user
	return c
}

// newPoller wires a poller at a temp state dir against a fake Clash API.
func newPoller(t *testing.T, f *fakeClash) (*hy2Poller, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "clash-secret"), []byte("s3cr3t\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatal(err)
	}
	return newPollerAt(dir, port), dir
}

func newPollerAt(dir string, port int) *hy2Poller {
	return &hy2Poller{
		confDir: dir,
		port:    port,
		users:   map[string]*hy2User{},
		conns:   map[string]struct{ up, down uint64 }{},
	}
}

func (p *hy2Poller) mustPoll(t *testing.T) {
	t.Helper()
	if err := p.poll(http.DefaultClient); err != nil {
		t.Fatalf("poll: %v", err)
	}
}

// The first snapshot only establishes baselines: its connections have been
// running since before this process existed, so their bytes are not ours to bank.
func TestPollerPrimesFirstSnapshot(t *testing.T) {
	f := &fakeClash{snapshots: [][]clashConn{{conn("c1", "alice", 900, 9000)}}}
	p, _ := newPoller(t, f)
	p.mustPoll(t)

	got := p.users["alice"]
	if got == nil {
		t.Fatal("alice not tracked")
	}
	if got.up != 0 || got.down != 0 {
		t.Fatalf("priming banked traffic: up=%d down=%d", got.up, got.down)
	}
	if got.lastSeen == 0 {
		t.Fatal("priming must still record liveness")
	}
}

// Counters are cumulative PER CONNECTION, so a growing connection adds only the
// delta — not its full value again on every poll.
func TestPollerAccumulatesDeltas(t *testing.T) {
	f := &fakeClash{snapshots: [][]clashConn{
		{conn("c1", "alice", 100, 1000)}, // primes
		{conn("c1", "alice", 150, 1500)}, // +50 / +500
		{conn("c1", "alice", 150, 1500)}, // idle, adds nothing
	}}
	p, _ := newPoller(t, f)
	p.mustPoll(t)
	p.mustPoll(t)
	p.mustPoll(t)

	if got := p.users["alice"]; got.up != 50 || got.down != 500 {
		t.Fatalf("want up=50 down=500, got up=%d down=%d", got.up, got.down)
	}
	if !strings.Contains(f.gotAuth, "s3cr3t") {
		t.Fatalf("secret not sent: %q", f.gotAuth)
	}
}

// A connection that appears after priming is counted in full, and its bytes stay
// banked once it closes.
func TestPollerSurvivesConnectionChurn(t *testing.T) {
	f := &fakeClash{snapshots: [][]clashConn{
		{},                             // primes on an empty snapshot
		{conn("c1", "bob", 500, 5000)}, // new connection: counted in full
		{},                             // closed
		{conn("c2", "bob", 200, 2000)}, // another one, counters start over
	}}
	p, _ := newPoller(t, f)
	for i := 0; i < 4; i++ {
		p.mustPoll(t)
	}

	if got := p.users["bob"]; got.up != 700 || got.down != 7000 {
		t.Fatalf("want up=700 down=7000, got up=%d down=%d", got.up, got.down)
	}
	if len(p.conns) != 1 {
		t.Fatalf("closed connection not forgotten: %v", p.conns)
	}
}

// Regression: breach-mgmt is restart-supervised independently of sing-box, so a
// mgmt-only restart meets connections that have been open for hours. Without
// priming, that first poll re-added each connection's whole since-open count on
// top of the totals just loaded from disk — doubling a user's usage forever.
func TestPollerNoDoubleCountAfterRestart(t *testing.T) {
	f := &fakeClash{snapshots: [][]clashConn{{conn("c1", "carol", 20_000, 40_000)}}}
	p, dir := newPoller(t, f)
	p.mustPoll(t)
	p.users["carol"].up = 20_000 // as if banked over the connection's life
	p.users["carol"].down = 40_000
	p.save()

	// Same still-open connection, same counters, brand-new process.
	f.i = 0
	revived := newPollerAt(dir, p.port)
	revived.load()
	revived.mustPoll(t)

	if got := revived.users["carol"]; got.up != 20_000 || got.down != 40_000 {
		t.Fatalf("totals inflated by the restart: up=%d down=%d (want 20000/40000)", got.up, got.down)
	}
}

// Totals must outlive the process, and the on-disk shape is load-bearing:
// stats.sh parses it with awk -F'\t'.
func TestPollerPersistsAcrossRestart(t *testing.T) {
	f := &fakeClash{snapshots: [][]clashConn{
		{},                            // primes
		{conn("c1", "carol", 42, 84)}, // counted in full
	}}
	p, dir := newPoller(t, f)
	p.mustPoll(t)
	p.mustPoll(t)
	p.save()

	raw, err := os.ReadFile(filepath.Join(dir, hy2StatsFile))
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(string(raw)), "\t")
	if len(fields) != 4 || fields[0] != "carol" || fields[1] != "42" || fields[2] != "84" {
		t.Fatalf("bad TSV line: %q", string(raw))
	}

	revived := newPollerAt(dir, p.port)
	revived.load()
	if got := revived.users["carol"]; got == nil || got.up != 42 || got.down != 84 {
		t.Fatalf("totals not restored: %+v", revived.users["carol"])
	}
}

// A recycled client NAME must not inherit the previous holder's usage, so totals
// for names no longer in the registry are dropped.
func TestPollerPrunesRemovedClients(t *testing.T) {
	f := &fakeClash{}
	p, dir := newPoller(t, f)
	p.users["alice"] = &hy2User{up: 1, down: 2, lastSeen: 3}
	p.users["ghost"] = &hy2User{up: 9, down: 9, lastSeen: 9}
	// Registry holds alice only (Hy2-only row: empty wg fields).
	if err := os.WriteFile(filepath.Join(dir, "clients"), []byte("alice\t\t\tPW\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p.save()

	if _, still := p.users["ghost"]; still {
		t.Fatal("removed client kept its totals")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, hy2StatsFile))
	if strings.Contains(string(raw), "ghost") {
		t.Fatalf("removed client written to disk: %q", raw)
	}
	if !strings.Contains(string(raw), "alice") {
		t.Fatalf("live client dropped: %q", raw)
	}
}

// An unreadable registry must NOT be read as "no clients exist" — that would
// wipe every total on a transient error.
func TestPollerKeepsTotalsWhenRegistryUnreadable(t *testing.T) {
	f := &fakeClash{}
	p, dir := newPoller(t, f)
	p.users["alice"] = &hy2User{up: 5, down: 6, lastSeen: 7}
	p.save() // no clients file exists at all

	if _, still := p.users["alice"]; !still {
		t.Fatal("totals pruned with no registry to compare against")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, hy2StatsFile))
	if !strings.Contains(string(raw), "alice") {
		t.Fatalf("totals lost: %q", raw)
	}
}

// Without the sing-box serializer patch the user arrives only inside the rule
// string; a connection we cannot attribute is dropped, never guessed.
func TestPollerUserFallbackAndUnattributable(t *testing.T) {
	withRule := clashConn{ID: "c1", Upload: 10, Download: 20, Rule: "auth_user=dave => route(direct)"}
	f := &fakeClash{snapshots: [][]clashConn{
		{},
		{withRule, conn("c2", "", 999, 999)},
	}}
	p, _ := newPoller(t, f)
	p.mustPoll(t)
	p.mustPoll(t)

	if got := p.users["dave"]; got == nil || got.up != 10 || got.down != 20 {
		t.Fatalf("rule fallback failed: %+v", p.users)
	}
	if len(p.users) != 1 {
		t.Fatalf("unattributable connection was counted: %v", p.users)
	}
}

func TestUserFromRule(t *testing.T) {
	for _, tc := range []struct{ rule, want string }{
		{"auth_user=alice => route(direct)", "alice"},
		{"auth_user=[bob] => route(u-bob)", "bob"},
		{"final", ""},
		{"inbound=hy2-in => route(direct)", ""},
	} {
		if got := userFromRule(tc.rule); got != tc.want {
			t.Errorf("userFromRule(%q) = %q, want %q", tc.rule, got, tc.want)
		}
	}
}

// A poll against a dead API fails cleanly, leaving totals untouched — and must
// not consume the priming flag, or the first real snapshot would be banked.
func TestPollerHandlesDeadAPI(t *testing.T) {
	f := &fakeClash{}
	p, _ := newPoller(t, f)
	realPort := p.port
	p.port = 1 // nothing listens
	if err := p.poll(http.DefaultClient); err == nil {
		t.Fatal("expected an error from a dead API")
	}
	if len(p.users) != 0 {
		t.Fatalf("totals mutated on failure: %v", p.users)
	}
	if p.primed {
		t.Fatal("a failed poll must not count as the priming snapshot")
	}
	p.port = realPort
}
