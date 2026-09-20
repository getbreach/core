package breachmobile

import (
	"context"
	"errors"
	"testing"
	"time"

	"breach/maxproto"
	"breach/provider"
	"breach/turn"
)

type cacheTestMinter struct{ calls int }

func (m *cacheTestMinter) Mint(string) (*provider.Creds, error) {
	m.calls++
	return &provider.Creds{Username: "test", Credential: "test", TurnHosts: []string{"localhost:3478"}, ExpiresAt: time.Now().Add(time.Hour)}, nil
}
func (*cacheTestMinter) CacheKey() string { return "test-account" }
func (*cacheTestMinter) Name() string     { return "wb" }
func (*cacheTestMinter) Reuses() bool     { return false }

func TestMintSurvivesCancelledPoolBuild(t *testing.T) {
	dir := t.TempDir()
	minter := &cacheTestMinter{}
	for attempt := 0; attempt < 2; attempt++ {
		c := newCoreWB([]provider.Minter{minter}, nil, 1, 3, 50, "udp", dir)
		c.openAllocation = func(cr *maxproto.Creds, _ int) (*stream, error) {
			if len(maxproto.LoadCachedCreds(dir, minter.CacheKey())) != 1 {
				t.Error("mint was not saved before allocation")
			}
			c.cancel()
			return nil, context.Canceled
		}
		c.buildPool(false)
		c.cancel()
	}
	if minter.calls != 1 {
		t.Fatalf("restart minted %d times, want 1", minter.calls)
	}
}

func TestUnusedCredentialsPersistAndRejectedStayRemoved(t *testing.T) {
	dir := t.TempDir()
	c := newCore(&maxproto.Config{Mints: 1, Streams: 1}, nil)
	defer c.cancel()
	var list []*maxproto.Creds
	for i := 0; i < 3; i++ {
		list = append(list, &maxproto.Creds{Credential: "test", TurnHosts: []string{"localhost:3478"}, ExpiresAt: time.Now().Add(time.Hour)})
	}
	c.rememberCreds(dir, "account", list)
	if got := c.cachedCreds(dir, "account"); len(got) != 3 || got[0] != list[0] {
		t.Fatal("unused credentials or live pointer lost")
	}
	restart := newCore(&maxproto.Config{}, nil)
	defer restart.cancel()
	if len(restart.cachedCreds(dir, "account")) != 3 {
		t.Fatal("unused credentials lost on restart")
	}
	c.rememberCreds(dir, "account", nil)
	if len(c.cachedCreds(dir, "account")) != 0 || len(maxproto.LoadCachedCreds(dir, "account")) != 0 {
		t.Fatal("rejected cache resurrected")
	}
}

func TestRestartMintsOnlyMissingCredentials(t *testing.T) {
	dir := t.TempDir()
	minter := &cacheTestMinter{}
	for _, count := range []int{3, 1, 4, 3} {
		c := newCoreWB([]provider.Minter{minter}, nil, 1, count, 50, "udp", dir)
		// Network failure must not discard valid credentials or mint extras.
		c.openAllocation = func(*maxproto.Creds, int) (*stream, error) {
			return nil, errors.New("offline")
		}
		c.buildPool(false)
		c.cancel()
		want := 3
		if count == 4 || minter.calls == 4 {
			want = 4
		}
		if minter.calls != want {
			t.Fatalf("requested %d: total mints %d, want %d", count, minter.calls, want)
		}
	}
}

func TestCacheReplacesOnlySpentCredential(t *testing.T) {
	dir := t.TempDir()
	minter := &cacheTestMinter{}
	c := newCoreWB([]provider.Minter{minter}, nil, 1, 2, 50, "udp", dir)
	defer c.cancel()
	good := &maxproto.Creds{Credential: "good", TurnHosts: []string{"localhost:3478"}, ExpiresAt: time.Now().Add(time.Hour)}
	spent := *good
	spent.Credential = "spent"
	c.rememberCreds(dir, minter.CacheKey(), []*maxproto.Creds{good, &spent})
	c.openAllocation = func(cr *maxproto.Creds, _ int) (*stream, error) {
		if cr.Credential == "spent" {
			return nil, &turn.ResponseError{Operation: "allocate", Code: 486}
		}
		return nil, errors.New("temporary network failure")
	}
	c.buildPool(false)
	if minter.calls != 1 {
		t.Fatalf("replaced %d credentials, want 1", minter.calls)
	}
	if got := c.cachedCreds(dir, minter.CacheKey()); len(got) != 2 || got[0] != good {
		t.Fatal("unaffected credential was replaced")
	}
	for _, cr := range maxproto.LoadCachedCreds(dir, minter.CacheKey()) {
		if cr.Credential == "spent" {
			t.Fatal("spent credential left on disk")
		}
	}
}
