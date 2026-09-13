package wbproto

import "testing"

// The credential cache is keyed by CacheKey, and callee is EMPTY until the first
// mint resolves it. Deriving the key from the live callee field would therefore
// change it mid-session: everything written before the first mint would be
// orphaned, and every reconnect would mint again — placing another real call in
// the user's chat, which is the whole thing the cache exists to avoid.
func TestCacheKeyDoesNotMoveWhenCalleeResolves(t *testing.T) {
	m := &Minter{chat: "chats/42", cacheKey: "wb|/data/wb-session.json|chats/42|"}
	before := m.CacheKey()

	m.callee = "9001" // what resolveCallee assigns on the first mint

	if got := m.CacheKey(); got != before {
		t.Fatalf("cache key changed once callee resolved: %q -> %q", before, got)
	}
}

// Two sessions on one device must not read each other's credentials, and one
// session pointed at two chats mints from different peers.
func TestCacheKeysAreDistinctPerSessionAndChat(t *testing.T) {
	key := func(session, chat, callee string) string {
		return (&Minter{cacheKey: "wb|" + session + "|" + chat + "|" + callee}).CacheKey()
	}
	seen := map[string]string{}
	for _, c := range []struct{ name, session, chat, callee string }{
		{"a", "/a.json", "chats/1", ""},
		{"b", "/b.json", "chats/1", ""},
		{"c", "/a.json", "chats/2", ""},
		{"d", "/a.json", "", "9001"},
	} {
		k := key(c.session, c.chat, c.callee)
		if prev, dup := seen[k]; dup {
			t.Fatalf("%s and %s share cache key %q", prev, c.name, k)
		}
		seen[k] = c.name
	}
}
