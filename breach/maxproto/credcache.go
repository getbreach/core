package maxproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// credCacheMargin: only reuse a cached credential if it still has at least this
// much life left, so a reused cred comfortably outlasts (re)connect setup. The
// remint loop refreshes a live pool well before expiry anyway.
const credCacheMargin = 30 * time.Minute

func credCacheFile(dir, token string) string {
	sum := sha256.Sum256([]byte(token))
	return filepath.Join(dir, "creds_"+hex.EncodeToString(sum[:8])+".json")
}

// LoadCachedCreds returns the still-valid cached TURN credentials for an account
// (keyed by token), or nil. Lets a reconnect within the ~8h cred TTL skip the
// mint (the MAX group-call/conference), so we don't ring/conference every time.
func LoadCachedCreds(dir, token string) []*Creds {
	if dir == "" || token == "" {
		return nil
	}
	data, err := os.ReadFile(credCacheFile(dir, token))
	if err != nil {
		return nil
	}
	var list []*Creds
	if json.Unmarshal(data, &list) != nil {
		return nil
	}
	out := make([]*Creds, 0, len(list))
	for _, c := range list {
		if c != nil && c.Credential != "" && len(c.TurnHosts) > 0 && time.Until(c.ExpiresAt) >= credCacheMargin {
			out = append(out, c)
		}
	}
	return out
}

// SaveCachedCreds persists an account's minted credentials for reuse on the next
// connect. Stored in the app's private dir; the filename is a hash of the token.
func SaveCachedCreds(dir, token string, list []*Creds) {
	if dir == "" || token == "" || len(list) == 0 {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	if data, err := json.Marshal(list); err == nil {
		_ = os.WriteFile(credCacheFile(dir, token), data, 0o600)
	}
}
