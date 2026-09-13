package maxproto

import "breach/provider"

// mintMinter adapts one account Config to provider.Minter. Everything MAX-
// specific (opcode 166 group-call minting, fingerprint, session) stays behind
// MintFrom; the pool above only ever sees provider.Minter.
type mintMinter struct{ cfg *Config }

func (m mintMinter) Mint(reuseLink string) (*provider.Creds, error) {
	c, err := MintFrom(m.cfg, reuseLink)
	if err != nil {
		return nil, err
	}
	// The client<->MAX-TURN transport is a config choice for MAX (all its relays
	// speak both); carry it on the creds so the pool stays provider-agnostic.
	if c.Transport == "" {
		c.Transport = m.cfg.TurnTransport
	}
	return c, nil
}

func (m mintMinter) Reuses() bool { return m.cfg.ReuseGroupCall }
func (m mintMinter) Name() string { return "max" }

// CacheKey is the account token — the same key LoadCachedCreds/SaveCachedCreds
// have always used, so existing cache files stay readable.
func (m mintMinter) CacheKey() string { return m.cfg.Token }

// Minters returns one provider.Minter per account to mint from (the MintAccounts
// fan-out that scales throughput past a single account's throttle ceiling).
func (c *Config) Minters() []provider.Minter {
	accs := c.MintAccounts()
	out := make([]provider.Minter, len(accs))
	for i, a := range accs {
		out[i] = mintMinter{cfg: a}
	}
	return out
}
