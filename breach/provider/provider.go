// Package provider is the seam between "where TURN credentials come from" and
// "what the tunnel does with them". A provider (MAX messenger, WB Chat, …) mints
// Creds; everything below Mint — turn.NewAlloc, the DTLS-SRTP disguise, the
// allocation pool, striping — is provider-agnostic and speaks only Creds. Adding
// a second messenger to breach is adding a second Minter, nothing under it.
package provider

import "time"

// Creds is a single minted TURN credential set: the currency every provider
// hands the tunnel. Its shape is the historical maxproto.Creds (kept via a type
// alias there), so on-disk cred caches round-trip unchanged.
type Creds struct {
	TurnHosts    []string // host:port list to allocate on
	Username     string
	Credential   string
	StunHosts    []string
	ExpiresAt    time.Time
	CallsUserID  int64
	Conversation string

	// JoinLink is the group-call link this credential was minted from. A provider
	// that re-joins one conference for fresh creds (MAX group calls) returns it so
	// the caller can thread it into the next Mint; providers without that notion
	// leave it empty. Persisted with the cred cache, so it survives restarts.
	JoinLink string `json:"joinLink,omitempty"`

	// Transport is the client<->relay link these hosts want: "auto" (default; udp
	// with a tcp fallback), "udp", or "tcp". It rides with the creds because WHICH
	// transport reaches a relay is a provider fact, not a caller choice — MAX
	// takes it from config, WB from how each TURN URL was advertised.
	Transport string `json:"transport,omitempty"`
}

// Minter mints one fresh TURN credential set for a single identity/account. A
// pool spreads its allocations across several Minters to scale past any one
// account's per-credential throttle ceiling.
type Minter interface {
	// Mint returns a fresh credential set. reuseLink asks a provider that supports
	// conference reuse (see Reuses) to re-join that link instead of creating a new
	// conference; providers without it ignore the argument.
	Mint(reuseLink string) (*Creds, error)

	// Reuses reports whether threading a returned Creds.JoinLink back into the
	// next Mint re-joins ONE conference (fewer calls in history, but all mints
	// share a single throttle bucket) rather than minting a fresh one each time.
	Reuses() bool

	// Name is the provider tag ("max", "wb"), for logs.
	Name() string
}
