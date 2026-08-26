package wbproto

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"breach/provider"
)

// Minter mints WB Chat TURN credentials for one WBID session and chat/callee.
// InitiateCall harvests the ICE servers, then the call is cancelled immediately
// — the TURN credentials stay valid (their expiry lives in the TURN username's
// timestamp prefix). It implements provider.Minter, so the breach pool drives a
// WB relay through the exact same DTLS-SRTP path it drives MAX through.
type Minter struct {
	api       *Client
	chat      string
	callType  string // "AUDIO" (default) or "VIDEO"
	transport string // client<->relay leg: auto|udp|tcp -> stamped on Creds

	mu     sync.Mutex
	callee string // resolved peer userID, cached after the first mint
}

// NewMinter loads a WBID session and prepares a minter. Provide either callee
// (a peer userID) or chat (a "chats/<id>" personal chat to resolve the peer
// from); callType defaults to AUDIO, transport to auto.
func NewMinter(sessionPath, chat, callee, callType, transport string) (*Minter, error) {
	api, err := Load(sessionPath)
	if err != nil {
		return nil, err
	}
	if callType == "" {
		callType = "AUDIO"
	}
	if transport == "" {
		transport = "auto"
	}
	if chat == "" && callee == "" {
		return nil, errors.New("wbproto: need a chat or a callee to mint from")
	}
	return &Minter{api: api, chat: chat, callee: callee, callType: callType, transport: transport}, nil
}

// Mint starts and immediately cancels one WB call, returning its TURN creds.
// reuseLink is ignored: WB has no group-call reuse (each call is a fresh mint).
func (m *Minter) Mint(_ string) (*provider.Creds, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	callee, err := m.resolveCallee(ctx)
	if err != nil {
		return nil, err
	}

	call, err := m.api.InitiateCall(ctx, callee, m.callType, m.chat)
	if err != nil {
		return nil, err
	}
	servers := call.TURNCredentials()
	// Cancel right away; harvested creds outlive the call. Report a cancel error
	// but don't fail the mint on it — the creds we already hold are what matter.
	if _, cerr := m.api.CancelCall(ctx, call.CallID, "1"); cerr != nil {
		return nil, fmt.Errorf("cancel mint call %s: %w", call.CallID, cerr)
	}
	if len(servers) == 0 {
		return nil, errors.New("wbproto: mint response has no authenticated TURN endpoints")
	}

	// breach's Creds carries ONE username/credential for a set of hosts, and the
	// data path is udp to the relay. All of a call's authenticated TURN URLs share
	// one credential pair, so key off the first and gather its udp hosts (falling
	// back to every host if none advertised udp), de-duplicating addresses.
	user, cred := servers[0].Username, servers[0].Credential
	var udp, all []string
	seen := map[string]bool{}
	for _, s := range servers {
		if s.Username != user || s.Credential != cred {
			continue
		}
		if !seen[s.Address] {
			seen[s.Address] = true
			all = append(all, s.Address)
		}
		if s.Transport == "udp" {
			udp = append(udp, s.Address)
		}
	}
	hosts := udp
	if len(hosts) == 0 {
		hosts = all
	}

	return &provider.Creds{
		TurnHosts:  hosts,
		Username:   user,
		Credential: cred,
		ExpiresAt:  CredentialsExpiry(servers),
		Transport:  m.transport,
	}, nil
}

func (m *Minter) resolveCallee(ctx context.Context) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.callee != "" {
		return m.callee, nil
	}
	callee, err := m.api.ResolvePeer(ctx, m.chat)
	if err != nil {
		return "", err
	}
	m.callee = callee
	return callee, nil
}

// Reuses is always false: WB mints a fresh call each time.
func (m *Minter) Reuses() bool { return false }

// Name tags this provider in logs.
func (m *Minter) Name() string { return "wb" }
