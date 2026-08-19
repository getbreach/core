package maxproto

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// StoredSession is everything needed to re-login by token without another SMS.
// The token alone is not enough: MAX binds it to the handshake identity
// (deviceId/instanceId) and the fingerprint is recomputed from deviceId on every
// login, so the identity travels WITH the token. The minting knobs are kept too
// so a restored session mints exactly as the original did.
type StoredSession struct {
	Token     string    `json:"token"`
	AccountID int64     `json:"accountId"`
	Phone     string    `json:"phone,omitempty"`
	Name      string    `json:"name,omitempty"`
	Identity  Identity  `json:"identity"`
	UserAgent UserAgent `json:"userAgent"`

	SdkVersion   string `json:"sdkVersion,omitempty"`
	ClientAppKey string `json:"clientAppKey,omitempty"`
	Capabilities string `json:"capabilities,omitempty"`

	SavedAt time.Time `json:"savedAt"`
}

// SessionFromConfig snapshots the minting-relevant parts of a config plus the
// token/account into a StoredSession.
func SessionFromConfig(cfg *Config, accountID int64, profile *Profile) *StoredSession {
	s := &StoredSession{
		Token:        cfg.Token,
		AccountID:    accountID,
		Identity:     Identity{DeviceID: cfg.DeviceID, InstanceID: cfg.InstanceID},
		UserAgent:    cfg.UserAgent,
		SdkVersion:   cfg.SdkVersion,
		ClientAppKey: cfg.ClientAppKey,
		Capabilities: cfg.Capabilities,
	}
	if profile != nil {
		if s.AccountID == 0 {
			s.AccountID = profile.UserID
		}
		s.Phone, s.Name = profile.Phone, profile.Name
	}
	return s
}

// Config rebuilds a mint-ready *Config from a stored session. host defaults to
// DefaultHost. The result still needs Server/WGListen/Streams/Mints for the
// tunnel; this only restores the MAX identity.
func (s *StoredSession) Config(host string) *Config {
	if host == "" {
		host = DefaultHost
	}
	return &Config{
		Host:            host,
		Port:            443,
		Token:           s.Token,
		DeviceID:        s.Identity.DeviceID,
		InstanceID:      s.Identity.InstanceID,
		ClientSessionID: 1,
		UserAgent:       s.UserAgent,
		SdkVersion:      s.SdkVersion,
		ClientAppKey:    s.ClientAppKey,
		Capabilities:    s.Capabilities,
		MintMode:        "silent",
	}
}

// SaveSession writes a session to path (0600, parent dir 0700). The file holds a
// long-lived credential, so callers should keep it in the app's private dir.
func SaveSession(path string, s *StoredSession) error {
	if path == "" {
		return fmt.Errorf("SaveSession: empty path")
	}
	if s == nil || s.Token == "" {
		return fmt.Errorf("SaveSession: nothing to save")
	}
	if s.SavedAt.IsZero() {
		s.SavedAt = time.Now()
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("SaveSession: %w", err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// Write-then-rename so a crash mid-write never truncates a good session.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("SaveSession: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("SaveSession: %w", err)
	}
	return nil
}

// LoadSession reads a session written by SaveSession. A missing file returns
// (nil, nil) — no session yet is not an error. A present-but-tokenless file is,
// since it cannot be used to log in.
func LoadSession(path string) (*StoredSession, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var s StoredSession
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("LoadSession: %s: %w", path, err)
	}
	if s.Token == "" || s.Identity.DeviceID == "" {
		return nil, fmt.Errorf("LoadSession: %s has no token/identity", path)
	}
	return &s, nil
}
