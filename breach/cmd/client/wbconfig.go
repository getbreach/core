package main

import (
	"encoding/json"
	"os"
)

// wbConfig is the on-disk config for a provider=wb run. It mirrors the shape the
// Android wrapper already parses (mobile.startWB), so one JSON file works for
// both the CLI and the app: tunnel settings plus where the WB session and callee
// come from. The setup wizard writes it; main loads it when the WB flags are
// absent, so a bare `breach-client` run works from config alone.
type wbConfig struct {
	Provider    string `json:"provider"` // "wb" — how a bare run knows which branch to take
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

	// Stream (SOCKS5) mode — same meaning as the MAX config's socks fields.
	Socks      string `json:"socks,omitempty"`
	SocksToken string `json:"socksToken,omitempty"`
	SocksPin   string `json:"socksPin,omitempty"`
	SocksUser  string `json:"socksUser,omitempty"`
	SocksPass  string `json:"socksPass,omitempty"`
}

// loadWBConfig reads a WB config from path, or returns a zero value if the file
// is absent (flags then supply everything, as before).
func loadWBConfig(path string) (wbConfig, error) {
	var c wbConfig
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c, nil
		}
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// firstNonEmpty returns a if it is non-empty, else b. Used to let an explicit
// flag override a config value.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// detectProvider peeks the "provider" field of a config file so a bare run
// (no -provider flag) can pick the right branch. Returns "" when the file is
// absent or names no provider (legacy MAX configs have no such field).
func detectProvider(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var p struct {
		Provider string `json:"provider"`
	}
	json.Unmarshal(data, &p)
	return p.Provider
}
