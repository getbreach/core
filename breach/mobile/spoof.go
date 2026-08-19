package breachmobile

import (
	"encoding/json"
	"fmt"

	"breach/maxproto"
)

// BumpClientSession advances the config's clientSessionId by one and returns the
// updated config JSON. The real client increments this per-account counter on
// every use of the account, so the app must call this once before each
// StartTransport and PERSIST the result — a constant clientSessionId across
// sessions is a fingerprint that outs the client.
func BumpClientSession(configJSON string) (string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(configJSON), &m); err != nil {
		return "", fmt.Errorf("bad config JSON: %w", err)
	}
	cur := 0
	switch v := m["clientSessionId"].(type) {
	case float64:
		cur = int(v)
	case int:
		cur = v
	}
	if cur < 1 {
		cur = 1 // login used session 1; the first connect after it is 2
	}
	m["clientSessionId"] = cur + 1
	out, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// UserAgentJSON builds the full handshake userAgent from the app's COSMETIC
// device fields and returns it as JSON.
//
// It exists so the app never carries a client version of its own. deviceInfoJSON
// is a maxproto.DeviceInfo ({deviceName,osVersion,screen,timezone,locale,
// deviceLocale}) — the app reads those off the real handset; the
// fingerprint-critical half (appVersion/buildNumber/arch/deviceType/
// pushDeviceType) is filled in HERE, locked to the build whose APK digests the
// anti-spoof fingerprint uses. An empty deviceInfoJSON keeps the core default
// device; any empty field inside it keeps that field's default.
//
// StartTransport takes a whole userAgent object rather than a DeviceInfo, so
// without this the app would have to hardcode the locked fields and go stale the
// moment they move here.
func UserAgentJSON(deviceInfoJSON string) (string, error) {
	var d maxproto.DeviceInfo
	if deviceInfoJSON != "" {
		if err := json.Unmarshal([]byte(deviceInfoJSON), &d); err != nil {
			return "", fmt.Errorf("bad deviceInfo JSON: %w", err)
		}
	}
	out, err := json.Marshal(maxproto.UserAgentFor(d))
	if err != nil {
		return "", err
	}
	return string(out), nil
}
