package breachmobile

import (
	"encoding/json"
	"fmt"

	"breach/maxproto"
)

// LoginAsker is implemented by the app: the transport calls these on a
// background goroutine and BLOCKS until the UI supplies the value, so both
// methods must block until the user has entered the SMS code / 2FA password.
type LoginAsker interface {
	AskCode() (string, error)
	AskPassword(hint string) (string, error)
}

// LoginResult is what a successful phone login produces. ConfigJSON is the
// identity block (host/port/token/deviceId/instanceId/clientSessionId/userAgent/
// mintMode/sdkVersion/clientAppKey/capabilities) ready to be merged into the
// app's saved config; the exit server + tunnel settings are added by the app.
type LoginResult struct {
	ConfigJSON string
	Token      string
	DeviceID   string
	InstanceID string
	Name       string
	Phone      string
	UserID     int64
}

// LoginByPhone runs the full MAX phone-auth flow (sessionInit → authRequest →
// SMS verify → optional 2FA) against `host` (empty = default) for `phone`, with
// a FRESH generated device identity. On success the LOGIN token is bound to that
// identity, so they are returned together inside ConfigJSON.
func LoginByPhone(host string, phone string, identityJSON string, deviceInfoJSON string, asker LoginAsker) (*LoginResult, error) {
	if asker == nil {
		return nil, fmt.Errorf("no LoginAsker provided")
	}
	// Reuse a saved identity on re-login so the account keeps ONE device
	// (a fresh deviceId every login looks like a new install each time). Empty
	// identityJSON generates a fresh one.
	var id *maxproto.Identity
	if identityJSON != "" {
		var parsed maxproto.Identity
		if err := json.Unmarshal([]byte(identityJSON), &parsed); err != nil {
			return nil, fmt.Errorf("bad identity JSON: %w", err)
		}
		if parsed.DeviceID != "" {
			id = &parsed
		}
	}
	cfg, err := maxproto.NewAuthConfig(host, id)
	if err != nil {
		return nil, err
	}
	// Spoof only the cosmetic device fields; appVersion/buildNumber/arch stay
	// locked to the build the fingerprint digests belong to, so the fingerprint
	// can never contradict the announced device.
	switch {
	case deviceInfoJSON != "":
		var d maxproto.DeviceInfo
		if err := json.Unmarshal([]byte(deviceInfoJSON), &d); err != nil {
			return nil, fmt.Errorf("bad deviceInfo JSON: %w", err)
		}
		cfg.UserAgent = maxproto.UserAgentFor(d)
	case id == nil:
		// Fresh install, no device chosen -> random, so installs aren't identical.
		cfg.UserAgent = maxproto.RandomDeviceUserAgent()
	default:
		// Re-login on an existing identity with no device given: keep the stable
		// default rather than randomizing (a device that changes under a fixed
		// deviceId is suspicious). Pass the saved device to keep full fidelity.
	}

	token, profile, err := maxproto.LoginByPhone(cfg, maxproto.NormalizePhone(phone),
		func() (string, error) { return asker.AskCode() },
		func(hint string) (string, error) { return asker.AskPassword(hint) },
	)
	if err != nil {
		return nil, err
	}
	cfg.Token = token

	block := map[string]any{
		"host":            cfg.Host,
		"port":            cfg.Port,
		"token":           cfg.Token,
		"deviceId":        cfg.DeviceID,
		"instanceId":      cfg.InstanceID,
		"clientSessionId": cfg.ClientSessionID,
		"userAgent":       cfg.UserAgent,
		"mintMode":        cfg.MintMode,
		"sdkVersion":      cfg.SdkVersion,
		"clientAppKey":    cfg.ClientAppKey,
		"capabilities":    cfg.Capabilities,
	}
	blockJSON, err := json.Marshal(block)
	if err != nil {
		return nil, err
	}

	res := &LoginResult{
		ConfigJSON: string(blockJSON),
		Token:      cfg.Token,
		DeviceID:   cfg.DeviceID,
		InstanceID: cfg.InstanceID,
	}
	if profile != nil {
		res.Name = profile.Name
		res.Phone = profile.Phone
		res.UserID = profile.UserID
	}
	return res, nil
}
