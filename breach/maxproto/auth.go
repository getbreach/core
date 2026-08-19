package maxproto

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// Phone-number authentication, ported from kolibri (examples/auth_request.rs and
// kolibri-py/examples/call_bot.py). Four steps against the same socket:
//
//	 6  sessionInit  -> callsSeed
//	17  authRequest  {phone, type: START_AUTH, mode: fingerprint} -> temp token
//	18  auth         {token, verifyCode, authTokenType: CHECK_CODE} -> LOGIN token
//	19  login        {token, ...} -> online
//
// Only step 19 was implemented before, and only with a token obtained
// elsewhere. The LOGIN token from step 18 is long-lived: mint it once, then the
// tunnel keeps re-minting TURN credentials with it on its own.

// DefaultHost is the MAX API endpoint. Its certificate chain terminates in the
// Минцифры root rather than a publicly trusted CA, so reaching it depends on
// the anchors bundled in mincifry.go.
const DefaultHost = "api2.oneme.ru"

// Calls-SDK identity sent in internalParams on every mint, extracted from
// ru.oneme.app 26.23.2 (ru.ok.android.externcalls.sdk):
//
//	DefaultSdkVersion   = ConversationFactory.SDK_VERSION
//	DefaultClientAppKey = the literal in the InternalParamsDto builder (s68)
//	DefaultCapabilities = hexCapability, the bitmask the current client sends
//	                      (0x3c02f; matches Komet's live reimplementation)
const (
	DefaultSdkVersion   = "0.2.1.3"
	DefaultClientAppKey = "CGPGAGLGDIHBABABA"
	DefaultCapabilities = "3c02f"
)

const (
	opSessionInit        = 6
	opAuthRequest        = 17
	opAuth               = 18
	opLogin              = 19
	opAuthLoginCheckPass = 115
)

// Identity is a device identity in the real client's format: deviceId is 16 hex
// characters (an Android ID), instanceId a UUID. MAX ties the LOGIN token to
// these, so they must be stored alongside the token and reused verbatim — a new
// identity means a new SMS.
type Identity struct {
	DeviceID   string `json:"deviceId"`
	InstanceID string `json:"instanceId"`
}

// NewIdentity generates a fresh install identity.
func NewIdentity() (Identity, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return Identity{}, fmt.Errorf("device id: %w", err)
	}
	return Identity{DeviceID: hex.EncodeToString(b[:]), InstanceID: uuidV4()}, nil
}

// Profile is who the LOGIN token belongs to, as returned by step 18.
type Profile struct {
	UserID int64  `json:"userId"`
	Phone  string `json:"phone"`
	Name   string `json:"name"`
}

// SessionInit performs the opcode 6 handshake and returns the server's
// callsSeed, which every fingerprint in this session is bound to.
func SessionInit(c *Client, cfg *Config) (int64, error) {
	pkt, err := c.Request(opSessionInit, map[string]any{
		"mt_instanceid":   cfg.InstanceID,
		"userAgent":       cfg.UserAgent.toMap(),
		"clientSessionId": cfg.ClientSessionID,
		"deviceId":        cfg.DeviceID,
	})
	if err != nil {
		return 0, fmt.Errorf("sessionInit: %w", err)
	}
	m, _ := pkt.Payload.(map[string]any)
	return toInt64(m["callsSeed"]), nil
}

// AuthRequest asks MAX to send an SMS code to phone and returns the temporary
// token that AuthVerify consumes. The `mode` field is the anti-spoof
// fingerprint and is mandatory here — unlike in login, MAX rejects the request
// without it.
func AuthRequest(c *Client, cfg *Config, callsSeed int64, phone string) (string, error) {
	phone = NormalizePhone(phone)
	if len(phone) < 6 {
		return "", fmt.Errorf("phone %q looks too short", phone)
	}
	language := cfg.UserAgent.Locale
	if language == "" {
		language = "ru"
	}
	pkt, err := c.Request(opAuthRequest, map[string]any{
		"phone":    phone,
		"type":     "START_AUTH",
		"language": language,
		"mode":     fingerprintFor(cfg, callsSeed),
	})
	if err != nil {
		return "", fmt.Errorf("authRequest: %w", err)
	}
	m, _ := pkt.Payload.(map[string]any)
	token, _ := m["token"].(string)
	if token == "" {
		return "", fmt.Errorf("authRequest: no token in response")
	}
	return token, nil
}

// VerifyResult is the outcome of the SMS-code step (opcode 18). MAX answers in
// one of two shapes: the account is in, or it has 2FA and wants a password next.
// (A brand-new number would instead carry a REGISTER token; we do not create
// accounts, so that path is reported as an error by AuthVerify.)
type VerifyResult struct {
	// Token is the long-lived LOGIN token when the account logged straight in.
	// Empty when PasswordRequired is set.
	Token   string
	Profile *Profile

	// PasswordRequired is set when the account has a 2FA password. TrackID
	// threads that challenge into CheckPassword; Hint is the user's password
	// hint, if they set one.
	PasswordRequired bool
	TrackID          string
	Hint             string
}

// AuthVerify submits the SMS code (opcode 18). On success it either returns the
// LOGIN token, or signals that a 2FA password is required — see VerifyResult.
func AuthVerify(c *Client, tempToken, code string) (*VerifyResult, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, fmt.Errorf("empty verification code")
	}
	pkt, err := c.Request(opAuth, map[string]any{
		"token":         tempToken,
		"verifyCode":    code,
		"authTokenType": "CHECK_CODE",
	})
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	m, _ := pkt.Payload.(map[string]any)

	// A 2FA account comes back with a passwordChallenge instead of a token.
	if ch := dig(m, "passwordChallenge"); ch != nil {
		trackID, _ := ch["trackId"].(string)
		if trackID == "" {
			return nil, fmt.Errorf("auth: passwordChallenge without a trackId")
		}
		hint, _ := ch["hint"].(string)
		return &VerifyResult{PasswordRequired: true, TrackID: trackID, Hint: hint}, nil
	}

	token, _ := dig(m, "tokenAttrs", "LOGIN")["token"].(string)
	if token == "" {
		// No LOGIN token and no challenge: either a wrong code, or a REGISTER
		// token for a number with no account (which we do not create).
		if dig(m, "tokenAttrs", "REGISTER")["token"] != nil {
			return nil, fmt.Errorf("auth: this number has no MAX account (registration is not supported)")
		}
		return nil, fmt.Errorf("auth: no LOGIN token in response (wrong code?)")
	}
	return &VerifyResult{Token: token, Profile: parseProfile(m)}, nil
}

// CheckPassword submits the 2FA password for the challenge from AuthVerify
// (opcode 115) and returns the LOGIN token. The password crosses in cleartext
// inside the encrypted transport — MAX does no client-side hashing — so it is
// never logged and the caller should hold it no longer than necessary.
func CheckPassword(c *Client, trackID, password string) (*VerifyResult, error) {
	if trackID == "" {
		return nil, fmt.Errorf("checkPassword: empty trackId")
	}
	if password == "" {
		return nil, fmt.Errorf("checkPassword: empty password")
	}
	pkt, err := c.Request(opAuthLoginCheckPass, map[string]any{
		"trackId":  trackID,
		"password": password,
	})
	if err != nil {
		return nil, fmt.Errorf("checkPassword: %w", err)
	}
	m, _ := pkt.Payload.(map[string]any)

	// A wrong password is reported in-band: the packet is OK but carries error.
	if m["error"] != nil {
		return nil, fmt.Errorf("checkPassword: wrong password")
	}
	token, _ := dig(m, "tokenAttrs", "LOGIN")["token"].(string)
	if token == "" {
		return nil, fmt.Errorf("checkPassword: no LOGIN token in response")
	}
	return &VerifyResult{Token: token, Profile: parseProfile(m)}, nil
}

// parseProfile pulls the account identity out of a login/verify response.
func parseProfile(m map[string]any) *Profile {
	p := &Profile{UserID: extractAccountID(m)}
	if contact := dig(m, "profile", "contact"); contact != nil {
		if p.UserID == 0 {
			p.UserID = toInt64(contact["id"])
		}
		p.Phone, _ = contact["phone"].(string)
		if names, ok := contact["names"].([]any); ok && len(names) > 0 {
			if first, ok := names[0].(map[string]any); ok {
				p.Name, _ = first["name"].(string)
			}
		}
	}
	return p
}

// extractAccountID probes the response for the account id the way the real
// client does (Komet account_models.dart extractAccountId): several nests, in
// order, first non-zero wins.
func extractAccountID(m map[string]any) int64 {
	for _, path := range [][]string{
		{"profile", "contact", "id"},
		{"profile", "contact", "contactId"},
		{"profile", "contact", "accountId"},
		{"profile", "id"},
		{"profile", "accountId"},
		{"contact", "id"},
		{"contact", "contactId"},
		{"account", "id"},
		{"account", "accountId"},
	} {
		parent := dig(m, path[:len(path)-1]...)
		if parent == nil {
			continue
		}
		if id := toInt64(parent[path[len(path)-1]]); id != 0 {
			return id
		}
	}
	// Flat fallbacks.
	for _, k := range []string{"accountId", "account_id"} {
		if id := toInt64(m[k]); id != 0 {
			return id
		}
	}
	return 0
}

// Login performs the opcode 19 token login. callsSeed comes from SessionInit.
//
// It sends chatCacheFingerprint by default — the real client always does, and a
// live run confirmed MAX accepts our bytes. It is skipped only when it would be
// wrong or useless: callsSeed 0 (nothing to bind to), the config opted out, or
// the announced appVersion is not in the digest table (fingerprintFor would then
// fall back to a different build, and a fingerprint contradicting the announced
// version is worse than none).
func Login(c *Client, cfg *Config, callsSeed int64) error {
	payload := map[string]any{
		"token":        cfg.Token,
		"interactive":  false,
		"exp":          map[string]any{"chatsCountGroups": []byte{0x0b, 0x32}},
		"presenceSync": -1,
		"chatsSync":    -1,
	}
	if cfg.sendFingerprint(callsSeed) {
		payload["chatCacheFingerprint"] = fingerprintFor(cfg, callsSeed)
	}
	if _, err := c.Request(opLogin, payload); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	return nil
}

// sendFingerprint decides whether Login attaches chatCacheFingerprint: yes by
// default, unless disabled, seedless, or built for a version we lack digests for.
func (cfg *Config) sendFingerprint(callsSeed int64) bool {
	if cfg.DisableFingerprint || callsSeed == 0 {
		return false
	}
	arch := cfg.UserAgent.Arch
	if arch == "" {
		arch = DefaultArch
	}
	_, known := DigestsFor(cfg.UserAgent.AppVersion, arch)
	return known
}

// LoginByPhone runs the whole SMS flow on a fresh connection and returns a
// LOGIN token for cfg's identity. askCode is called once the SMS is on its way;
// askPassword is called only when the account has 2FA, with the password hint
// (empty if none). Pass a nil askPassword to fail fast on 2FA accounts.
func LoginByPhone(cfg *Config, phone string, askCode func() (string, error), askPassword func(hint string) (string, error)) (string, *Profile, error) {
	c, err := Dial(cfg.Host, cfg.Port)
	if err != nil {
		return "", nil, err
	}
	defer c.Close()

	callsSeed, err := SessionInit(c, cfg)
	if err != nil {
		return "", nil, err
	}
	if callsSeed == 0 {
		return "", nil, fmt.Errorf("sessionInit returned no callsSeed; cannot build the auth fingerprint")
	}

	tempToken, err := AuthRequest(c, cfg, callsSeed, phone)
	if err != nil {
		return "", nil, err
	}

	code, err := askCode()
	if err != nil {
		return "", nil, err
	}
	res, err := AuthVerify(c, tempToken, code)
	if err != nil {
		return "", nil, err
	}

	if res.PasswordRequired {
		if askPassword == nil {
			return "", nil, fmt.Errorf("account has 2FA but no password prompt was provided")
		}
		password, err := askPassword(res.Hint)
		if err != nil {
			return "", nil, err
		}
		res, err = CheckPassword(c, res.TrackID, password)
		if err != nil {
			return "", nil, err
		}
	}
	return res.Token, res.Profile, nil
}

// NormalizePhone reduces any input to "+<digits>", the form MAX expects.
func NormalizePhone(phone string) string {
	var b strings.Builder
	b.WriteByte('+')
	for _, r := range phone {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// MaskPhone renders a number for logs without printing it in full.
func MaskPhone(phone string) string {
	if len(phone) <= 5 {
		return "***"
	}
	return phone[:3] + "***" + phone[len(phone)-2:]
}

// dig walks nested maps, returning nil if any step is missing or not a map.
func dig(m map[string]any, path ...string) map[string]any {
	for _, k := range path {
		if m == nil {
			return nil
		}
		next, _ := m[k].(map[string]any)
		m = next
	}
	return m
}

// DefaultUserAgent is the handshake identity used when a config does not supply
// one. appVersion / buildNumber / arch are not free-form: the anti-spoof
// fingerprint is derived from the digests of that exact build and ABI, so these
// three must stay in step with the apkBuilds table in fingerprint.go.
func DefaultUserAgent() UserAgent {
	return UserAgent{
		DeviceType:   "ANDROID",
		AppVersion:   DefaultAppVersion,
		OsVersion:    "Android 14",
		Timezone:     "Europe/Moscow",
		Screen:       "420dpi 420dpi 1080x2340",
		PushType:     "GCM",
		Arch:         DefaultArch,
		Locale:       "ru",
		BuildNumber:  DefaultBuildNumber,
		DeviceName:   "Xiaomi 23127PN0CG",
		DeviceLocale: "ru",
	}
}

// NewAuthConfig builds a config good enough to authenticate with: defaults plus
// a fresh device identity. Unlike ParseConfig it does not demand a token —
// obtaining one is the point. Pass an existing identity to re-authenticate the
// same device (a new one means MAX treats it as a new install).
func NewAuthConfig(host string, id *Identity) (*Config, error) {
	if host == "" {
		host = DefaultHost
	}
	if id == nil {
		fresh, err := NewIdentity()
		if err != nil {
			return nil, err
		}
		id = &fresh
	}
	return &Config{
		Host:            host,
		Port:            443,
		DeviceID:        id.DeviceID,
		InstanceID:      id.InstanceID,
		ClientSessionID: 1,
		UserAgent:       DefaultUserAgent(),
		SdkVersion:      "0.1.16.4",
		ClientAppKey:    "CGPGAGLGDIHBABABA",
		Capabilities:    "3c03f",
		MintMode:        "silent",
	}, nil
}
