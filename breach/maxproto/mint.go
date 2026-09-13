package maxproto

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"breach/provider"
)

type UserAgent struct {
	DeviceType   string `json:"deviceType"`
	AppVersion   string `json:"appVersion"`
	OsVersion    string `json:"osVersion"`
	Timezone     string `json:"timezone"`
	Screen       string `json:"screen"`
	PushType     string `json:"pushDeviceType"`
	Arch         string `json:"arch"`
	Locale       string `json:"locale"`
	BuildNumber  int    `json:"buildNumber"`
	DeviceName   string `json:"deviceName"`
	DeviceLocale string `json:"deviceLocale"`
}

func (u UserAgent) toMap() map[string]any {
	return map[string]any{
		"deviceType": u.DeviceType, "appVersion": u.AppVersion, "osVersion": u.OsVersion,
		"timezone": u.Timezone, "screen": u.Screen, "pushDeviceType": u.PushType,
		"arch": u.Arch, "locale": u.Locale, "buildNumber": u.BuildNumber,
		"deviceName": u.DeviceName, "deviceLocale": u.DeviceLocale,
	}
}

// Account is one MAX identity used to mint TURN credentials. Spreading the
// allocation pool across SEVERAL accounts is the way past MAX's per-account/IP
// throttle ceiling (each account has its own ceiling), so total bandwidth scales
// ~linearly with the number of accounts.
type Account struct {
	Token           string    `json:"token"`
	DeviceID        string    `json:"deviceId"`
	InstanceID      string    `json:"instanceId"`
	ClientSessionID int       `json:"clientSessionId"`
	UserAgent       UserAgent `json:"userAgent"`
	MintMode        string    `json:"mintMode"`
	CalleeID        int64     `json:"calleeId"`
	SdkVersion      string    `json:"sdkVersion"`
	ClientAppKey    string    `json:"clientAppKey"`
	Capabilities    string    `json:"capabilities"`
}

type Config struct {
	Host            string    `json:"host"`
	Port            int       `json:"port"`
	Token           string    `json:"token"`
	DeviceID        string    `json:"deviceId"`
	InstanceID      string    `json:"instanceId"`
	ClientSessionID int       `json:"clientSessionId"`
	UserAgent       UserAgent `json:"userAgent"`
	MintMode        string    `json:"mintMode"` // "silent" (76->166, default) or "call" (78)
	CalleeID        int64     `json:"calleeId"` // required for "call" mode
	IsVideo         bool      `json:"isVideo"`
	SdkVersion      string    `json:"sdkVersion"`
	ClientAppKey    string    `json:"clientAppKey"`
	Capabilities    string    `json:"capabilities"`

	// DisableFingerprint suppresses chatCacheFingerprint on the opcode 19 login.
	// The real client always sends it, and a live run confirmed MAX accepts our
	// bytes when the announced appVersion is in the digest table, so we send it
	// by default (and skip it for an unknown version, where it would mismatch —
	// see Login). Set this to force it off. See fingerprint.go.
	DisableFingerprint bool `json:"disableFingerprint,omitempty"`

	// Optional: mint from MULTIPLE accounts (pooled allocations bypass the
	// per-account throttle). When set, the top-level identity above is ignored
	// for minting and each account is used in turn.
	Accounts []Account `json:"accounts"`

	// Tunnel settings (so the client needs no CLI args — required on Android,
	// where a standalone GOOS=android binary doesn't receive os.Args).
	Server   string `json:"server"`
	WGListen string `json:"wgListen"`
	Streams  int    `json:"streams"`
	Mints    int    `json:"mints"`
	// TurnTransport picks the client↔MAX-TURN link: "auto" (default; UDP with a
	// TCP fallback for networks that block UDP), "udp", or "tcp".
	TurnTransport string `json:"turnTransport,omitempty"`
	// ReuseGroupCall re-joins ONE group call for every mint instead of creating a
	// fresh conference each time. Off by default: MAX throttles relay per minted
	// credential (per join), so reusing one call collapses all mints onto a single
	// throttle bucket — killing the throughput that scales with mints. Enable it
	// only when keeping the call history clean matters more than bandwidth.
	ReuseGroupCall bool   `json:"reuseGroupCall,omitempty"`
	DNS            string `json:"dns"` // resolver for the MAX API host (Android has no /etc/resolv.conf)

	// KeepaliveMs is the per-allocation bidirectional SRTP keepalive interval.
	// Lower = keeps MAX's per-allocation throttle disengaged more reliably, but
	// costs more packets/sec (more account pressure); higher = leaner but riskier.
	// 0 = default (50). Clamped to [20,500] by the core.
	KeepaliveMs int `json:"keepaliveMs"`

	// Optional: directory to cache minted TURN creds per account. When set, a
	// reconnect within the ~8h cred TTL reuses cached creds instead of minting
	// (no MAX group-call/conference). Empty = always mint.
	CredCacheDir string `json:"credCacheDir"`
}

// MintAccounts returns one *Config per account to mint from: each is the base
// config (host/port/tunnel settings) with that account's identity overlaid.
// With no Accounts list it returns just the base config (single-account, as before).
func (c *Config) MintAccounts() []*Config {
	if len(c.Accounts) == 0 {
		return []*Config{c}
	}
	out := make([]*Config, 0, len(c.Accounts))
	for _, a := range c.Accounts {
		cc := *c
		cc.Accounts = nil
		cc.Token = a.Token
		cc.DeviceID = a.DeviceID
		cc.InstanceID = a.InstanceID
		if a.ClientSessionID != 0 {
			cc.ClientSessionID = a.ClientSessionID
		}
		if a.UserAgent != (UserAgent{}) {
			cc.UserAgent = a.UserAgent
		}
		if a.MintMode != "" {
			cc.MintMode = a.MintMode
		}
		cc.CalleeID = a.CalleeID
		if a.SdkVersion != "" {
			cc.SdkVersion = a.SdkVersion
		}
		if a.ClientAppKey != "" {
			cc.ClientAppKey = a.ClientAppKey
		}
		if a.Capabilities != "" {
			cc.Capabilities = a.Capabilities
		}
		out = append(out, &cc)
	}
	return out
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(data)
}

// ParseConfig unmarshals a config from raw JSON bytes and applies the same
// defaults/validation as LoadConfig. The mobile wrapper uses this so the app can
// hand the core a config string without writing it to disk first.
func ParseConfig(data []byte) (*Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Host == "" {
		// api2 is the current MAX API endpoint. Its chain terminates in the
		// Минцифры root, which no OS trusts by default — Dial adds the bundled
		// anchors for exactly this reason.
		c.Host = DefaultHost
	}
	if c.Port == 0 {
		c.Port = 443
	}
	// Defaults match the ru.oneme.app 26.23.2 calls SDK, extracted from the APK
	// (ru.ok.android.externcalls.sdk): sdkVersion is ConversationFactory.SDK_VERSION,
	// clientAppKey is the literal in the InternalParamsDto builder, capabilities is
	// the hexCapability bitmask the current client sends (matches Komet). They ride
	// in internalParams on the mint request, so keep them consistent with the
	// spoofed userAgent version — see fingerprint.go for the same reasoning.
	if c.SdkVersion == "" {
		c.SdkVersion = DefaultSdkVersion
	}
	if c.ClientAppKey == "" {
		c.ClientAppKey = DefaultClientAppKey
	}
	if c.Capabilities == "" {
		c.Capabilities = DefaultCapabilities
	}
	if c.MintMode == "" {
		c.MintMode = "silent"
	}
	if c.MintMode != "silent" && c.MintMode != "call" {
		return nil, fmt.Errorf("config: mintMode must be \"silent\" or \"call\"")
	}
	if c.TurnTransport == "" {
		c.TurnTransport = "auto"
	}
	if c.TurnTransport != "auto" && c.TurnTransport != "udp" && c.TurnTransport != "tcp" {
		return nil, fmt.Errorf("config: turnTransport must be \"auto\", \"udp\" or \"tcp\"")
	}
	if len(c.Accounts) > 0 {
		for i, a := range c.Accounts {
			if a.Token == "" || a.DeviceID == "" {
				return nil, fmt.Errorf("config: accounts[%d] needs token and deviceId", i)
			}
		}
	} else {
		if c.Token == "" || c.DeviceID == "" {
			return nil, fmt.Errorf("config: token and deviceId are required")
		}
		if c.MintMode == "call" && c.CalleeID == 0 {
			return nil, fmt.Errorf("config: mintMode \"call\" requires calleeId (a friend's id)")
		}
	}
	return &c, nil
}

// Creds is a single minted TURN credential set. It is an alias for the shared
// provider.Creds so MAX and any other messenger hand the tunnel the exact same
// type; the on-disk cred cache (credcache.go) round-trips unchanged.
type Creds = provider.Creds

// Mint logs in and starts a 1:1 call (opcode 78) to harvest fresh TURN creds.
func Mint(cfg *Config) (*Creds, error) {
	return MintFrom(cfg, "")
}

// MintFrom is Mint with an optional reuseLink: in "silent" mode a non-empty
// group-call link is re-joined (opcode 166) for fresh creds instead of creating
// a new conference, falling back to a fresh conference if the link has gone
// stale. The returned Creds carries the link actually used (Creds.JoinLink), so
// the caller can thread it into the next mint. reuseLink is ignored in "call"
// mode, which has no reusable link.
func MintFrom(cfg *Config, reuseLink string) (*Creds, error) {
	client, err := Dial(cfg.Host, cfg.Port)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	callsSeed, err := SessionInit(client, cfg)
	if err != nil {
		return nil, err
	}
	if err := Login(client, cfg, callsSeed); err != nil {
		return nil, err
	}

	ip := internalParams(cfg)
	var icpRaw, usedLink string
	switch cfg.MintMode {
	case "call":
		icpRaw, err = mintCall(client, cfg.CalleeID, ip, cfg.IsVideo)
	default: // "silent"
		icpRaw, usedLink, err = mintSilent(client, ip, cfg.IsVideo, reuseLink)
	}
	if err != nil {
		return nil, err
	}
	var icp map[string]any
	if err := json.Unmarshal([]byte(icpRaw), &icp); err != nil {
		return nil, fmt.Errorf("decode internalCallerParams: %w", err)
	}

	c := &Creds{}
	if id, ok := icp["id"].(map[string]any); ok {
		c.CallsUserID = toInt64(id["internal"])
	}
	if turn, ok := icp["turn"].(map[string]any); ok {
		c.TurnHosts = turnHosts(toStrings(turn["urls"]))
		c.Username, _ = turn["username"].(string)
		c.Credential, _ = turn["credential"].(string)
	}
	if stun, ok := icp["stun"].(map[string]any); ok {
		c.StunHosts = turnHosts(toStrings(stun["urls"]))
	}
	if i := strings.IndexByte(c.Username, ':'); i > 0 {
		if sec, err := strconv.ParseInt(c.Username[:i], 10, 64); err == nil {
			c.ExpiresAt = time.Unix(sec, 0)
		}
	}
	c.JoinLink = usedLink
	if len(c.TurnHosts) == 0 || c.Credential == "" {
		return nil, fmt.Errorf("response had no TURN credentials")
	}
	return c, nil
}

// mintSilent mints TURN creds from a group conference. With reuseLink set it
// re-joins that existing conference (opcode 166) — no new conference is created,
// so remints do not spawn a fresh "Групповой звонок" each time — and falls back
// to a new conference only if the reused link has gone stale. With reuseLink
// empty it creates one (opcode 76, +84 fallback) and joins. Returns the join
// response's internalParams and the link actually used. The response's
// internalParams JSON carries the TURN creds inline (verified live against api2
// — no ws2 socket needed).
func mintSilent(client *Client, ip string, isVideo bool, reuseLink string) (icpRaw, joinLink string, err error) {
	link := reuseLink
	if link == "" {
		link, err = createJoinLink(client)
		if err != nil {
			return "", "", err
		}
	}

	icpRaw, err = joinByLink(client, link, ip, isVideo)
	if err != nil {
		if reuseLink == "" {
			return "", "", err
		}
		// The reused link failed (conference ended / expired): make a fresh one
		// and try once more, so a stale link degrades to the create path, not an
		// outage.
		logf("reused joinLink failed (%v); creating a new conference", err)
		link, err = createJoinLink(client)
		if err != nil {
			return "", "", err
		}
		icpRaw, err = joinByLink(client, link, ip, isVideo)
		if err != nil {
			return "", "", err
		}
	}
	return icpRaw, link, nil
}

// createJoinLink creates a group conference (opcode 76 — rings nobody) and
// returns its join link, falling back to opcode 84 if 76 does not carry one.
// Matches the real client's shape: 76 takes just {conversationId}.
func createJoinLink(client *Client) (string, error) {
	conv := uuidV4()
	pkt, err := client.Request(76, map[string]any{"conversationId": conv})
	if err != nil {
		return "", fmt.Errorf("mint (opcode 76): %w", err)
	}
	resp, _ := pkt.Payload.(map[string]any)
	if id, _ := resp["conversationId"].(string); id != "" {
		conv = id
	}
	link, _ := resp["joinLink"].(string)
	if link == "" {
		pkt, err = client.Request(84, map[string]any{"conversationId": conv})
		if err != nil {
			return "", fmt.Errorf("mint join-link (opcode 84): %w", err)
		}
		resp, _ = pkt.Payload.(map[string]any)
		link, _ = resp["joinLink"].(string)
	}
	if link == "" {
		return "", fmt.Errorf("no joinLink from opcode 76/84: %v", resp)
	}
	return link, nil
}

// joinByLink joins a conference by link (opcode 166) and returns the response's
// internalParams JSON string (which carries the TURN creds inline).
func joinByLink(client *Client, link, ip string, isVideo bool) (string, error) {
	pkt, err := client.Request(166, map[string]any{
		"joinLink": link, "internalParams": ip, "isVideo": isVideo,
	})
	if err != nil {
		return "", fmt.Errorf("mint join (opcode 166): %w", err)
	}
	resp, _ := pkt.Payload.(map[string]any)
	icp, _ := resp["internalParams"].(string)
	if icp == "" {
		icp, _ = resp["internalCallerParams"].(string)
	}
	if icp == "" {
		return "", fmt.Errorf("no internalParams in join response: %v", resp)
	}
	return icp, nil
}

// mintCall places a 1:1 call to a friend (opcode 78) and reads the TURN
// credentials from the call-setup response. This rings the callee.
func mintCall(client *Client, calleeID int64, ip string, isVideo bool) (string, error) {
	pkt, err := client.Request(78, map[string]any{
		"conversationId": uuidV4(), "calleeIds": []int64{calleeID},
		"internalParams": ip, "isVideo": isVideo,
	})
	if err != nil {
		return "", fmt.Errorf("mint (opcode 78): %w", err)
	}
	resp, _ := pkt.Payload.(map[string]any)
	icp, _ := resp["internalCallerParams"].(string)
	if icp == "" {
		return "", fmt.Errorf("no internalCallerParams in response: %v", resp)
	}
	return icp, nil
}

func internalParams(cfg *Config) string {
	b, _ := json.Marshal(map[string]any{
		"platform": "ANDROID", "sdkVersion": cfg.SdkVersion, "clientAppKey": cfg.ClientAppKey,
		"deviceId": cfg.DeviceID, "protocolVersion": 5, "onlyAdminCanRecord": false,
		"waitForAdmin": false, "capabilities": cfg.Capabilities,
	})
	return string(b)
}

// turnHosts strips the scheme and any "?transport=" suffix from advertised ICE
// URLs, leaving the host:port the pool allocates on.
//
// A scheme is matched as a leading token, not as "everything before the first
// colon": the latter also eats the host of a scheme-less "host:3478", leaving a
// bare port behind. Providers seen in the wild always send a scheme, so this is
// defensive — but a bare port silently allocated on is the worst way to find out
// otherwise.
func turnHosts(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		if i := strings.IndexByte(u, '?'); i >= 0 {
			u = u[:i]
		}
		for _, scheme := range []string{"turns:", "turn:", "stuns:", "stun:"} {
			rest, ok := strings.CutPrefix(u, scheme)
			if !ok {
				continue
			}
			rest = strings.TrimPrefix(rest, "//")
			// A real scheme leaves a host:port behind it; "turn:3478" is a host
			// named "turn" on port 3478, not a scheme with the host omitted.
			if strings.Contains(rest, ":") {
				u = rest
			}
			break
		}
		out = append(out, u)
	}
	return out
}

func uuidV4() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// toInt64 coerces a decoded msgpack number. msgpack encodes integers in the
// narrowest form that fits, so a field is only int64 when its value needs 64
// bits — every smaller value arrives as int8/uint8/.../uint32 and must be
// handled too, or it silently reads as 0.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case int32:
		return int64(n)
	case int16:
		return int64(n)
	case int8:
		return int64(n)
	case int:
		return int64(n)
	case uint64:
		return int64(n)
	case uint32:
		return int64(n)
	case uint16:
		return int64(n)
	case uint8:
		return int64(n)
	case uint:
		return int64(n)
	case float64:
		return int64(n)
	case float32:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

func toStrings(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
