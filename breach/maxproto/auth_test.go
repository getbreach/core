package maxproto

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

// fakeMAX is a scripted stand-in for the MAX API over an in-memory pipe: it
// answers each opcode from a table and records what was sent, so the auth flow
// can be exercised without touching the real service (every live run of it
// sends an actual SMS).
type fakeMAX struct {
	mu      sync.Mutex
	seen    map[uint16]map[string]any
	replies map[uint16]any
	errors  map[uint16]string
}

func newFakeMAX(t *testing.T, replies map[uint16]any) (*Client, *fakeMAX) {
	t.Helper()
	f := &fakeMAX{seen: map[uint16]map[string]any{}, replies: replies, errors: map[uint16]string{}}
	clientSide, serverSide := net.Pipe()

	go func() {
		defer serverSide.Close()
		r := bufio.NewReader(serverSide)
		for {
			pkt, err := readPacket(r)
			if err != nil {
				return
			}
			payload, _ := pkt.Payload.(map[string]any)
			f.mu.Lock()
			f.seen[pkt.Opcode] = payload
			reply, ok := f.replies[pkt.Opcode]
			errMsg, isErr := f.errors[pkt.Opcode]
			f.mu.Unlock()

			cmd := byte(cmdOK)
			if isErr {
				cmd, reply, ok = cmdError, map[string]any{"message": errMsg}, true
			}
			if !ok {
				reply = map[string]any{}
			}
			body, err := msgpack.Marshal(reply)
			if err != nil {
				return
			}
			if _, err := serverSide.Write(serverPacket(cmd, pkt.Opcode, pkt.Seq, 0, body)); err != nil {
				return
			}
		}
	}()

	c := newClient(clientSide)
	t.Cleanup(func() { c.Close() })
	return c, f
}

func (f *fakeMAX) request(opcode uint16) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.seen[opcode]
}

func (f *fakeMAX) failWith(opcode uint16, message string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errors[opcode] = message
}

func testConfig() *Config {
	return &Config{
		Host: DefaultHost, Port: 443,
		Token: "existing-token", DeviceID: "a1b2c3d4e5f60718", InstanceID: "inst-1",
		ClientSessionID: 1, UserAgent: DefaultUserAgent(),
	}
}

// callsSeed drives every fingerprint in the session, and msgpack sends it in the
// narrowest form that fits — so this also guards the toInt64 fix from the
// direction that matters most: a seed misread as 0 would produce a valid-looking
// but wrong fingerprint on every subsequent request.
func TestSessionInitReturnsCallsSeed(t *testing.T) {
	for _, seed := range []int{1, 300, 70000, 1 << 30} {
		c, f := newFakeMAX(t, map[uint16]any{
			opSessionInit: map[string]any{"callsSeed": seed, "deviceName": "x"},
		})
		got, err := SessionInit(c, testConfig())
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		if got != int64(seed) {
			t.Errorf("callsSeed = %d, want %d", got, seed)
		}
		sent := f.request(opSessionInit)
		if sent["deviceId"] != "a1b2c3d4e5f60718" {
			t.Errorf("deviceId not sent: %#v", sent)
		}
		if _, ok := sent["userAgent"].(map[string]any); !ok {
			t.Errorf("userAgent not sent as a map: %#v", sent["userAgent"])
		}
	}
}

func TestAuthRequestSendsFingerprintAndReturnsToken(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{
		opAuthRequest: map[string]any{"token": "temp-token-abc"},
	})
	cfg := testConfig()

	token, err := AuthRequest(c, cfg, 12345, "+7 (999) 123-45-67")
	if err != nil {
		t.Fatalf("AuthRequest: %v", err)
	}
	if token != "temp-token-abc" {
		t.Errorf("token = %q", token)
	}

	sent := f.request(opAuthRequest)
	if sent["phone"] != "+79991234567" {
		t.Errorf("phone = %#v, want normalized +79991234567", sent["phone"])
	}
	if sent["type"] != "START_AUTH" {
		t.Errorf("type = %#v", sent["type"])
	}
	if sent["language"] != "ru" {
		t.Errorf("language = %#v", sent["language"])
	}

	mode, ok := sent["mode"].([]byte)
	if !ok {
		t.Fatalf("mode sent as %T, want binary", sent["mode"])
	}
	if want := Fingerprint(12345, cfg.DeviceID); !bytes.Equal(mode, want) {
		t.Errorf("mode is not the fingerprint for this seed/device\n got %x\nwant %x", mode, want)
	}
	if len(mode) != FingerprintSize {
		t.Errorf("mode is %d bytes, want %d", len(mode), FingerprintSize)
	}
}

func TestAuthRequestRejectsShortPhone(t *testing.T) {
	c, _ := newFakeMAX(t, nil)
	if _, err := AuthRequest(c, testConfig(), 1, "123"); err == nil {
		t.Error("expected a rejection before any SMS is sent")
	}
}

func TestAuthVerifyExtractsTokenAndProfile(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{
		opAuth: map[string]any{
			"tokenAttrs": map[string]any{
				"LOGIN": map[string]any{"token": "long-lived-token"},
			},
			"profile": map[string]any{
				"contact": map[string]any{
					"id":    987654321,
					"phone": "+79991234567",
					"names": []any{map[string]any{"name": "Тест"}},
				},
			},
		},
	})

	res, err := AuthVerify(c, "temp-token-abc", " 1234 ")
	if err != nil {
		t.Fatalf("AuthVerify: %v", err)
	}
	if res.PasswordRequired {
		t.Fatal("did not expect a password challenge")
	}
	if res.Token != "long-lived-token" {
		t.Errorf("token = %q", res.Token)
	}
	if res.Profile.UserID != 987654321 {
		t.Errorf("UserID = %d", res.Profile.UserID)
	}
	if res.Profile.Phone != "+79991234567" || res.Profile.Name != "Тест" {
		t.Errorf("profile = %+v", res.Profile)
	}

	sent := f.request(opAuth)
	if sent["verifyCode"] != "1234" {
		t.Errorf("verifyCode = %#v, want trimmed", sent["verifyCode"])
	}
	if sent["authTokenType"] != "CHECK_CODE" || sent["token"] != "temp-token-abc" {
		t.Errorf("verify payload = %#v", sent)
	}
}

// A wrong code comes back without a LOGIN token; that must be an error rather
// than an empty token handed on to the caller.
func TestAuthVerifyRejectsResponseWithoutToken(t *testing.T) {
	c, _ := newFakeMAX(t, map[uint16]any{
		opAuth: map[string]any{"profile": map[string]any{}},
	})
	if _, err := AuthVerify(c, "temp", "0000"); err == nil {
		t.Error("expected an error when the response carries no LOGIN token")
	}
}

func TestAuthVerifyRejectsEmptyCode(t *testing.T) {
	c, _ := newFakeMAX(t, nil)
	if _, err := AuthVerify(c, "temp", "   "); err == nil {
		t.Error("expected an error for a blank code")
	}
}

func TestAuthPropagatesServerError(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{opAuthRequest: map[string]any{"token": "x"}})
	f.failWith(opAuthRequest, "phone.blocked")

	_, err := AuthRequest(c, testConfig(), 1, "+79991234567")
	if err == nil {
		t.Fatal("expected the server error to surface")
	}
	if !strings.Contains(err.Error(), "phone.blocked") {
		t.Errorf("error lost the server message: %v", err)
	}
}

// The default config announces a version in the digest table, so Login now
// sends chatCacheFingerprint — the real client always does, and a live run
// confirmed MAX accepts it. presenceSync/chatsSync match the real client too.
func TestLoginSendsFingerprintByDefault(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{opLogin: map[string]any{}})
	cfg := testConfig()

	if err := Login(c, cfg, 12345); err != nil {
		t.Fatalf("Login: %v", err)
	}
	sent := f.request(opLogin)
	fp, ok := sent["chatCacheFingerprint"].([]byte)
	if !ok {
		t.Fatalf("chatCacheFingerprint missing or not binary")
	}
	if want := Fingerprint(12345, cfg.DeviceID); !bytes.Equal(fp, want) {
		t.Errorf("fingerprint mismatch\n got %x\nwant %x", fp, want)
	}
	if sent["token"] != "existing-token" {
		t.Errorf("token = %#v", sent["token"])
	}
	if sent["interactive"] != false {
		t.Errorf("interactive = %#v", sent["interactive"])
	}
	if sent["presenceSync"] != int8(-1) && toInt64(sent["presenceSync"]) != -1 {
		t.Errorf("presenceSync = %#v, want -1", sent["presenceSync"])
	}
	if _, ok := sent["exp"].(map[string]any); !ok {
		t.Errorf("exp = %#v", sent["exp"])
	}
}

// DisableFingerprint forces it off even for a known version.
func TestLoginDisableFingerprint(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{opLogin: map[string]any{}})
	cfg := testConfig()
	cfg.DisableFingerprint = true

	if err := Login(c, cfg, 12345); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, present := f.request(opLogin)["chatCacheFingerprint"]; present {
		t.Error("chatCacheFingerprint sent despite DisableFingerprint")
	}
}

// An unknown appVersion must NOT send a fingerprint: fingerprintFor would fall
// back to a different build, and a fingerprint contradicting the announced
// version is worse than none.
func TestLoginSkipsFingerprintForUnknownVersion(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{opLogin: map[string]any{}})
	cfg := testConfig()
	cfg.UserAgent.AppVersion = "0.0.0-nonexistent"

	if err := Login(c, cfg, 12345); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, present := f.request(opLogin)["chatCacheFingerprint"]; present {
		t.Error("fingerprint sent for a version with no digests")
	}
}

// Without a callsSeed there is nothing to bind the fingerprint to; sending one
// derived from 0 would be a wrong value rather than a missing field.
func TestLoginSkipsFingerprintWithoutSeed(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{opLogin: map[string]any{}})
	cfg := testConfig()

	if err := Login(c, cfg, 0); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, present := f.request(opLogin)["chatCacheFingerprint"]; present {
		t.Error("fingerprint sent with callsSeed 0")
	}
}

func TestNormalizePhone(t *testing.T) {
	for in, want := range map[string]string{
		"+7 (999) 123-45-67": "+79991234567",
		"89991234567":        "+89991234567",
		"+7-999-123-45-67":   "+79991234567",
		"":                   "+",
	} {
		if got := NormalizePhone(in); got != want {
			t.Errorf("NormalizePhone(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMaskPhoneKeepsNumberOutOfLogs(t *testing.T) {
	full := "+79991234567"
	masked := MaskPhone(full)
	if strings.Contains(masked, "9991234") {
		t.Errorf("MaskPhone leaked the subscriber digits: %q", masked)
	}
	if MaskPhone("+7999") != "***" {
		t.Errorf("short input should mask entirely, got %q", MaskPhone("+7999"))
	}
}

// deviceId is 16 hex characters (an Android ID) and instanceId a UUID; MAX ties
// the LOGIN token to both, so the format has to match the real client's.
func TestNewIdentityFormat(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		id, err := NewIdentity()
		if err != nil {
			t.Fatalf("NewIdentity: %v", err)
		}
		if len(id.DeviceID) != 16 {
			t.Fatalf("deviceId %q is %d chars, want 16", id.DeviceID, len(id.DeviceID))
		}
		if strings.Trim(id.DeviceID, "0123456789abcdef") != "" {
			t.Fatalf("deviceId %q is not lowercase hex", id.DeviceID)
		}
		if len(id.InstanceID) != 36 || strings.Count(id.InstanceID, "-") != 4 {
			t.Fatalf("instanceId %q is not a UUID", id.InstanceID)
		}
		if seen[id.DeviceID] {
			t.Fatalf("duplicate deviceId %q across generations", id.DeviceID)
		}
		seen[id.DeviceID] = true
	}
}

func TestNewAuthConfigNeedsNoToken(t *testing.T) {
	cfg, err := NewAuthConfig("", nil)
	if err != nil {
		t.Fatalf("NewAuthConfig: %v", err)
	}
	if cfg.Host != DefaultHost {
		t.Errorf("host = %q, want %q", cfg.Host, DefaultHost)
	}
	if cfg.Token != "" {
		t.Errorf("token = %q, want empty (obtaining one is the point)", cfg.Token)
	}
	if cfg.DeviceID == "" || cfg.InstanceID == "" {
		t.Error("identity not generated")
	}

	id := Identity{DeviceID: "0011223344556677", InstanceID: "reused"}
	reused, err := NewAuthConfig("api.oneme.ru", &id)
	if err != nil {
		t.Fatalf("NewAuthConfig: %v", err)
	}
	if reused.DeviceID != id.DeviceID || reused.InstanceID != id.InstanceID {
		t.Errorf("supplied identity was not reused: %+v", reused)
	}
	if reused.Host != "api.oneme.ru" {
		t.Errorf("host override ignored: %q", reused.Host)
	}
}

// The default host moved to api2, which is exactly the host that does not
// validate without the bundled anchors.
func TestDefaultHostIsApi2(t *testing.T) {
	if DefaultHost != "api2.oneme.ru" {
		t.Errorf("DefaultHost = %q", DefaultHost)
	}
	cfg, err := ParseConfig([]byte(`{"token":"t","deviceId":"d"}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.Host != DefaultHost {
		t.Errorf("config default host = %q, want %q", cfg.Host, DefaultHost)
	}
}

// The bundle must be the Минцифры root plus its sub CA, and the sub must
// actually chain to the root — a stale or truncated copy would fail at TLS
// time against api2 with a confusing "unknown authority".
func TestMincifryBundleIsRootPlusSubCA(t *testing.T) {
	var certs []*x509.Certificate
	rest := mincifryCAPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parsing bundled cert: %v", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) != mincifryPoolCount {
		t.Fatalf("bundle has %d certs, want %d (root + sub CA)", len(certs), mincifryPoolCount)
	}

	root, sub := certs[0], certs[1]
	for _, c := range certs {
		if !c.IsCA {
			t.Errorf("%q is not a CA certificate", c.Subject.CommonName)
		}
	}
	if root.Subject.CommonName != "Russian Trusted Root CA" {
		t.Errorf("first cert is %q, want the root", root.Subject.CommonName)
	}
	if sub.Subject.CommonName != "Russian Trusted Sub CA" {
		t.Errorf("second cert is %q, want the sub CA", sub.Subject.CommonName)
	}
	if err := sub.CheckSignatureFrom(root); err != nil {
		t.Errorf("sub CA does not chain to the bundled root: %v", err)
	}

	pool, err := mincifryRoots()
	if err != nil {
		t.Fatalf("mincifryRoots: %v", err)
	}
	if pool == nil {
		t.Fatal("nil root pool")
	}
}

// The calls-SDK defaults are extracted from ru.oneme.app 26.23.2's APK
// (ru.ok.android.externcalls.sdk) and must match what the real client puts in
// internalParams, so a minted allocation looks like it came from that build.
func TestCallsSDKDefaults(t *testing.T) {
	if DefaultSdkVersion != "0.2.1.3" {
		t.Errorf("DefaultSdkVersion = %q, want 0.2.1.3 (APK ConversationFactory.SDK_VERSION)", DefaultSdkVersion)
	}
	if DefaultClientAppKey != "CGPGAGLGDIHBABABA" {
		t.Errorf("DefaultClientAppKey = %q", DefaultClientAppKey)
	}
	if DefaultCapabilities != "3c02f" {
		t.Errorf("DefaultCapabilities = %q, want 3c02f (hexCapability the client sends)", DefaultCapabilities)
	}

	// ParseConfig must fill exactly these when the config omits them.
	cfg, err := ParseConfig([]byte(`{"token":"t","deviceId":"d"}`))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if cfg.SdkVersion != DefaultSdkVersion || cfg.ClientAppKey != DefaultClientAppKey || cfg.Capabilities != DefaultCapabilities {
		t.Errorf("defaults not applied: sdk=%q key=%q caps=%q", cfg.SdkVersion, cfg.ClientAppKey, cfg.Capabilities)
	}

	// internalParams carries them on the wire under the DTO's JSON keys
	// ("capabilities", not "hexCapability"; "waitForAdmin", not
	// "isWaitForAdminEnabled") — the names the APK's InternalParamsDto serializer
	// uses, confirmed against smali.
	var ip map[string]any
	if err := json.Unmarshal([]byte(internalParams(cfg)), &ip); err != nil {
		t.Fatalf("internalParams is not valid JSON: %v", err)
	}
	for _, want := range []struct {
		key string
		val any
	}{
		{"platform", "ANDROID"},
		{"sdkVersion", DefaultSdkVersion},
		{"clientAppKey", DefaultClientAppKey},
		{"capabilities", DefaultCapabilities},
	} {
		if ip[want.key] != want.val {
			t.Errorf("internalParams[%q] = %#v, want %#v", want.key, ip[want.key], want.val)
		}
	}
	if _, ok := ip["waitForAdmin"]; !ok {
		t.Error("internalParams missing waitForAdmin key")
	}
}

// A 2FA account answers the SMS step with a passwordChallenge instead of a
// token; AuthVerify must surface that as a state, not an error.
func TestAuthVerifyDetectsPasswordChallenge(t *testing.T) {
	c, _ := newFakeMAX(t, map[uint16]any{
		opAuth: map[string]any{
			"passwordChallenge": map[string]any{"trackId": "track-xyz", "hint": "my cat"},
		},
	})
	res, err := AuthVerify(c, "temp", "1234")
	if err != nil {
		t.Fatalf("AuthVerify: %v", err)
	}
	if !res.PasswordRequired {
		t.Fatal("passwordChallenge not detected")
	}
	if res.TrackID != "track-xyz" || res.Hint != "my cat" {
		t.Errorf("challenge = %+v", res)
	}
	if res.Token != "" {
		t.Errorf("token should be empty on a challenge, got %q", res.Token)
	}
}

// A REGISTER token (number with no account) is a distinct, clearer error than a
// wrong code — we do not create accounts.
func TestAuthVerifyReportsUnregisteredNumber(t *testing.T) {
	c, _ := newFakeMAX(t, map[uint16]any{
		opAuth: map[string]any{
			"tokenAttrs": map[string]any{"REGISTER": map[string]any{"token": "reg-token"}},
		},
	})
	_, err := AuthVerify(c, "temp", "1234")
	if err == nil || !strings.Contains(err.Error(), "no MAX account") {
		t.Errorf("err = %v, want an unregistered-number message", err)
	}
}

func TestCheckPasswordReturnsToken(t *testing.T) {
	c, f := newFakeMAX(t, map[uint16]any{
		opAuthLoginCheckPass: map[string]any{
			"tokenAttrs": map[string]any{"LOGIN": map[string]any{"token": "login-after-2fa"}},
			"profile":    map[string]any{"contact": map[string]any{"id": 555, "phone": "+70001112233"}},
		},
	})
	res, err := CheckPassword(c, "track-xyz", "hunter2")
	if err != nil {
		t.Fatalf("CheckPassword: %v", err)
	}
	if res.Token != "login-after-2fa" {
		t.Errorf("token = %q", res.Token)
	}
	if res.Profile.UserID != 555 {
		t.Errorf("UserID = %d", res.Profile.UserID)
	}
	sent := f.request(opAuthLoginCheckPass)
	if sent["trackId"] != "track-xyz" || sent["password"] != "hunter2" {
		t.Errorf("checkPassword payload = %#v", sent)
	}
}

// A wrong password comes back as an OK packet carrying an in-band error, not an
// error packet — CheckPassword must still treat it as failure.
func TestCheckPasswordRejectsInBandError(t *testing.T) {
	c, _ := newFakeMAX(t, map[uint16]any{
		opAuthLoginCheckPass: map[string]any{"error": "password.invalid"},
	})
	if _, err := CheckPassword(c, "track", "wrong"); err == nil {
		t.Error("expected an error for a wrong password reported in-band")
	}
}

func TestCheckPasswordRejectsEmptyArgs(t *testing.T) {
	c, _ := newFakeMAX(t, nil)
	if _, err := CheckPassword(c, "", "pw"); err == nil {
		t.Error("empty trackId should error")
	}
	if _, err := CheckPassword(c, "track", ""); err == nil {
		t.Error("empty password should error")
	}
}

func TestExtractAccountIDProbesNests(t *testing.T) {
	cases := []struct {
		name string
		m    map[string]any
		want int64
	}{
		{"profile.contact.id", map[string]any{"profile": map[string]any{"contact": map[string]any{"id": 111}}}, 111},
		{"profile.contact.accountId", map[string]any{"profile": map[string]any{"contact": map[string]any{"accountId": 222}}}, 222},
		{"profile.id", map[string]any{"profile": map[string]any{"id": 333}}, 333},
		{"flat accountId", map[string]any{"accountId": 444}, 444},
		{"flat account_id", map[string]any{"account_id": 555}, 555},
		{"none", map[string]any{"foo": "bar"}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractAccountID(tc.m); got != tc.want {
				t.Errorf("extractAccountID = %d, want %d", got, tc.want)
			}
		})
	}
}

// countingFakeMAX records how many times each opcode was requested, so the mint
// reuse logic can be checked by counting conference-creation calls.
func countingFakeMAX(t *testing.T, replies map[uint16]any) (*Client, func(uint16) int, func(uint16, string)) {
	t.Helper()
	var mu chanCounter
	mu.n = map[uint16]int{}
	mu.replies = replies
	mu.fail = map[uint16]string{}
	clientSide, serverSide := net.Pipe()
	go mu.serve(serverSide)
	c := newClient(clientSide)
	t.Cleanup(func() { c.Close() })
	return c, mu.count, mu.setFail
}

type chanCounter struct {
	mu      syncMutex
	n       map[uint16]int
	replies map[uint16]any
	fail    map[uint16]string
}

func (f *chanCounter) serve(conn net.Conn) {
	defer conn.Close()
	r := bufioNewReader(conn)
	for {
		pkt, err := readPacket(r)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.n[pkt.Opcode]++
		reply, ok := f.replies[pkt.Opcode]
		msg, isErr := f.fail[pkt.Opcode]
		f.mu.Unlock()
		cmd := byte(cmdOK)
		if isErr {
			cmd, reply, ok = cmdError, map[string]any{"message": msg}, true
		}
		if !ok {
			reply = map[string]any{}
		}
		body, _ := msgpackMarshal(reply)
		if _, err := conn.Write(serverPacket(cmd, pkt.Opcode, pkt.Seq, 0, body)); err != nil {
			return
		}
	}
}

func (f *chanCounter) count(op uint16) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n[op]
}

func (f *chanCounter) setFail(op uint16, msg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[op] = msg
}

// A reused link joins straight to opcode 166 — no conference (76) is created.
func TestMintSilentReusesLink(t *testing.T) {
	icp := `{"turn":{"urls":["turn:1.2.3.4:19302"],"username":"u","credential":"c"}}`
	c, count, _ := countingFakeMAX(t, map[uint16]any{
		166: map[string]any{"internalParams": icp},
	})

	raw, link, err := mintSilent(c, "{}", false, "existing-link")
	if err != nil {
		t.Fatalf("mintSilent: %v", err)
	}
	if link != "existing-link" {
		t.Errorf("link = %q, want the reused one", link)
	}
	if raw == "" {
		t.Error("no internalParams returned")
	}
	if count(76) != 0 {
		t.Errorf("created %d conferences; a reused link must create none", count(76))
	}
	if count(166) != 1 {
		t.Errorf("joined %d times, want 1", count(166))
	}
}

// With no link, exactly one conference is created and then joined.
func TestMintSilentCreatesWhenNoLink(t *testing.T) {
	icp := `{"turn":{"urls":["turn:1.2.3.4:19302"],"username":"u","credential":"c"}}`
	c, count, _ := countingFakeMAX(t, map[uint16]any{
		76:  map[string]any{"joinLink": "fresh-link", "conversationId": "conv-1"},
		166: map[string]any{"internalParams": icp},
	})

	_, link, err := mintSilent(c, "{}", false, "")
	if err != nil {
		t.Fatalf("mintSilent: %v", err)
	}
	if link != "fresh-link" {
		t.Errorf("link = %q, want the created one", link)
	}
	if count(76) != 1 || count(166) != 1 {
		t.Errorf("opcodes: 76=%d 166=%d, want 1/1", count(76), count(166))
	}
}

// A stale reused link must degrade to creating a fresh conference, not fail.
func TestMintSilentFallsBackOnStaleLink(t *testing.T) {
	icp := `{"turn":{"urls":["turn:1.2.3.4:19302"],"username":"u","credential":"c"}}`
	c, count, setFail := countingFakeMAX(t, map[uint16]any{
		76:  map[string]any{"joinLink": "fresh-link"},
		166: map[string]any{"internalParams": icp},
	})
	// First join (the reused link) fails; the retry after creating a conference
	// must succeed. The fake fails 166 unconditionally, so to test the fallback
	// path we instead assert a conference gets created on a reuse failure.
	setFail(166, "call.not.found")

	_, _, err := mintSilent(c, "{}", false, "stale-link")
	// Both joins fail here (fake fails 166 always), so we expect an error — but a
	// conference must have been created on the fallback attempt.
	if err == nil {
		t.Fatal("expected an error when every join fails")
	}
	if count(76) != 1 {
		t.Errorf("fallback did not create a conference (76 count = %d)", count(76))
	}
	if count(166) != 2 {
		t.Errorf("expected 2 join attempts (reuse + fallback), got %d", count(166))
	}
}

// createJoinLink falls back to opcode 84 when 76 returns no link.
func TestCreateJoinLinkFallsBackTo84(t *testing.T) {
	c, count, _ := countingFakeMAX(t, map[uint16]any{
		76: map[string]any{"conversationId": "conv-9"}, // no joinLink
		84: map[string]any{"joinLink": "link-from-84"},
	})
	link, err := createJoinLink(c)
	if err != nil {
		t.Fatalf("createJoinLink: %v", err)
	}
	if link != "link-from-84" {
		t.Errorf("link = %q", link)
	}
	if count(84) != 1 {
		t.Error("opcode 84 fallback not used")
	}
}

// Creds carries the link it was minted from, so it round-trips through the cred
// cache and the caller can reuse it.
func TestCredsJoinLinkPersists(t *testing.T) {
	dir := t.TempDir()
	orig := []*Creds{{
		TurnHosts: []string{"1.2.3.4:19302"}, Username: "u", Credential: "c",
		ExpiresAt: timeNowPlusHour(), JoinLink: "persisted-link",
	}}
	SaveCachedCreds(dir, "tok", orig)
	got := LoadCachedCreds(dir, "tok")
	if len(got) != 1 || got[0].JoinLink != "persisted-link" {
		t.Errorf("JoinLink did not survive the cred cache: %+v", got)
	}
}

type syncMutex = sync.Mutex

func bufioNewReader(c net.Conn) *bufio.Reader { return bufio.NewReader(c) }
func msgpackMarshal(v any) ([]byte, error)    { return msgpack.Marshal(v) }
func timeNowPlusHour() time.Time              { return time.Now().Add(time.Hour) }
