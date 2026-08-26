package wbproto

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// WB ID OAuth2 endpoints and the fixed public-client parameters (authorization
// code + PKCE S256), mirroring the WB workspace Android app. Login is two steps
// separated by a human action: StartLogin builds the authorize URL, the user
// signs in via web and is redirected to redirectURI with a ?code=..., then
// Complete exchanges that code for tokens. tokenURL is shared with refresh().
const (
	authorizeURL = "https://id.wb.ru/login/oauth2/authorize"
	wbClientID   = "wb_workspace_android"
	wbRedirect   = "https://chat.wb.ru/android/ru.wb.workspace/callback"
	wbScope      = "openid phone read:profile:first_name read:profile:last_name"
	wbAudience   = "https://wbid.ru"
)

// LoginFlow holds the per-attempt PKCE secret and state between StartLogin and
// Complete. Keep the same instance across both calls (the mobile app stashes it
// while the webview is open); a fresh Complete on a different LoginFlow fails the
// state/verifier check by design.
type LoginFlow struct {
	AuthURL  string // open this; the user signs in and is redirected to the callback
	DeviceID string // stable device identity, carried into the saved session
	State    string // CSRF token echoed back in the callback

	verifier string // PKCE code_verifier, never leaves the process
}

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// StartLogin builds the WB ID authorize URL and the PKCE/state secrets. Pass an
// existing session's deviceID to keep the device identity stable across
// re-logins, or "" to mint a fresh one.
func StartLogin(deviceID string) (*LoginFlow, error) {
	if deviceID == "" {
		deviceID = newUUID()
	}
	verBytes := make([]byte, 48)
	if _, err := rand.Read(verBytes); err != nil {
		return nil, err
	}
	verifier := b64url(verBytes)
	sum := sha256.Sum256([]byte(verifier))
	challenge := b64url(sum[:])
	state := newUUID()

	q := url.Values{
		"client_id":             {wbClientID},
		"response_type":         {"code"},
		"redirect_uri":          {wbRedirect},
		"code_challenge_method": {"S256"},
		"code_challenge":        {challenge},
		"state":                 {state},
		"deviceId":              {deviceID},
		"prompt":                {"none"},
		"scope":                 {wbScope},
		"audience":              {wbAudience},
		"fresh_auth":            {"1"},
	}
	return &LoginFlow{
		AuthURL:  authorizeURL + "?" + q.Encode(),
		DeviceID: deviceID,
		State:    state,
		verifier: verifier,
	}, nil
}

// Complete parses the callback URL the user pasted back, validates it against
// this flow's state, exchanges the authorization code for tokens, and writes the
// WBID session to sessionPath (0600). It returns the parsed Session. The whole
// token response is persisted (like refresh does), not just the typed fields, so
// nothing WB sends is silently dropped.
func (f *LoginFlow) Complete(ctx context.Context, callbackURL, sessionPath string) (*Session, error) {
	code, err := f.codeFromCallback(callbackURL)
	if err != nil {
		return nil, err
	}

	payload := map[string]string{
		"clientId":     wbClientID,
		"grantType":    "authorization_code",
		"code":         code,
		"codeVerifier": f.verifier,
		"redirectUri":  wbRedirect,
		"state":        f.State,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ktor-client")
	req.Header.Set("X-Device-Id", f.DeviceID)
	req.AddCookie(&http.Cookie{Name: "device_id", Value: f.DeviceID})

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exchange WBID code: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{Method: http.MethodPost, URL: tokenURL, Status: resp.StatusCode, Body: strings.TrimSpace(string(raw))}
	}

	var session map[string]json.RawMessage
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	// Inject the fields refresh() and Load() expect but the token endpoint does
	// not echo, so the saved session is self-sufficient.
	for k, v := range map[string]string{"deviceId": f.DeviceID, "clientId": wbClientID, "redirectUri": wbRedirect} {
		b, _ := json.Marshal(v)
		session[k] = b
	}
	merged, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := writePrivate(sessionPath, append(merged, '\n')); err != nil {
		return nil, err
	}

	var s Session
	if err := json.Unmarshal(merged, &s); err != nil {
		return nil, err
	}
	if s.AccessToken == "" || s.RefreshToken == "" || s.ValidationKey == "" {
		return &s, errors.New("token response missing accessToken/refreshToken/validationKey")
	}
	return &s, nil
}

func (f *LoginFlow) codeFromCallback(callbackURL string) (string, error) {
	got, err := url.Parse(strings.TrimSpace(callbackURL))
	if err != nil {
		return "", fmt.Errorf("parse callback URL: %w", err)
	}
	want, _ := url.Parse(wbRedirect)
	if got.Scheme != want.Scheme || got.Host != want.Host || got.Path != want.Path {
		return "", fmt.Errorf("not the expected callback URL (want %s)", wbRedirect)
	}
	qs := got.Query()
	if e := qs.Get("error"); e != "" {
		return "", fmt.Errorf("oauth error: %s %s", e, qs.Get("error_description"))
	}
	code := qs.Get("code")
	if code == "" {
		return "", errors.New("callback URL has no code parameter")
	}
	if qs.Get("state") != f.State {
		return "", errors.New("state mismatch (callback does not match this login attempt)")
	}
	return code, nil
}

// DeviceIDFromSession best-effort reads the deviceId from an existing session
// file so a re-login keeps the same device identity. Returns "" if absent.
func DeviceIDFromSession(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var s struct {
		DeviceID string `json:"deviceId"`
	}
	if json.Unmarshal(b, &s) != nil {
		return ""
	}
	return s.DeviceID
}
