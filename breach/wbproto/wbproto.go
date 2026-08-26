package wbproto

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	chatBaseURL = "https://chat.wb.ru"
	vcsBaseURL  = "https://chat.wb.ru/api/vcs/v1"
	tokenURL    = "https://id.wb.ru/oauth-bff/api/mobile/v1/token"
)

type Session struct {
	AccessToken   string `json:"accessToken"`
	RefreshToken  string `json:"refreshToken"`
	ValidationKey string `json:"validationKey"`
	DeviceID      string `json:"deviceId"`
	ClientID      string `json:"clientId"`
	RedirectURI   string `json:"redirectUri"`
}

type Client struct {
	HTTP        *http.Client
	Session     Session
	SessionPath string
}

type UserBrief struct {
	UserID      string `json:"userId"`
	DisplayName string `json:"displayName"`
	AvatarURL   string `json:"avatarUrl"`
}

type IceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
}

type RTCConfig struct {
	IceServers []IceServer `json:"iceServers"`
}

type CallResponse struct {
	CallID          string    `json:"callId"`
	Channel         string    `json:"channel"`
	ConnectionToken string    `json:"connectionToken"`
	WebSocketURL    string    `json:"wsUrl"`
	RTCConfig       RTCConfig `json:"rtcConfig"`
	Caller          UserBrief `json:"caller"`
	Callee          UserBrief `json:"callee"`
	Version         string    `json:"version"`
}

type VersionedCallResponse struct {
	CallID  string `json:"callId"`
	Channel string `json:"channel"`
	State   string `json:"state"`
	Version string `json:"version"`
}

type chatMembersResponse struct {
	Data []chatMember `json:"data"`
}

type chatMember struct {
	ID json.RawMessage `json:"id"`
}

type TURNServer struct {
	Address    string
	Transport  string
	Username   string
	Credential string
}

func (s TURNServer) ExpiresAt() time.Time {
	prefix, _, ok := strings.Cut(s.Username, ":")
	if !ok {
		return time.Time{}
	}
	unix, err := strconv.ParseInt(prefix, 10, 64)
	if err != nil || unix <= 0 {
		return time.Time{}
	}
	return time.Unix(unix, 0)
}

func CredentialsExpiry(servers []TURNServer) time.Time {
	var earliest time.Time
	for _, server := range servers {
		expires := server.ExpiresAt()
		if !expires.IsZero() && (earliest.IsZero() || expires.Before(earliest)) {
			earliest = expires
		}
	}
	return earliest
}

type APIError struct {
	Method string
	URL    string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.URL, e.Status, e.Body)
}

func Load(sessionPath string) (*Client, error) {
	b, err := os.ReadFile(sessionPath)
	if err != nil {
		return nil, fmt.Errorf("read WBID session: %w", err)
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("decode WBID session: %w", err)
	}
	if s.AccessToken == "" || s.RefreshToken == "" || s.ValidationKey == "" || s.DeviceID == "" {
		return nil, errors.New("WBID session needs accessToken, refreshToken, validationKey and deviceId")
	}
	if s.ClientID == "" {
		s.ClientID = "wb_workspace_android"
	}
	if s.RedirectURI == "" {
		s.RedirectURI = "https://chat.wb.ru/android/ru.wb.workspace/callback"
	}
	return &Client{
		HTTP:        &http.Client{Timeout: 30 * time.Second},
		Session:     s,
		SessionPath: sessionPath,
	}, nil
}

func (c *Client) SessionFileIsPrivate() (bool, error) {
	st, err := os.Stat(c.SessionPath)
	if err != nil {
		return false, err
	}
	return st.Mode().Perm()&0o077 == 0, nil
}

func (c *Client) ResolvePeer(ctx context.Context, chat string) (string, error) {
	chat = NormalizeChatID(chat)
	var members chatMembersResponse
	path := "/api/messenger/v1/chat/members?chatId=" + url.QueryEscape(chat) + "&limit=100"
	if err := c.do(ctx, http.MethodGet, chatBaseURL+path, nil, &members, true); err != nil {
		return "", err
	}
	myID := jwtUserID(c.Session.AccessToken)
	var peers []string
	for _, member := range members.Data {
		id := jsonScalarString(member.ID)
		if id != "" && id != myID {
			peers = append(peers, id)
		}
	}
	if len(peers) != 1 {
		return "", fmt.Errorf("personal chat must contain exactly one peer, got %d", len(peers))
	}
	return peers[0], nil
}

func (c *Client) InitiateCall(ctx context.Context, calleeID, callType, chat string) (*CallResponse, error) {
	callType = strings.ToUpper(callType)
	switch callType {
	case "AUDIO":
		callType = "CALL_TYPE_AUDIO"
	case "VIDEO":
		callType = "CALL_TYPE_VIDEO"
	case "CALL_TYPE_AUDIO", "CALL_TYPE_VIDEO":
	default:
		return nil, fmt.Errorf("unsupported call type %q", callType)
	}
	body := map[string]any{
		"calleeId":       calleeID,
		"callType":       callType,
		"idempotencyKey": newUUID(),
	}
	if chat != "" {
		body["extra"] = map[string]string{"chatId": NormalizeChatID(chat)}
	}
	var out CallResponse
	if err := c.do(ctx, http.MethodPost, vcsBaseURL+"/p2p/calls:initiateCall", body, &out, true); err != nil {
		return nil, err
	}
	if out.CallID == "" {
		return nil, errors.New("initiateCall response has no callId")
	}
	return &out, nil
}

func (c *Client) CancelCall(ctx context.Context, callID, expectedVersion string) (*VersionedCallResponse, error) {
	body := map[string]string{"callId": callID, "expectedVersion": expectedVersion}
	var out VersionedCallResponse
	if err := c.do(ctx, http.MethodPost, vcsBaseURL+"/p2p/calls:cancelCall", body, &out, true); err != nil {
		return nil, err
	}
	return &out, nil
}

func (r *CallResponse) TURNCredentials() []TURNServer {
	seen := make(map[string]bool)
	var out []TURNServer
	for _, ice := range r.RTCConfig.IceServers {
		if ice.Username == "" || ice.Credential == "" {
			continue
		}
		for _, raw := range ice.URLs {
			address, transport, ok := parseTURNURL(raw)
			if !ok {
				continue
			}
			key := address + "\x00" + transport
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, TURNServer{
				Address: address, Transport: transport,
				Username: ice.Username, Credential: ice.Credential,
			})
		}
	}
	return out
}

func NormalizeChatID(chat string) string {
	return strings.TrimPrefix(strings.TrimSpace(chat), "chats/")
}

func parseTURNURL(raw string) (address, transport string, ok bool) {
	if !strings.HasPrefix(raw, "turn:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(raw, "turn:")
	address, query, _ := strings.Cut(rest, "?")
	if address == "" {
		return "", "", false
	}
	transport = "udp"
	if values, err := url.ParseQuery(query); err == nil && values.Get("transport") != "" {
		transport = strings.ToLower(values.Get("transport"))
	}
	if transport != "udp" && transport != "tcp" {
		return "", "", false
	}
	return address, transport, true
}

func (c *Client) do(ctx context.Context, method, endpoint string, body any, out any, retryAuth bool) error {
	if tokenExpiring(c.Session.AccessToken, 60*time.Second) {
		if err := c.refresh(ctx); err != nil {
			return err
		}
	}
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Session.AccessToken)
	req.Header.Set("X-WBID-SDK-Validation-Key", c.Session.ValidationKey)
	req.Header.Set("X-Device-Id", c.Session.DeviceID)
	req.Header.Set("User-Agent", "ktor-client")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) && retryAuth {
		if err := c.refresh(ctx); err != nil {
			return err
		}
		return c.do(ctx, method, endpoint, body, out, false)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Method: method, URL: endpoint, Status: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	}
	if len(b) == 0 || out == nil {
		return nil
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("decode %s response: %w", endpoint, err)
	}
	return nil
}

func (c *Client) refresh(ctx context.Context) error {
	body := map[string]string{
		"clientId": c.Session.ClientID, "grantType": "refresh_token",
		"refreshToken": c.Session.RefreshToken, "redirectUri": c.Session.RedirectURI,
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ktor-client")
	req.Header.Set("X-Device-Id", c.Session.DeviceID)
	req.AddCookie(&http.Cookie{Name: "device_id", Value: c.Session.DeviceID})
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("refresh WBID token: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{Method: http.MethodPost, URL: tokenURL, Status: resp.StatusCode, Body: strings.TrimSpace(string(responseBody))}
	}
	var update map[string]json.RawMessage
	if err := json.Unmarshal(responseBody, &update); err != nil {
		return fmt.Errorf("decode refresh response: %w", err)
	}
	current, err := os.ReadFile(c.SessionPath)
	if err != nil {
		return err
	}
	var session map[string]json.RawMessage
	if err := json.Unmarshal(current, &session); err != nil {
		return err
	}
	for key, value := range update {
		session[key] = value
	}
	merged, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	if err := writePrivate(c.SessionPath, append(merged, '\n')); err != nil {
		return err
	}
	return json.Unmarshal(merged, &c.Session)
}

func writePrivate(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wbid-session-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func tokenExpiring(token string, leeway time.Duration) bool {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Exp json.Number `json:"exp"`
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return false
	}
	exp, err := strconv.ParseInt(string(claims.Exp), 10, 64)
	return err == nil && time.Now().Add(leeway).Unix() >= exp
}

func jwtUserID(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims map[string]any
	if json.Unmarshal(b, &claims) != nil {
		return ""
	}
	for _, key := range []string{"sub", "user"} {
		if value, ok := claims[key]; ok {
			return fmt.Sprint(value)
		}
	}
	return ""
}

func jsonScalarString(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return string(n)
	}
	return ""
}

func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
