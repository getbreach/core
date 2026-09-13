package breachmobile

import (
	"context"
	"fmt"
	"os"
	"time"

	"breach/wbproto"
)

// WB ID login + chat listing, exposed to the Android app. Login is the two-step
// browser-callback OAuth flow: WBStartLogin builds an authorize URL, the app
// opens it in a Custom Tab / WebView, catches the redirect to the WB callback
// URL, and hands it to Complete. These calls happen before the VPN is up (so no
// tun to loop into); once a transport is running, wbproto.Control is already set
// and they are socket-protected automatically.

// WBLoginFlow is a live WB ID login attempt. Keep the same instance between
// WBStartLogin and Complete — the PKCE secret lives inside it.
type WBLoginFlow struct {
	inner *wbproto.LoginFlow
}

// WBStartLogin begins a WB ID login. Pass an existing session's deviceId (from
// WBDeviceIDFromSession) to keep the device identity across re-logins, or "" for
// a fresh one. Open AuthURL(), then feed the callback URL to Complete().
func WBStartLogin(deviceID string) (*WBLoginFlow, error) {
	f, err := wbproto.StartLogin(deviceID)
	if err != nil {
		return nil, err
	}
	return &WBLoginFlow{inner: f}, nil
}

// AuthURL is the WB ID page the app should open for the user to sign in.
func (f *WBLoginFlow) AuthURL() string { return f.inner.AuthURL }

// DeviceID is the device identity this attempt will bind the session to.
func (f *WBLoginFlow) DeviceID() string { return f.inner.DeviceID }

// Complete exchanges the authorization code in the pasted/intercepted callback
// URL for tokens, saves the WB session to sessionPath (0600, app private dir),
// and returns the saved session JSON for the app to keep. sessionPath is the same
// path later passed to StartTransport as "wbSession".
func (f *WBLoginFlow) Complete(callbackURL, sessionPath string) (string, error) {
	if sessionPath == "" {
		return "", fmt.Errorf("wb: need a session path to save to")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := f.inner.Complete(ctx, callbackURL, sessionPath); err != nil {
		return "", err
	}
	b, err := os.ReadFile(sessionPath)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// WBDeviceIDFromSession returns the deviceId stored in a WB session file, or ""
// if the file is absent/unreadable — so a re-login can keep the same device.
func WBDeviceIDFromSession(sessionPath string) string {
	return wbproto.DeviceIDFromSession(sessionPath)
}

// WBResolvePeer resolves the single OTHER member of a personal chat and returns
// their userID, so the app can validate a chat at pick time. chat is "chats/<id>"
// or a bare id.
//
// This is exactly the lookup the minter does on its first Mint, and it is the
// one that rejects a group: minting places a call to a specific peer, and a chat
// with two or twenty other members has no single peer to call. Running it here
// turns "the tunnel fails to connect, minutes later" into "this chat will not
// work, pick another one".
func WBResolvePeer(sessionPath, chat string) (string, error) {
	client, err := wbproto.Load(sessionPath)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return client.ResolvePeer(ctx, chat)
}

// WBListChats returns the account's chats as JSON ({"chatViews":[...]}), so the
// app can let the user pick which personal chat to mint TURN credentials from.
// The chat's id is used as StartTransport's "wbChat" ("chats/<id>").
func WBListChats(sessionPath string) (string, error) {
	client, err := wbproto.Load(sessionPath)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := client.ChatViews(ctx, 200)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}
