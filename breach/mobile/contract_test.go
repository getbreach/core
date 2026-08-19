package breachmobile

import (
	"encoding/json"
	"testing"

	"breach/maxproto"
)

// A client that carries NO copy of the MAX constants must still end up fully
// configured: it omits host/port/sdkVersion/clientAppKey/capabilities, takes its
// userAgent from UserAgentJSON, and leaves clientSessionId to BumpClientSession.
// This pins that path end to end — it is what the Android app does.
func TestMinimalClientConfigGetsCoreDefaults(t *testing.T) {
	ua, err := UserAgentJSON(`{"deviceName":"samsung SM-S918B","osVersion":"Android 14","screen":"480dpi 480dpi 1440x3088","timezone":"Europe/Moscow","locale":"ru","deviceLocale":"ru"}`)
	if err != nil {
		t.Fatal(err)
	}
	app := `{"token":"T","deviceId":"D","instanceId":"I","userAgent":` + ua +
		`,"mintMode":"silent","server":"1.2.3.4:48000","wgListen":"127.0.0.1:51821",` +
		`"streams":4,"mints":1,"turnTransport":"auto","keepaliveMs":50,"credCacheDir":"/data/creds"}`

	bumped, err := BumpClientSession(app)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	json.Unmarshal([]byte(bumped), &got)
	if got["clientSessionId"] != float64(2) {
		t.Errorf("clientSessionId = %v, want 2 (login used 1)", got["clientSessionId"])
	}

	c, err := maxproto.ParseConfig([]byte(bumped))
	if err != nil {
		t.Fatal(err)
	}
	if c.Host != maxproto.DefaultHost || c.Port != 443 {
		t.Errorf("host/port = %q/%d, want core defaults", c.Host, c.Port)
	}
	if c.SdkVersion != maxproto.DefaultSdkVersion || c.Capabilities != maxproto.DefaultCapabilities || c.ClientAppKey != maxproto.DefaultClientAppKey {
		t.Errorf("sdk/caps/appKey = %q/%q/%q, want core defaults", c.SdkVersion, c.Capabilities, c.ClientAppKey)
	}
	if c.TurnTransport != "auto" {
		t.Errorf("turnTransport = %q", c.TurnTransport)
	}
	if c.UserAgent.AppVersion != maxproto.DefaultAppVersion || c.UserAgent.BuildNumber != maxproto.DefaultBuildNumber || c.UserAgent.Arch != maxproto.DefaultArch {
		t.Errorf("locked UA fields not core-built: %+v", c.UserAgent)
	}
	if c.UserAgent.DeviceName != "samsung SM-S918B" || c.UserAgent.Screen != "480dpi 480dpi 1440x3088" {
		t.Errorf("cosmetic UA fields lost: %+v", c.UserAgent)
	}
	if _, known := maxproto.DigestsFor(c.UserAgent.AppVersion, c.UserAgent.Arch); !known {
		t.Error("fingerprint digests unknown for the announced version — it would be skipped")
	}
	if c.DNS != "" {
		t.Errorf("dns = %q, want empty (core picks)", c.DNS)
	}
	if c.KeepaliveMs != 50 || c.Streams != 4 || c.Mints != 1 || c.CredCacheDir != "/data/creds" {
		t.Errorf("tunnel settings mangled: %+v", c)
	}
}

// The turnTransport toggle must survive as-is, and anything else be rejected.
func TestTurnTransportAccepted(t *testing.T) {
	base := `{"token":"T","deviceId":"D","turnTransport":%q}`
	for _, v := range []string{"auto", "udp", "tcp"} {
		c, err := maxproto.ParseConfig([]byte(`{"token":"T","deviceId":"D","turnTransport":"` + v + `"}`))
		if err != nil || c.TurnTransport != v {
			t.Errorf("%q -> %v / %v", v, c, err)
		}
	}
	_ = base
	if _, err := maxproto.ParseConfig([]byte(`{"token":"T","deviceId":"D","turnTransport":"quic"}`)); err == nil {
		t.Error("bad turnTransport accepted")
	}
}
