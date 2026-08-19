package maxproto

import (
	"os"
	"path/filepath"
	"testing"
)

func sampleSession() *StoredSession {
	cfg, _ := NewAuthConfig("", &Identity{DeviceID: "a1b2c3d4e5f60718", InstanceID: "inst-1"})
	cfg.Token = "login-token"
	return SessionFromConfig(cfg, 987654321, &Profile{UserID: 987654321, Phone: "+79991234567", Name: "Тест"})
}

func TestSessionRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "session.json")
	orig := sampleSession()

	if err := SaveSession(path, orig); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	// The parent dir must be private, and the file too.
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir perm = %v (err %v), want 0700", fiMode(fi), err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("file perm = %v (err %v), want 0600", fiMode(fi), err)
	}

	got, err := LoadSession(path)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if got.Token != orig.Token || got.AccountID != orig.AccountID {
		t.Errorf("token/account not preserved: %+v", got)
	}
	if got.Identity != orig.Identity {
		t.Errorf("identity not preserved: %+v want %+v", got.Identity, orig.Identity)
	}
	if got.UserAgent != orig.UserAgent {
		t.Errorf("userAgent not preserved")
	}
	if got.SavedAt.IsZero() {
		t.Error("SavedAt not stamped")
	}
}

// The whole point of persistence: a restored session rebuilds a config that
// mints with the SAME identity and token, so MAX still honours the token.
func TestSessionConfigReproducesIdentity(t *testing.T) {
	sess := sampleSession()
	cfg := sess.Config("")

	if cfg.Host != DefaultHost {
		t.Errorf("host = %q, want %q", cfg.Host, DefaultHost)
	}
	if cfg.Token != sess.Token {
		t.Errorf("token = %q", cfg.Token)
	}
	if cfg.DeviceID != sess.Identity.DeviceID || cfg.InstanceID != sess.Identity.InstanceID {
		t.Errorf("identity not restored: device=%q instance=%q", cfg.DeviceID, cfg.InstanceID)
	}
	if cfg.SdkVersion != sess.SdkVersion || cfg.ClientAppKey != sess.ClientAppKey || cfg.Capabilities != sess.Capabilities {
		t.Errorf("mint knobs not restored: %q %q %q", cfg.SdkVersion, cfg.ClientAppKey, cfg.Capabilities)
	}
	// The restored config must satisfy the same validation a hand-written one does.
	if cfg.Token == "" || cfg.DeviceID == "" {
		t.Fatal("restored config missing token/deviceId")
	}

	// The fingerprint depends only on deviceId + callsSeed, so a restored config
	// must produce the same fingerprint the original identity would.
	if got, want := fingerprintFor(cfg, 42), Fingerprint(42, sess.Identity.DeviceID); string(got) != string(want) {
		t.Error("restored config yields a different fingerprint")
	}
}

// A missing file is "no session yet", not an error — callers fall back to login.
func TestLoadSessionMissingIsNotError(t *testing.T) {
	got, err := LoadSession(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Errorf("missing file should not error, got %v", err)
	}
	if got != nil {
		t.Errorf("missing file should return nil session, got %+v", got)
	}
}

// A file that exists but has no usable token/identity must error, not silently
// hand back a session that cannot log in.
func TestLoadSessionRejectsIncomplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte(`{"accountId":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSession(path); err == nil {
		t.Error("a tokenless session file should error")
	}
}

func TestSaveSessionRejectsTokenless(t *testing.T) {
	if err := SaveSession(filepath.Join(t.TempDir(), "x.json"), &StoredSession{AccountID: 1}); err == nil {
		t.Error("saving a session with no token should error")
	}
}

// SaveSession writes atomically; a leftover .tmp must not remain on success.
func TestSaveSessionIsAtomic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.json")
	if err := SaveSession(path, sampleSession()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Error(".tmp file left behind after a successful save")
	}
}

func fiMode(fi os.FileInfo) os.FileMode {
	if fi == nil {
		return 0
	}
	return fi.Mode().Perm()
}
