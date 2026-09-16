package main

import (
	"bufio"
	"path/filepath"
	"strings"
	"testing"

	"breach/maxproto"
)

// The wizard's whole point is producing a config the normal run path can load.
// These tests pin that round-trip so a change to either side can't silently
// break "set up, then run".

func TestMaxConfigRoundTrip(t *testing.T) {
	cfg, err := maxproto.NewAuthConfig("", nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Token = "tok" // ParseConfig requires token+deviceId
	cfg.Server = "1.2.3.4:48000"
	cfg.WGListen = "127.0.0.1:51821"
	cfg.Streams, cfg.Mints = 6, 3
	cfg.Socks = "127.0.0.1:1080"
	cfg.SocksToken, cfg.SocksPin = "pw", "pin"

	path := filepath.Join(t.TempDir(), "config.json")
	if err := writeMaxConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	if p := detectProvider(path); p != "max" {
		t.Fatalf("detectProvider = %q, want max", p)
	}
	got, err := maxproto.LoadConfig(path)
	if err != nil {
		t.Fatalf("run path cannot load wizard config: %v", err)
	}
	if got.Server != cfg.Server || got.Streams != 6 || got.Mints != 3 {
		t.Errorf("tunnel fields lost: %+v", got)
	}
	if got.Socks != cfg.Socks || got.SocksToken != "pw" || got.SocksPin != "pin" {
		t.Errorf("socks fields lost: socks=%q token=%q pin=%q", got.Socks, got.SocksToken, got.SocksPin)
	}
}

func TestWBConfigRoundTrip(t *testing.T) {
	wc := wbConfig{
		Provider: "wb", Server: "9.9.9.9:48000", WGListen: "127.0.0.1:5555",
		Streams: 5, Mints: 2, WBSession: "/tmp/s.json", WBChat: "chats/42",
		WBCallType: "AUDIO", Socks: "127.0.0.1:1080", SocksToken: "pw",
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if err := writeJSONConfig(path, wc); err != nil {
		t.Fatal(err)
	}
	if p := detectProvider(path); p != "wb" {
		t.Fatalf("detectProvider = %q, want wb", p)
	}
	got, err := loadWBConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != wc {
		t.Errorf("wb round-trip mismatch:\n got %+v\nwant %+v", got, wc)
	}
}

func TestPromptHelpers(t *testing.T) {
	// blank -> default; then explicit values.
	r := bufio.NewReader(strings.NewReader("\n7\nnope\n\ny\n"))
	if v := ask(r, "x", "def"); v != "def" {
		t.Errorf("ask default = %q", v)
	}
	if n := askInt(r, "n", 4); n != 7 {
		t.Errorf("askInt = %d, want 7", n)
	}
	// "nope" is not a number -> reprompt, blank -> default 4.
	if n := askInt(r, "n", 4); n != 4 {
		t.Errorf("askInt fallback = %d, want 4", n)
	}
	if !askYesNo(r, "go?", false) {
		t.Errorf("askYesNo(y) = false")
	}
}
