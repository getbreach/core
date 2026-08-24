package main

import (
	"net"
	"os"
	"testing"

	"breach/qtun"
)

// The dispatcher decides a client's backend from one byte, and stream mode
// carries QUIC — the same shape Hysteria2 has. Getting this table wrong sends a
// client's traffic to a backend that will silently drop it.
func TestPickBackendRoutesStreamMode(t *testing.T) {
	wg := &net.UDPAddr{Port: 51820}
	hy2 := &net.UDPAddr{Port: 51821}
	socks := &net.UDPAddr{Port: 51823}

	all := &srv{wgAddr: wg, hy2Addr: hy2, socksAddr: socks}
	for _, tc := range []struct {
		name  string
		first byte
		want  *net.UDPAddr
	}{
		{"stream marker", qtun.RelayMarker, socks},
		{"wireguard handshake init", 0x01, wg},
		{"wireguard transport", 0x04, wg},
		{"quic long header", 0xC0, hy2},
		{"quic short header", 0x40, hy2},
	} {
		if got := all.pickBackend(tc.first); got != tc.want {
			t.Errorf("%s: first=0x%02x -> %v, want %v", tc.name, tc.first, got, tc.want)
		}
	}

	// The marker must not hijack a client on an exit without stream mode: there
	// the byte means nothing and the usual sniffing applies.
	noSocks := &srv{wgAddr: wg, hy2Addr: hy2}
	if got := noSocks.pickBackend(qtun.RelayMarker); got != wg {
		t.Errorf("marker on a non-stream exit -> %v, want the wireguard backend", got)
	}

	// A stream-mode-only exit (no sing-box, no wireguard-go) is the whole point
	// of this mode; every first byte has to land on the one backend there is.
	onlySocks := &srv{socksAddr: socks}
	for _, b := range []byte{qtun.RelayMarker, 0x01, 0x40} {
		if got := onlySocks.pickBackend(b); got != socks {
			t.Errorf("socks-only exit: first=0x%02x -> %v, want socks", b, got)
		}
	}
}

// A token is only valid if it is in the registry; an absent or unreadable
// registry must mean "nobody", never "everybody" — the alternative is an open
// proxy on the internet.
func TestTokenSetFromRegistry(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/clients"
	// Hy2-only row (empty WireGuard fields) plus a full row and a WG-only row.
	if err := writeFile(path, "phoneA\t\t\tPWA\nboth1\tPUB\t10.9.0.2\tPWB\nwgonly\tPUB2\t10.9.0.3\t\n"); err != nil {
		t.Fatal(err)
	}
	ts := &tokenSet{path: path}
	for _, tok := range []string{"PWA", "PWB"} {
		if !ts.valid(tok) {
			t.Errorf("registry token %q rejected", tok)
		}
	}
	for _, tok := range []string{"", "nope", "PUB", "10.9.0.2"} {
		if ts.valid(tok) {
			t.Errorf("token %q accepted", tok)
		}
	}

	missing := &tokenSet{path: dir + "/does-not-exist"}
	if missing.valid("PWA") {
		t.Error("a missing registry must reject everything, not accept it")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
