package main

import (
	"bufio"
	"context"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"breach/qtun"
)

// Stream mode on the exit: a QUIC listener bound to loopback that dials out on a
// client's behalf, so a client can offer a local SOCKS5 proxy instead of running
// WireGuard or Hysteria2.
//
// It deliberately reuses the relay unchanged. To the dispatcher this is just a
// third backend address, so clientGroup dials it exactly like it dials
// wireguard-go or sing-box, and every client keeps its own source port — which
// is also what gives QUIC a distinct peer per client.

// tokenSet answers "may this token use the exit?" from the client registry
// ($CONF_DIR/clients, TSV, password in field 4 — the same secret the Hy2 path
// uses). Cached briefly: provisioning rewrites the file, and re-reading it for
// every stream would turn a browser's tab into a burst of syscalls.
type tokenSet struct {
	path string

	mu       sync.Mutex
	tokens   []string
	loadedAt time.Time
}

const tokenTTL = 5 * time.Second

func (t *tokenSet) valid(token string) bool {
	if token == "" {
		return false
	}
	t.mu.Lock()
	if time.Since(t.loadedAt) > tokenTTL {
		t.tokens = readTokens(t.path)
		t.loadedAt = time.Now()
	}
	valid := t.tokens
	t.mu.Unlock()
	return qtun.ConstantTimeTokenMatch(token, valid)
}

func readTokens(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		// No registry means nobody is provisioned; refusing everything is the
		// safe reading, since the alternative is an open proxy.
		return nil
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Split(sc.Text(), "\t")
		if len(fields) >= 4 && fields[3] != "" {
			out = append(out, fields[3])
		}
	}
	return out
}

// startSocksBackend brings up the QUIC listener and returns the address the
// dispatcher should route stream-mode clients to.
func startSocksBackend(listen, clientsPath, stateDir string) (*net.UDPAddr, error) {
	laddr, err := net.ResolveUDPAddr("udp", listen)
	if err != nil {
		return nil, err
	}
	pc, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return nil, err
	}
	pc.SetReadBuffer(8 << 20)
	pc.SetWriteBuffer(8 << 20)

	tlsConf, pin, err := qtun.ServerTLS(
		filepath.Join(stateDir, "qtun-cert.pem"),
		filepath.Join(stateDir, "qtun-key.pem"),
	)
	if err != nil {
		pc.Close()
		return nil, err
	}
	// The pin is the client's only way to verify the exit; publish it where
	// provisioning can pick it up, and log it so an operator can copy it by hand.
	pinPath := filepath.Join(stateDir, "qtun-pin")
	if err := os.WriteFile(pinPath, []byte(pin+"\n"), 0o644); err != nil {
		log.Printf("socks backend: could not write %s: %v", pinPath, err)
	}
	log.Printf("breach-server: stream mode on %s (cert sha256 %s)", listen, pin)

	tokens := &tokenSet{path: clientsPath}
	go func() {
		err := qtun.Serve(context.Background(), pc, tlsConf, qtun.ServerOptions{
			Auth: tokens.valid,
			Logf: log.Printf,
		})
		log.Printf("socks backend stopped: %v", err)
	}()
	return laddr, nil
}
