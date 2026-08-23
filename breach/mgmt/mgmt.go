//go:build mgmt

// Package mgmt is the breach-exit MANAGEMENT API — a small, fixed-verb HTTPS
// service that lets the app manage a provisioned exit (add / list / remove
// clients, read stats) WITHOUT keeping SSH root credentials around after the
// one-time install.
//
// It is deliberately NOT a remote shell. It exposes a closed set of verbs, each
// of which shells out to the SAME /usr/local/bin tools the operator would run by
// hand (provision-client, list-clients, remove-client, stats). A leaked secret
// can therefore create or delete a VPN user, or read load — but can never run an
// arbitrary command or gain root. Client names are strictly allow-listed before
// they reach a tool, both to prevent argument abuse and because a tab/newline in
// a name would corrupt the TSV client registry.
//
// Guarding: a per-server high-entropy secret carried in the URL path
// (constant-time compared) over pinned self-signed TLS. The app learns the
// secret + the cert's SHA-256 once, from the handle block this daemon prints at
// startup, and pins the certificate thereafter (there is no CA).
//
// This whole package is behind the `mgmt` build tag: an exit image built with
// --build-arg MGMT=0 does not compile or ship it at all.
package mgmt

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Options configures the daemon. The entrypoint passes these as flags.
type Options struct {
	Listen        string // TCP listen address for the HTTPS API, e.g. ":48000"
	ConfDir       string // state dir: secret, cert, and the client registry the tools use
	BinDir        string // dir holding provision-client/list-clients/remove-client/stats
	AdvertiseHost string // public host/IP embedded in the handle URL the app connects to
}

// validName gates every client name before it reaches a shell tool or the TSV
// registry. No tabs, no newlines, no shell metacharacters — just a short slug.
var validName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// execTimeout bounds a single tool invocation. Provisioning reloads sing-box, so
// give it room, but never hang a request forever.
const execTimeout = 45 * time.Second

// Run loads (or creates) the secret + self-signed cert, prints the handle block,
// and serves the API until the process is killed. It blocks.
func Run(opt Options) error {
	if opt.ConfDir == "" {
		opt.ConfDir = "/etc/breach"
	}
	if opt.BinDir == "" {
		opt.BinDir = "/usr/local/bin"
	}
	if opt.Listen == "" {
		opt.Listen = ":48000"
	}

	secret, err := loadOrCreateSecret(filepath.Join(opt.ConfDir, "mgmt-secret"))
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	cert, leafDER, err := loadOrCreateCert(
		filepath.Join(opt.ConfDir, "mgmt-cert.pem"),
		filepath.Join(opt.ConfDir, "mgmt-key.pem"),
	)
	if err != nil {
		return fmt.Errorf("cert: %w", err)
	}
	certSha := sha256.Sum256(leafDER)

	port, err := listenPort(opt.Listen)
	if err != nil {
		return err
	}
	host := opt.AdvertiseHost
	if host == "" {
		host = "YOUR_VPS_IP"
	}

	if err := writeHandle(opt.ConfDir, host, port, secret, certSha[:]); err != nil {
		// Non-fatal: the block is still printed below; the file is a convenience
		// for recovering the handle via `docker exec ... cat mgmt.json`.
		log.Printf("breach-mgmt: could not persist handle: %v", err)
	}
	printHandle(host, port, secret, certSha[:])

	s := &server{secret: secret, confDir: opt.ConfDir, binDir: opt.BinDir}
	srv := &http.Server{
		Addr:              opt.Listen,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		// No blanket ReadTimeout/WriteTimeout: a request can legitimately queue
		// behind the serialization mutex, so ServeHTTP sets a per-request deadline
		// measured from when it actually starts (see below).
		IdleTimeout: 60 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		},
		ErrorLog: log.New(os.Stderr, "breach-mgmt http: ", 0),
	}
	log.Printf("breach-mgmt: listening on %s (TCP), state=%s", opt.Listen, opt.ConfDir)
	// Certs come from TLSConfig, so the file args are empty.
	return srv.ListenAndServeTLS("", "")
}

// server routes authenticated requests and serializes the mutating tool calls —
// the shell tools have NO file locking, so two concurrent provisions could pick
// the same IP or a provision could race a remove. One mutex around every tool
// call is plenty: this API is human-paced.
type server struct {
	secret  string
	confDir string
	binDir  string
	mu      sync.Mutex
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Bound the read side generously; the write deadline is (re)set fresh right
	// before each response is written (writeJSON / passthroughJSON), AFTER any
	// queueing on s.mu — so a request that waited on the mutex still gets a full
	// write budget instead of blowing a fixed server-wide deadline mid-response.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(execTimeout + 15*time.Second))

	// The secret is the first path segment; everything hangs off /<secret>/…
	seg, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if subtle.ConstantTimeCompare([]byte(seg), []byte(s.secret)) != 1 {
		// Don't reveal whether the path or the secret was wrong.
		http.NotFound(w, r)
		return
	}

	switch {
	case rest == "health" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "service": "breach-mgmt", "version": 1})
	case rest == "clients" && r.Method == http.MethodGet:
		s.handleList(w, r)
	case rest == "clients" && r.Method == http.MethodPost:
		s.handleAdd(w, r)
	case rest == "stats" && r.Method == http.MethodGet:
		s.handleStats(w, r)
	case strings.HasPrefix(rest, "clients/") && r.Method == http.MethodDelete:
		s.handleRemove(w, r, strings.TrimPrefix(rest, "clients/"))
	default:
		writeErr(w, http.StatusNotFound, "no such endpoint")
	}
}

// handleAdd provisions a new client and returns its provision block (the
// exit-only ServerConfig the app merges with a MAX identity).
func (s *server) handleAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad JSON body")
		return
	}
	name := strings.TrimSpace(body.Name)
	if !validName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name (allowed: 1-32 of A-Z a-z 0-9 _ -)")
		return
	}

	s.mu.Lock()
	stdout, stderr, err := s.run("provision-client", name)
	s.mu.Unlock()
	if err != nil {
		msg := firstLine(stderr)
		if strings.Contains(stderr, "already exists") {
			writeErr(w, http.StatusConflict, msg)
			return
		}
		writeErr(w, http.StatusInternalServerError, "provision failed: "+msg)
		return
	}
	block := extractBlock(stdout, "===BREACH-CLIENT-CONFIG-BEGIN===", "===BREACH-CLIENT-CONFIG-END===")
	if block == "" || !json.Valid([]byte(block)) {
		writeErr(w, http.StatusInternalServerError, "provision produced no config block")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": json.RawMessage(block)})
}

// handleRemove revokes a client. `name` is the trailing path segment.
func (s *server) handleRemove(w http.ResponseWriter, r *http.Request, name string) {
	name = strings.TrimSpace(name)
	if !validName.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid name")
		return
	}
	s.mu.Lock()
	_, stderr, err := s.run("remove-client", name)
	s.mu.Unlock()
	if err != nil {
		if strings.Contains(stderr, "no such client") {
			writeErr(w, http.StatusNotFound, "no such client: "+name)
			return
		}
		writeErr(w, http.StatusInternalServerError, "remove failed: "+firstLine(stderr))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"removed": name})
}

// handleList / handleStats pass the tools' single-line JSON straight through.
func (s *server) handleList(w http.ResponseWriter, r *http.Request) {
	s.passthroughJSON(w, "list-clients")
}

func (s *server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.passthroughJSON(w, "stats")
}

func (s *server) passthroughJSON(w http.ResponseWriter, tool string) {
	s.mu.Lock()
	stdout, stderr, err := s.run(tool)
	s.mu.Unlock()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, tool+" failed: "+firstLine(stderr))
		return
	}
	out := strings.TrimSpace(stdout)
	if !json.Valid([]byte(out)) {
		writeErr(w, http.StatusInternalServerError, tool+" produced invalid JSON")
		return
	}
	freshWriteDeadline(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(out))
}

// run executes one bare-name tool from binDir with CONF_DIR set. Args are passed
// as a real argv (no shell), so a validated name cannot inject anything.
func (s *server) run(tool string, args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(s.binDir, tool), args...)
	cmd.Env = append(os.Environ(), "CONF_DIR="+s.confDir)
	var so, se bytes.Buffer
	cmd.Stdout = &so
	cmd.Stderr = &se
	err = cmd.Run()
	return so.String(), se.String(), err
}

// ---- helpers ---------------------------------------------------------------

func extractBlock(out, begin, end string) string {
	i := strings.Index(out, begin)
	if i < 0 {
		return ""
	}
	rest := out[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return "unknown error"
	}
	return s
}

// freshWriteDeadline resets the connection's write deadline to now+15s, so the
// response write always has its full budget regardless of prior mutex queueing.
func freshWriteDeadline(w http.ResponseWriter) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(15 * time.Second))
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	freshWriteDeadline(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func listenPort(addr string) (int, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("bad -listen %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return 0, fmt.Errorf("bad -listen port %q", portStr)
	}
	return port, nil
}

func loadOrCreateSecret(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s, nil
		}
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	s := base64.RawURLEncoding.EncodeToString(raw)
	if err := os.WriteFile(path, []byte(s+"\n"), 0o600); err != nil {
		return "", err
	}
	return s, nil
}

// loadOrCreateCert returns the TLS certificate and the leaf's DER bytes (what the
// app pins by SHA-256). A self-signed P-256 cert, persisted so the pin is stable
// across restarts.
func loadOrCreateCert(certPath, keyPath string) (tls.Certificate, []byte, error) {
	if _, err := os.Stat(certPath); err == nil {
		// The cert already exists → it MUST load. Failing closed here is deliberate:
		// silently regenerating would rotate the SHA-256 that every provisioned app
		// has pinned, breaking them all with an opaque "pin mismatch". Force an
		// explicit, visible decision instead.
		cert, lerr := tls.LoadX509KeyPair(certPath, keyPath)
		if lerr != nil || len(cert.Certificate) == 0 {
			return tls.Certificate{}, nil, fmt.Errorf(
				"existing mgmt cert at %s could not be loaded (%v); refusing to overwrite the pinned cert — delete mgmt-cert.pem AND mgmt-key.pem to intentionally rotate (every provisioned app must then re-provision)",
				certPath, lerr)
		}
		return cert, cert.Certificate[0], nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "breach-mgmt"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, nil, err
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	return cert, der, nil
}

// writeHandle persists the connection handle (incl. secret) 0600 for recovery
// via `docker exec breach-exit cat /etc/breach/mgmt.json`.
func writeHandle(confDir, host string, port int, secret string, certSha []byte) error {
	b, err := json.Marshal(handleObj(host, port, secret, certSha))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(confDir, "mgmt.json"), b, 0o600)
}

// printHandle emits the handle between sentinel lines so install.sh (over SSH)
// can slice it out of the container logs, exactly like the client-config block.
func printHandle(host string, port int, secret string, certSha []byte) {
	b, _ := json.Marshal(handleObj(host, port, secret, certSha))
	fmt.Println("===BREACH-MGMT-BEGIN===")
	fmt.Println(string(b))
	fmt.Println("===BREACH-MGMT-END===")
}

func handleObj(host string, port int, secret string, certSha []byte) map[string]any {
	return map[string]any{
		"url":        fmt.Sprintf("https://%s:%d/%s", host, port, secret),
		"host":       host,
		"port":       port,
		"secret":     secret,
		"certSha256": hex.EncodeToString(certSha),
	}
}
