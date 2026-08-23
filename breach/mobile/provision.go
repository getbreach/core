package breachmobile

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"breach/deploy"
)

// This file is the one-time SSH provisioner: given fresh-VPS credentials it ships
// deploy/install.sh over SSH, runs it (which installs Docker, pulls the published
// exit image, starts it, and provisions the first client), streams progress, and
// captures two blocks from the output — the client's provision block (an
// exit-only ServerConfig) and the management handle (url + secret + cert pin).
//
// After this, the app keeps only the management handle and drives the exit via
// manage.go (ServerAddClient/…). The SSH credentials are used ONCE and can be
// discarded — nothing here persists them.

// ProvisionProgress streams install output to the UI, line by line. Called on a
// background goroutine; the implementation must be thread-safe.
type ProvisionProgress interface {
	Line(s string)
}

// ProvisionResult is what a successful install yields. All fields are strings so
// the gomobile bind is happy. HandleJSON is empty when the management API was
// disabled for this install.
type ProvisionResult struct {
	ServerConfigJSON   string // provision block: {name, server, wireguard, hysteria2}
	HandleJSON         string // management handle: {url, host, port, secret, certSha256}
	HostKeyFingerprint string // SHA256:… of the server's SSH host key (record to pin next time)
}

type provisionOpts struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	User               string `json:"user"`
	Password           string `json:"password"`
	PrivateKey         string `json:"privateKey"` // PEM
	Passphrase         string `json:"passphrase"` // for an encrypted PrivateKey
	Proto              string `json:"proto"`      // hy2 | both | wg
	RelayPort          int    `json:"relayPort"`
	PublicEndpoint     string `json:"publicEndpoint"` // advertised ip:port; default host:relayPort
	ClientName         string `json:"clientName"`
	LogLevel           string `json:"logLevel"`
	MgmtEnable         *bool  `json:"mgmtEnable"`         // default true
	HostKeyFingerprint string `json:"hostKeyFingerprint"` // if set, require the server to match (else TOFU)
}

// ProvisionServer installs a Breach exit on the box described by optionsJSON.
// p may be nil; pass a Protector when a VpnService tun is up so the SSH socket
// bypasses the tunnel. progress may be nil.
func ProvisionServer(optionsJSON string, p Protector, progress ProvisionProgress) (*ProvisionResult, error) {
	var opt provisionOpts
	if err := json.Unmarshal([]byte(optionsJSON), &opt); err != nil {
		return nil, fmt.Errorf("bad options JSON: %w", err)
	}
	if opt.Host == "" {
		return nil, fmt.Errorf("host is required")
	}
	if opt.Port == 0 {
		opt.Port = 22
	}
	if opt.User == "" {
		opt.User = "root"
	}
	if opt.Proto == "" {
		opt.Proto = "hy2"
	}
	switch opt.Proto {
	case "hy2", "both", "wg":
	default:
		return nil, fmt.Errorf("proto must be hy2|both|wg (got %q)", opt.Proto)
	}
	if opt.RelayPort == 0 {
		opt.RelayPort = 48000
	}
	if opt.ClientName == "" {
		opt.ClientName = "phoneA"
	}
	if !mgmtNameRe.MatchString(opt.ClientName) {
		return nil, fmt.Errorf("invalid clientName (allowed: 1-32 of A-Z a-z 0-9 _ -)")
	}
	if opt.PublicEndpoint == "" {
		opt.PublicEndpoint = fmt.Sprintf("%s:%d", opt.Host, opt.RelayPort)
	}
	mgmtEnable := opt.MgmtEnable == nil || *opt.MgmtEnable

	auths, err := sshAuths(&opt)
	if err != nil {
		return nil, err
	}
	if opt.Password != "" && opt.PrivateKey == "" && opt.HostKeyFingerprint == "" {
		logp(progress, "warning: first connection is trust-on-first-use (host key unverified) and you are using PASSWORD auth — on an untrusted network prefer an SSH key or pass a known hostKeyFingerprint")
	}

	var gotFP string
	hostKey := func(_ string, _ net.Addr, key ssh.PublicKey) error {
		gotFP = ssh.FingerprintSHA256(key)
		if opt.HostKeyFingerprint != "" && opt.HostKeyFingerprint != gotFP {
			return fmt.Errorf("host key mismatch: server presented %s, expected %s", gotFP, opt.HostKeyFingerprint)
		}
		return nil // trust-on-first-use: accept and report the fingerprint to pin later
	}

	cfg := &ssh.ClientConfig{
		User:            opt.User,
		Auth:            auths,
		HostKeyCallback: hostKey,
		Timeout:         20 * time.Second,
	}

	addr := net.JoinHostPort(opt.Host, fmt.Sprintf("%d", opt.Port))
	logp(progress, "connecting to "+addr+" …")

	d := net.Dialer{Timeout: 20 * time.Second}
	if p != nil {
		d.Control = protectControl(p, func(string) {})
	}
	netConn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	sshConn, chans, reqs, err := ssh.NewClientConn(netConn, addr, cfg)
	if err != nil {
		netConn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()
	logp(progress, "authenticated; host key "+gotFP)

	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh session: %w", err)
	}
	defer sess.Close()

	// Feed install.sh on stdin; the env prefix parameterizes it. Values are
	// single-quoted so nothing in them can break out of the command.
	env := strings.Join([]string{
		"PROTO=" + shQuote(opt.Proto),
		"PUBLIC_ENDPOINT=" + shQuote(opt.PublicEndpoint),
		fmt.Sprintf("RELAY_PORT=%d", opt.RelayPort),
		"MGMT_ENABLE=" + boolEnv(mgmtEnable),
		"CLIENT=" + shQuote(opt.ClientName),
		"LOG_LEVEL=" + shQuote(orDefault(opt.LogLevel, "info")),
	}, " ")
	sess.Stdin = strings.NewReader(deploy.InstallSh)

	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := sess.StderrPipe()
	if err != nil {
		return nil, err
	}

	var outBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); streamLines(stdout, progress, &outBuf) }()
	go func() { defer wg.Done(); streamLines(stderr, progress, nil) }()

	logp(progress, "installing exit (this can take a couple of minutes) …")
	runErr := sess.Run(env + " sh -s")
	if runErr != nil {
		// If the remote refused the exec request the channel never reaches EOF, so
		// the reader goroutines would block forever and wg.Wait() would deadlock.
		// Closing the session forces the readers to unblock. Idempotent with the
		// deferred Close above.
		sess.Close()
	}
	wg.Wait()

	out := outBuf.String()
	block := extractBetween(out, "===BREACH-CLIENT-CONFIG-BEGIN===", "===BREACH-CLIENT-CONFIG-END===")
	if block == "" || !json.Valid([]byte(block)) {
		if runErr != nil {
			return nil, fmt.Errorf("install failed: %v\n%s", runErr, tail(out, 800))
		}
		return nil, fmt.Errorf("install produced no client config block\n%s", tail(out, 800))
	}

	res := &ProvisionResult{ServerConfigJSON: block, HostKeyFingerprint: gotFP}
	if mgmtEnable {
		if h := extractBetween(out, "===BREACH-MGMT-BEGIN===", "===BREACH-MGMT-END==="); h != "" && json.Valid([]byte(h)) {
			res.HandleJSON = h
		} else {
			logp(progress, "warning: no management handle in output — exit is up but only SSH-manageable")
		}
	}
	if runErr != nil {
		// A non-zero exit after we already have a valid client block is usually a
		// benign late step; surface it but don't fail the provision.
		logp(progress, "note: installer exited non-zero ("+runErr.Error()+") but config was produced")
	}
	logp(progress, "done — exit is live")
	return res, nil
}

func sshAuths(opt *provisionOpts) ([]ssh.AuthMethod, error) {
	var auths []ssh.AuthMethod
	if opt.PrivateKey != "" {
		var signer ssh.Signer
		var err error
		if opt.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(opt.PrivateKey), []byte(opt.Passphrase))
		} else {
			signer, err = ssh.ParsePrivateKey([]byte(opt.PrivateKey))
		}
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}
	if opt.Password != "" {
		auths = append(auths, ssh.Password(opt.Password))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("no auth: provide password or privateKey")
	}
	return auths, nil
}

// secretBlocks are the sentinel-delimited payloads the installer prints: the
// client's provision block (WireGuard/Hy2 keys) and the management handle (an
// admin-grade secret). They are meant to be PARSED, not read — and the progress
// stream goes straight to a UI log that a user will screenshot when something
// goes wrong. So they are captured for parsing and withheld from progress.
var secretBlocks = [...][2]string{
	{"===BREACH-CLIENT-CONFIG-BEGIN===", "===BREACH-CLIENT-CONFIG-END==="},
	{"===BREACH-MGMT-BEGIN===", "===BREACH-MGMT-END==="},
}

func streamLines(r io.Reader, progress ProvisionProgress, capture *bytes.Buffer) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	// Non-empty while inside a secret block; holds the terminator to watch for.
	var suppressUntil string
	for sc.Scan() {
		line := sc.Text()
		if capture != nil {
			capture.WriteString(line)
			capture.WriteByte('\n')
		}
		if progress == nil {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if suppressUntil != "" {
			if trimmed == suppressUntil {
				suppressUntil = ""
				progress.Line("(withheld — see the app)")
			}
			continue
		}
		if b := blockStarting(trimmed); b != nil {
			suppressUntil = b[1]
			continue
		}
		progress.Line(line)
	}
}

func blockStarting(trimmed string) *[2]string {
	for i := range secretBlocks {
		if trimmed == secretBlocks[i][0] {
			return &secretBlocks[i]
		}
	}
	return nil
}

func extractBetween(s, begin, end string) string {
	i := strings.Index(s, begin)
	if i < 0 {
		return ""
	}
	rest := s[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return ""
	}
	return strings.TrimSpace(rest[:j])
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func boolEnv(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func logp(progress ProvisionProgress, s string) {
	if progress != nil {
		progress.Line(s)
	}
}
