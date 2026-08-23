package breachmobile

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

// This file is the CLIENT half of the exit management API (server half:
// breach/mgmt). After a one-time SSH install the app keeps only a "server
// handle" — {url, host, port, secret, certSha256} — and drives the exit through
// these calls over pinned self-signed TLS. No SSH root credentials are retained.
//
// Every call takes the handle as a JSON string (gomobile-safe) and an optional
// Protector: pass one when a VpnService tun is up so the mgmt socket bypasses the
// tunnel; pass nil when provisioning/managing with the tun down.

type mgmtHandle struct {
	URL        string `json:"url"` // https://host:port/<secret>
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Secret     string `json:"secret"`
	CertSha256 string `json:"certSha256"` // hex SHA-256 of the server's leaf cert (the pin)
}

// mgmtNameRe mirrors the server's allow-list so the app fails fast on a bad name.
var mgmtNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func parseHandle(handleJSON string) (*mgmtHandle, error) {
	var h mgmtHandle
	if err := json.Unmarshal([]byte(handleJSON), &h); err != nil {
		return nil, fmt.Errorf("bad server handle JSON: %w", err)
	}
	if h.URL == "" || h.CertSha256 == "" {
		return nil, fmt.Errorf("server handle missing url/certSha256")
	}
	return &h, nil
}

// mgmtClient builds an HTTP client that trusts EXACTLY the one self-signed cert
// whose SHA-256 is pinned in the handle — no CA, no hostname check.
func mgmtClient(h *mgmtHandle, p Protector) (*http.Client, error) {
	want, err := hex.DecodeString(h.CertSha256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("bad certSha256 in handle")
	}
	dialer := &net.Dialer{Timeout: 12 * time.Second}
	if p != nil {
		dialer.Control = protectControl(p, func(string) {})
	}
	tr := &http.Transport{
		DialContext:       dialer.DialContext,
		DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{
			// We do NOT trust any CA; correctness comes entirely from the pin below.
			InsecureSkipVerify: true, //nolint:gosec // pinned via VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return fmt.Errorf("mgmt: server presented no certificate")
				}
				sum := sha256.Sum256(rawCerts[0])
				if subtle.ConstantTimeCompare(sum[:], want) != 1 {
					return fmt.Errorf("mgmt: certificate pin mismatch (server not trusted)")
				}
				return nil
			},
		},
	}
	return &http.Client{Timeout: 60 * time.Second, Transport: tr}, nil
}

// scrubURL removes the request URL from a transport error before it can cross
// the gomobile boundary — the URL path carries the management secret, and Go's
// *url.Error embeds the full URL in its message. We keep only the underlying
// cause (host:port + net/TLS reason), which is not secret.
func scrubURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("management request failed: %w", ue.Err)
	}
	return err
}

// mgmtDo performs one request and returns the raw 2xx body, or a Go error
// carrying the server's {"error":...} message on a non-2xx.
func mgmtDo(client *http.Client, method, reqURL string, body any) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, reqURL, rdr)
	if err != nil {
		return nil, scrubURL(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, scrubURL(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return nil, fmt.Errorf("mgmt %s: %s", resp.Status, e.Error)
		}
		return nil, fmt.Errorf("mgmt %s", resp.Status)
	}
	return data, nil
}

// ServerCheck verifies the handle is reachable and the TLS pin matches; returns
// the health JSON. Use it to validate a saved handle before showing "connected".
func ServerCheck(handleJSON string, p Protector) (string, error) {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return "", err
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return "", err
	}
	data, err := mgmtDo(c, http.MethodGet, h.URL+"/health", nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ServerAddClient provisions a new client on the exit and returns its provision
// block (the exit-only ServerConfig JSON: {name, server, wireguard, hysteria2}),
// ready for the app's ConfigImport.fromProvisionBlock. It does NOT contain a MAX
// identity — the app merges that in separately.
func ServerAddClient(handleJSON string, name string, p Protector) (string, error) {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return "", err
	}
	if !mgmtNameRe.MatchString(name) {
		return "", fmt.Errorf("invalid name (allowed: 1-32 of A-Z a-z 0-9 _ -)")
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return "", err
	}
	data, err := mgmtDo(c, http.MethodPost, h.URL+"/clients", map[string]string{"name": name})
	if err != nil {
		return "", err
	}
	var resp struct {
		Config json.RawMessage `json:"config"`
	}
	if err := json.Unmarshal(data, &resp); err != nil || len(resp.Config) == 0 {
		return "", fmt.Errorf("mgmt: add-client returned no config")
	}
	return string(resp.Config), nil
}

// ServerListClients returns the exit's client list JSON (names/addresses, no
// secrets): [{"name","address","wg","hy2"}, ...].
func ServerListClients(handleJSON string, p Protector) (string, error) {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return "", err
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return "", err
	}
	data, err := mgmtDo(c, http.MethodGet, h.URL+"/clients", nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ServerRemoveClient revokes a client by name.
func ServerRemoveClient(handleJSON string, name string, p Protector) error {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return err
	}
	if !mgmtNameRe.MatchString(name) {
		return fmt.Errorf("invalid name")
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return err
	}
	_, err = mgmtDo(c, http.MethodDelete, h.URL+"/clients/"+name, nil)
	return err
}

// ServerStats returns the exit's stats JSON: {"server":{load1,mem,uptime},
// "clients":[{name,address,rx,tx,handshake,online}, ...]}. rx/tx sum this
// client's WireGuard AND Hysteria2 traffic, and online is true when either was
// seen recently; "handshake" is the fresher of the two liveness stamps. Hy2
// numbers require an exit built with the management API (they come from
// sing-box's Clash API); without it Hy2 clients report zeros.
func ServerStats(handleJSON string, p Protector) (string, error) {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return "", err
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return "", err
	}
	data, err := mgmtDo(c, http.MethodGet, h.URL+"/stats", nil)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ServerSetRoutes replaces the exit's SERVER-SIDE routing policy: what the exit
// itself is allowed to reach on behalf of every client (e.g. block ads, or block
// everything except a whitelist). routeJSON is a sing-box "route" object; pass ""
// to clear the policy and let everything through.
//
// This is the exit's policy, not the phone's — the app's own routing rules are a
// separate thing that never leaves the device.
//
// Needs an exit image built after the mgmt API grew this verb; an older one
// answers 404 ("no such endpoint").
func ServerSetRoutes(handleJSON string, routeJSON string, p Protector) error {
	h, err := parseHandle(handleJSON)
	if err != nil {
		return err
	}
	body := map[string]any{"clear": true}
	if routeJSON != "" {
		// A JSON object, not just valid JSON: `null` and a bare array both decode
		// here without error but are not a sing-box "route", and would only fail
		// on the exit, as a sing-box that no longer starts.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal([]byte(routeJSON), &probe); err != nil || probe == nil {
			return fmt.Errorf("route must be a JSON object")
		}
		body = map[string]any{"route": json.RawMessage(routeJSON)}
	}
	c, err := mgmtClient(h, p)
	if err != nil {
		return err
	}
	_, err = mgmtDo(c, http.MethodPut, h.URL+"/routes", body)
	return err
}
