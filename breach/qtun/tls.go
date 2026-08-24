package qtun

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// TLS here is QUIC's own, not a second layer: QUIC cannot run without it. There
// is no CA anywhere in this system, so the exit keeps one self-signed identity
// and the client pins its SHA-256 — the same shape the management API uses.
//
// The pin is what makes the exit's identity verifiable. Without one the client
// still gets confidentiality, but an attacker able to sit inside the outer DTLS
// (which is itself unauthenticated today) could impersonate the exit and collect
// tokens. So an unpinned client warns, loudly, rather than pretending.

// ServerTLS loads the exit's identity from certPath/keyPath, creating it on
// first use. It returns the config plus the SHA-256 of the leaf in hex — that
// string is what a client pins.
func ServerTLS(certPath, keyPath string) (*tls.Config, string, error) {
	if _, err := os.Stat(certPath); err == nil {
		// Present but unloadable is a hard error, never a silent regeneration:
		// rotating the identity would break every client that pinned the old one.
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil || len(cert.Certificate) == 0 {
			return nil, "", fmt.Errorf("qtun: existing cert at %s is unusable (%v); refusing to rotate the pin — delete both files to do that deliberately", certPath, err)
		}
		sum := sha256.Sum256(cert.Certificate[0])
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, hex.EncodeToString(sum[:]), nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "breach-qtun"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if certPath != "" {
		if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
			return nil, "", err
		}
		if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
			return nil, "", err
		}
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(der)
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}, hex.EncodeToString(sum[:]), nil
}

// ClientTLS builds the client side. certSha256 is the hex SHA-256 of the exit's
// leaf; empty means "accept whatever is presented", which is only sane on a
// trusted path — callers should warn.
func ClientTLS(certSha256 string) (*tls.Config, error) {
	conf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// Verification is done by the pin below, not by any CA.
		InsecureSkipVerify: true, //nolint:gosec // pinned in VerifyPeerCertificate
	}
	if certSha256 == "" {
		return conf, nil
	}
	want, err := hex.DecodeString(certSha256)
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("qtun: bad certSha256 %q", certSha256)
	}
	conf.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return fmt.Errorf("qtun: exit presented no certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		if subtle.ConstantTimeCompare(sum[:], want) != 1 {
			return fmt.Errorf("qtun: exit certificate does not match the pin")
		}
		return nil
	}
	return conf, nil
}
