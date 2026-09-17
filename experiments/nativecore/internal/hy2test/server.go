// Package hy2test starts a real, pinned Hy2 server for local integration tests.
// Its unrestricted exit is deliberately test-only, never a production server.
package hy2test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"net"
	"testing"
	"time"

	"breach-nativecore/hy2"
	"github.com/apernet/hysteria/core/v2/server"
)

type auth struct{}

func (auth) Authenticate(_ net.Addr, password string, _ uint64) (bool, string) {
	return password == "test-password", "test-user"
}

func Server(t testing.TB) (net.Addr, hy2.TLSOptions) {
	s := NewServer(t)
	return s.Addr, s.TLS
}

// Restartable retains its certificate and UDP address across server restarts.
// Start and Stop are controlled by the test goroutine.
type Restartable struct {
	t    testing.TB
	Addr net.Addr
	TLS  hy2.TLSOptions
	cert tls.Certificate
	stop func()
}

func NewServer(t testing.TB) *Restartable {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"hy2.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pin := sha256.Sum256(der)
	s := &Restartable{t: t, cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, TLS: hy2.TLSOptions{ServerName: "hy2.test", CertSHA256: hex.EncodeToString(pin[:])}}
	s.Start()
	t.Cleanup(s.Stop)
	return s
}

func (r *Restartable) Start() {
	r.t.Helper()
	address := "127.0.0.1:0"
	if r.Addr != nil {
		address = r.Addr.String()
	}
	pc, err := net.ListenPacket("udp", address)
	if err != nil {
		r.t.Fatal(err)
	}
	s, err := server.NewServer(&server.Config{Conn: pc, Authenticator: auth{}, TLSConfig: server.TLSConfig{Certificates: []tls.Certificate{r.cert}}, QUICConfig: server.QUICConfig{DisablePathMTUDiscovery: true}})
	if err != nil {
		pc.Close()
		r.t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = s.Serve() }()
	r.Addr = pc.LocalAddr()
	r.stop = func() { s.Close(); pc.Close(); <-done }
}

func (r *Restartable) Stop() {
	if r.stop != nil {
		r.stop()
		r.stop = nil
	}
}

func Client(t testing.TB) *hy2.Client {
	t.Helper()
	addr, tls := Server(t)
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := hy2.Dial(ctx, pc, addr, "test-password", tls)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}
