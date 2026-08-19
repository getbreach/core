package maxproto

import (
	"crypto/x509"
	_ "embed"
	"fmt"
	"sync"
)

// The Russian Trusted Root/Sub CA that api2.oneme.ru chains to. It is absent
// from every OS trust store outside Russia, so without it the TLS handshake to
// that host fails with "unknown authority" — and installing it system-wide is
// not something a tunnel client should ask of its host. Bundling it and adding
// it to a per-connection root pool keeps the trust decision local to this
// dial: it is additive, so every other host still validates against the system
// roots as usual.
//
// Ported from kolibri-net/src/transport/tls.rs. Same PEM, extracted from
// ru.oneme.app v26.23.1 (res/raw/rootca_ssl_rsa2022.cer).

//go:embed mincifry_ca.pem
var mincifryCAPEM []byte

// mincifryPoolCount is how many anchors the bundle carries (root + sub CA).
const mincifryPoolCount = 2

var (
	mincifryOnce sync.Once
	mincifryPool *x509.CertPool
	mincifryErr  error
)

// mincifryRoots returns the system roots plus the bundled Минцифры anchors.
// Additive on purpose: api.oneme.ru chains to a public CA and must keep
// validating normally.
func mincifryRoots() (*x509.CertPool, error) {
	mincifryOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil {
			// Android and scratch containers can lack a readable store; the
			// bundled anchors alone still let api2.oneme.ru work.
			logf("maxproto: system cert pool unavailable (%v), using bundled anchors only", err)
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(mincifryCAPEM) {
			mincifryErr = fmt.Errorf("maxproto: bundled Минцифры CA failed to parse")
			return
		}
		mincifryPool = pool
	})
	return mincifryPool, mincifryErr
}
