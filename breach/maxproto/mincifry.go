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
// Ported from kolibri-net/src/transport/tls.rs. Same PEM.
//
// Provenance of the two anchors in mincifry_ca.pem, kept HERE rather than in
// the .pem itself: the PEM is go:embed'ed, so anything written in it ships
// verbatim inside the client binary, where a note about which app it was taken
// from is both useless at runtime and a free hint to anyone unpacking the APK.
// Go comments never reach the binary.
//
//	Russian Trusted Root CA — CN=Russian Trusted Root CA, serial 1000,
//	  2022-03-01..2032-02-27
//	  SHA-256(DER) D2:6D:2D:02:31:B7:C3:9F:92:CC:73:85:12:BA:54:10:35:19:E4:40:
//	               5D:68:B5:BD:70:3E:97:88:CA:8E:CF:31
//	Russian Trusted Sub CA — CN=Russian Trusted Sub CA, serial 1005,
//	  2024-07-15..2029-07-19, issued by the root above
//	  SHA-256(DER) 21:55:78:50:36:C9:00:DB:B5:F1:BB:2A:15:69:C8:0C:55:59:5B:D6:
//	               BF:94:86:7A:29:BB:DD:BC:7D:88:A3:F2

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
