package maxproto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
)

// Anti-spoof fingerprint, ported from kolibri-net/src/auth.rs. MAX sends it as
// `mode` in authRequest (opcode 17) and `chatCacheFingerprint` in login
// (opcode 19); callsSeed comes from the sessionInit (opcode 6) response.
//
// The three inputs are hashes of the real client's APK: its signing
// certificate, its dex, and its native library. The certificate hash is the
// same for every build, but the dex hash changes with each release and the .so
// hash with each release AND ABI — so a fingerprint is only coherent when it is
// built from the digests of exactly the appVersion and arch that userAgent
// claims. Sending a fingerprint that contradicts the announced version is worse
// than sending none, which is why the digests live in a table keyed by both.
//
// Digest source: https://hashes.pymax.org/versions.json
//   signature = certificate_meta_sha256   dex = dex_meta_sha256
//   so        = so_meta_sha256[arch]

// DefaultAppVersion is the MAX build this package impersonates by default;
// DefaultBuildNumber is its buildNumber, which userAgent must report to match.
const (
	DefaultAppVersion  = "26.23.2"
	DefaultBuildNumber = 6779
	DefaultArch        = "arm64-v8a"
)

// FingerprintSize is the length of a fingerprint: three concatenated SHA-256.
const FingerprintSize = 96

// signatureDigestHex is the APK signing certificate hash. Identical across
// every published version, so it is not part of the per-version table.
const signatureDigestHex = "1684414033eb263e2c615f8b7df5ed8793850a07656304997fbf07e9e21e1e93"

// apkBuild is one release: the dex digest plus a .so digest per ABI.
type apkBuild struct {
	buildNumber int
	dex         string
	so          map[string]string
}

// apkBuilds holds the releases this package can impersonate. Adding one is a
// copy of the matching entry from the digest list above — no other change.
var apkBuilds = map[string]apkBuild{
	"26.23.2": {
		buildNumber: 6779,
		dex:         "38cff46f392dc1734c308be011c2f0d8da152a390b41063dbb2c913e3032f4b3",
		so: map[string]string{
			"arm64-v8a":   "634ecc42b246784d975f180b4fecf903df235cdf0476da47163a85630eb1a6a8",
			"armeabi-v7a": "042220bdd481a280d2c1f4f6827f0e4fab7bca61e5af0f6035a0d191aed1350c",
			"x86":         "deffe34d2a9d83584e02cbb3f22ba5a6dbe1b065dbc8a8ea8ca908dae865c5f6",
			"x86_64":      "251b88c27a1c055f27adc110e44a75a1c60408b0d5e20e3844f816aa227212a3",
		},
	},
}

// Digests is the APK digest triple a fingerprint is built from.
type Digests struct {
	Signature []byte
	Dex       []byte
	So        []byte
}

// DefaultDigests are the digests for DefaultAppVersion on DefaultArch.
func DefaultDigests() Digests {
	d, ok := DigestsFor(DefaultAppVersion, DefaultArch)
	if !ok {
		// Unreachable: TestDefaultBuildIsInTheTable pins this.
		panic("maxproto: default app version missing from apkBuilds")
	}
	return d
}

// DigestsFor returns the digests for one appVersion/arch pair. ok is false when
// the table has no entry, which means a fingerprint for that combination would
// be a guess.
func DigestsFor(appVersion, arch string) (Digests, bool) {
	build, ok := apkBuilds[appVersion]
	if !ok {
		return Digests{}, false
	}
	soHex, ok := build.so[arch]
	if !ok {
		return Digests{}, false
	}
	return Digests{
		Signature: mustHex(signatureDigestHex),
		Dex:       mustHex(build.dex),
		So:        mustHex(soHex),
	}, true
}

// BuildNumberFor returns the buildNumber userAgent must report for appVersion.
func BuildNumberFor(appVersion string) (int, bool) {
	build, ok := apkBuilds[appVersion]
	return build.buildNumber, ok
}

// ChatCacheFingerprint builds the 96-byte fingerprint: three SHA-256 over
// `digest || int64BE(callsSeed) || utf8(deviceID)`, concatenated in
// signature / dex / so order.
func ChatCacheFingerprint(signatureDigest, dexDigest, soDigest []byte, callsSeed int64, deviceID string) []byte {
	var seed [8]byte
	binary.BigEndian.PutUint64(seed[:], uint64(callsSeed))
	device := []byte(deviceID)

	out := make([]byte, 0, FingerprintSize)
	for _, digest := range [][]byte{signatureDigest, dexDigest, soDigest} {
		h := sha256.New()
		h.Write(digest)
		h.Write(seed[:])
		h.Write(device)
		out = h.Sum(out)
	}
	return out
}

// Fingerprint is ChatCacheFingerprint with the default build's digests.
func Fingerprint(callsSeed int64, deviceID string) []byte {
	d := DefaultDigests()
	return ChatCacheFingerprint(d.Signature, d.Dex, d.So, callsSeed, deviceID)
}

// fingerprintFor builds the fingerprint matching what cfg's userAgent claims.
// An unknown appVersion/arch falls back to the default build rather than
// failing — an unrecognised combination should not block authentication — but
// it says so, because the resulting fingerprint contradicts the announced
// version and that is worth knowing before MAX starts checking.
func fingerprintFor(cfg *Config, callsSeed int64) []byte {
	arch := cfg.UserAgent.Arch
	if arch == "" {
		arch = DefaultArch
	}
	d, ok := DigestsFor(cfg.UserAgent.AppVersion, arch)
	if !ok {
		logf("maxproto: no APK digests for appVersion %q arch %q; using %s/%s — "+
			"the fingerprint will not match the announced version",
			cfg.UserAgent.AppVersion, arch, DefaultAppVersion, DefaultArch)
		d = DefaultDigests()
	}
	return ChatCacheFingerprint(d.Signature, d.Dex, d.So, callsSeed, cfg.DeviceID)
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("maxproto: bad digest constant: " + err.Error())
	}
	return b
}
