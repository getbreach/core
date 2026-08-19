package maxproto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Golden vectors pin the exact bytes so this port and kolibri-net cannot drift.
// kolibri's own tests only assert length/determinism; these were derived
// independently from the spec in kolibri-net/src/auth.rs and then confirmed
// byte-for-byte against the Rust implementation.
func TestFingerprintGoldenVectors(t *testing.T) {
	def := DefaultDigests()
	v7, ok := DigestsFor(DefaultAppVersion, "armeabi-v7a")
	if !ok {
		t.Fatal("armeabi-v7a missing from the default build")
	}

	cases := []struct {
		name      string
		digests   Digests
		callsSeed int64
		deviceID  string
		want      string
	}{
		{
			name: "default build, arm64-v8a", digests: def,
			callsSeed: 12345, deviceID: "dev-abc",
			want: "df33c9ed0a449aade45c394bdbc8d9798679131a4061cee3e408748c1f163dd7" +
				"a02a62847bef31d65a0c3e2afaf8bf5413e610a2a4369f55d2f36ef4beaf7251" +
				"d782c62838abbba15db05ae5b029abc4f09d1ffd291243d526de8016f8440f64",
		},
		{
			// Negative seed: the spec says int64 big-endian, so sign matters.
			name: "negative calls seed", digests: def,
			callsSeed: -1, deviceID: "dev",
			want: "1ef2f74811d4ded6264c2a4ac49b5b639ceda212ba76b523c4448c739fe7660f" +
				"9bd2ff07c3c978668450ef614d2d4938f80218abbe7e31e6ea2d64c3bb94d0dd" +
				"7e843a076cc7644abbb444e8f854c51103d4bd47a1c28fb00825c37856011abc",
		},
		{
			name: "zero seed, empty device id", digests: def,
			callsSeed: 0, deviceID: "",
			want: "ed2605a76aeb7a9a0bca2b794c1348a9da4377b33b97105e212256a8d7584eba" +
				"7cc14a2209567878c1cd5dcf072239bc584bbb295887cb8bed8ff44f359ed1f3" +
				"72af8852d87a2811130872496ca04a0945ef0f0bb06194f54927ccbc0baf45da",
		},
		{
			// Same build, different ABI: only the third block may change, since
			// the .so digest is the only per-ABI input.
			name: "default build, armeabi-v7a", digests: v7,
			callsSeed: 12345, deviceID: "dev-abc",
			want: "df33c9ed0a449aade45c394bdbc8d9798679131a4061cee3e408748c1f163dd7" +
				"a02a62847bef31d65a0c3e2afaf8bf5413e610a2a4369f55d2f36ef4beaf7251" +
				"a0c6d50c132576d2dedc4498e2ca1e10c648088384d885a687992c279059f032",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ChatCacheFingerprint(tc.digests.Signature, tc.digests.Dex, tc.digests.So, tc.callsSeed, tc.deviceID)
			if len(got) != FingerprintSize {
				t.Fatalf("length = %d, want %d", len(got), FingerprintSize)
			}
			if h := hex.EncodeToString(got); h != tc.want {
				t.Errorf("fingerprint mismatch\n got %s\nwant %s", h, tc.want)
			}
		})
	}
}

// The shipped default must exist in the table — DefaultDigests panics otherwise,
// and DefaultUserAgent would announce a version we cannot fingerprint.
func TestDefaultBuildIsInTheTable(t *testing.T) {
	d, ok := DigestsFor(DefaultAppVersion, DefaultArch)
	if !ok {
		t.Fatalf("no digests for the default %s/%s", DefaultAppVersion, DefaultArch)
	}
	for name, digest := range map[string][]byte{"signature": d.Signature, "dex": d.Dex, "so": d.So} {
		if len(digest) != 32 {
			t.Errorf("%s digest is %d bytes, want 32", name, len(digest))
		}
	}
	if build, ok := BuildNumberFor(DefaultAppVersion); !ok || build != DefaultBuildNumber {
		t.Errorf("BuildNumberFor(%s) = %d/%v, want %d", DefaultAppVersion, build, ok, DefaultBuildNumber)
	}

	// userAgent must announce exactly the build the fingerprint is derived from;
	// a mismatch here is the whole failure mode the table exists to prevent.
	ua := DefaultUserAgent()
	if ua.AppVersion != DefaultAppVersion {
		t.Errorf("DefaultUserAgent appVersion = %q, want %q", ua.AppVersion, DefaultAppVersion)
	}
	if ua.BuildNumber != DefaultBuildNumber {
		t.Errorf("DefaultUserAgent buildNumber = %d, want %d", ua.BuildNumber, DefaultBuildNumber)
	}
	if ua.Arch != DefaultArch {
		t.Errorf("DefaultUserAgent arch = %q, want %q", ua.Arch, DefaultArch)
	}
}

// Every ABI in the table must be complete: a missing entry would silently fall
// back to the default build's digests for a config that named a real arch.
func TestEveryBuildCoversEveryABI(t *testing.T) {
	abis := []string{"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}
	for version := range apkBuilds {
		for _, abi := range abis {
			d, ok := DigestsFor(version, abi)
			if !ok {
				t.Errorf("%s has no digests for %s", version, abi)
				continue
			}
			if len(d.So) != 32 {
				t.Errorf("%s/%s so digest is %d bytes", version, abi, len(d.So))
			}
		}
	}
}

// Only the .so block may differ between ABIs of one build: signature and dex are
// per-release, not per-ABI.
func TestABIChangesOnlyTheSoBlock(t *testing.T) {
	arm64, _ := DigestsFor(DefaultAppVersion, "arm64-v8a")
	x86, _ := DigestsFor(DefaultAppVersion, "x86_64")

	if !bytes.Equal(arm64.Signature, x86.Signature) || !bytes.Equal(arm64.Dex, x86.Dex) {
		t.Fatal("signature/dex differ across ABIs of one build")
	}
	if bytes.Equal(arm64.So, x86.So) {
		t.Fatal("so digest is identical across ABIs — table is likely wrong")
	}

	a := ChatCacheFingerprint(arm64.Signature, arm64.Dex, arm64.So, 42, "dev")
	b := ChatCacheFingerprint(x86.Signature, x86.Dex, x86.So, 42, "dev")
	if !bytes.Equal(a[:64], b[:64]) {
		t.Error("first two blocks changed with the ABI")
	}
	if bytes.Equal(a[64:], b[64:]) {
		t.Error("third block did not change with the ABI")
	}
}

func TestDigestsForUnknownBuild(t *testing.T) {
	if _, ok := DigestsFor("0.0.0", DefaultArch); ok {
		t.Error("unknown appVersion reported as known")
	}
	if _, ok := DigestsFor(DefaultAppVersion, "mips"); ok {
		t.Error("unknown arch reported as known")
	}
	if _, ok := BuildNumberFor("0.0.0"); ok {
		t.Error("unknown appVersion has a build number")
	}
}

// fingerprintFor must follow the config, and fall back audibly rather than
// failing when the config names a build we have no digests for.
func TestFingerprintForFollowsConfig(t *testing.T) {
	cfg := testConfig()
	cfg.UserAgent.AppVersion = DefaultAppVersion
	cfg.UserAgent.Arch = "x86_64"

	d, _ := DigestsFor(DefaultAppVersion, "x86_64")
	want := ChatCacheFingerprint(d.Signature, d.Dex, d.So, 99, cfg.DeviceID)
	if got := fingerprintFor(cfg, 99); !bytes.Equal(got, want) {
		t.Error("fingerprintFor ignored userAgent.arch")
	}

	// Unknown version → default digests, still a well-formed fingerprint.
	cfg.UserAgent.AppVersion = "1.2.3"
	fallback := fingerprintFor(cfg, 99)
	if len(fallback) != FingerprintSize {
		t.Fatalf("fallback is %d bytes", len(fallback))
	}
	if !bytes.Equal(fallback, Fingerprint(99, cfg.DeviceID)) {
		t.Error("unknown version did not fall back to the default build")
	}

	// Empty arch is treated as the default ABI, not as unknown.
	cfg.UserAgent.AppVersion = DefaultAppVersion
	cfg.UserAgent.Arch = ""
	if !bytes.Equal(fingerprintFor(cfg, 99), Fingerprint(99, cfg.DeviceID)) {
		t.Error("empty arch did not default to " + DefaultArch)
	}
}

// Ported from kolibri-net/src/auth.rs::fingerprint_varies_with_inputs.
func TestFingerprintVariesWithInputs(t *testing.T) {
	sig, dex, so := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	base := ChatCacheFingerprint(sig, dex, so, 1, "dev")

	variants := []struct {
		name string
		got  []byte
	}{
		{"calls seed", ChatCacheFingerprint(sig, dex, so, 2, "dev")},
		{"device id", ChatCacheFingerprint(sig, dex, so, 1, "dev2")},
		{"signature digest", ChatCacheFingerprint(bytes.Repeat([]byte{9}, 32), dex, so, 1, "dev")},
		{"dex digest", ChatCacheFingerprint(sig, bytes.Repeat([]byte{9}, 32), so, 1, "dev")},
		{"so digest", ChatCacheFingerprint(sig, dex, bytes.Repeat([]byte{9}, 32), 1, "dev")},
	}
	for _, v := range variants {
		if bytes.Equal(base, v.got) {
			t.Errorf("changing %s did not change the fingerprint", v.name)
		}
	}
}

// The three digests must land in signature/dex/so order, one 32-byte block
// each — a swap would still be 96 deterministic bytes, so pin the layout.
func TestFingerprintBlockOrder(t *testing.T) {
	sig, dex, so := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	full := ChatCacheFingerprint(sig, dex, so, 42, "dev")

	for i, digest := range [][]byte{sig, dex, so} {
		only := ChatCacheFingerprint(digest, digest, digest, 42, "dev")[:32]
		if !bytes.Equal(full[i*32:(i+1)*32], only) {
			t.Errorf("block %d is not the hash of digest %d", i, i)
		}
	}
}
