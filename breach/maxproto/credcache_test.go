package maxproto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestCredentialCacheLifetimeAndIsolation(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "private")
	good := &Creds{Username: "u", Credential: "p", TurnHosts: []string{"localhost:3478"}, ExpiresAt: time.Now().Add(time.Hour), JoinLink: "test-link"}
	expired := *good
	expired.ExpiresAt = time.Now().Add(10 * time.Minute)
	if err := SaveCachedCreds(dir, "account-a", []*Creds{nil, good, &expired, {ExpiresAt: good.ExpiresAt}}); err != nil {
		t.Fatal(err)
	}
	got := LoadCachedCreds(dir, "account-a")
	if len(got) != 1 || got[0].JoinLink != good.JoinLink {
		t.Fatal("valid credential did not round trip")
	}
	if len(LoadCachedCreds(dir, "account-b")) != 0 {
		t.Fatal("account cache leaked")
	}
	if runtime.GOOS != "windows" {
		for path, want := range map[string]os.FileMode{dir: 0700, credCacheFile(dir, "account-a"): 0600} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != want {
				t.Fatalf("permissions %o want %o", info.Mode().Perm(), want)
			}
		}
	}
	if err := SaveCachedCreds(dir, "account-a", nil); err != nil {
		t.Fatal(err)
	}
	if len(LoadCachedCreds(dir, "account-a")) != 0 {
		t.Fatal("cleared credentials resurrected")
	}
	if err := os.WriteFile(credCacheFile(dir, "account-a"), []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if len(LoadCachedCreds(dir, "account-a")) != 0 {
		t.Fatal("corrupt cache accepted")
	}
}

func TestCredentialCacheAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	creds := []*Creds{{Credential: "p", TurnHosts: []string{"localhost:3478"}, ExpiresAt: time.Now().Add(time.Hour)}}
	if err := SaveCachedCreds(dir, "account", creds); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if err := SaveCachedCreds(dir, "account", creds); err != nil {
					t.Error(err)
					return
				}
				data, err := os.ReadFile(credCacheFile(dir, "account"))
				if err != nil {
					t.Error(err)
					return
				}
				var got []*Creds
				if json.Unmarshal(data, &got) != nil || len(got) != 1 {
					t.Error("reader observed a partial cache")
					return
				}
			}
		}()
	}
	wg.Wait()
	leftovers, err := filepath.Glob(filepath.Join(dir, ".creds-*"))
	if err != nil || len(leftovers) != 0 {
		t.Fatal("temporary cache files left behind")
	}
	// A failed replacement must report an error and remove the temporary file.
	bad := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(bad, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := SaveCachedCreds(bad, "account", creds); err == nil {
		t.Fatal("write failure hidden")
	}
}
