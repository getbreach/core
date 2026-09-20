package engine

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCredentialCachePaths(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	for _, value := range []string{"", "custom-cache", filepath.Join(dir, "absolute-cache")} {
		c := testConfig()
		c.Mode = "turn"
		c.Remote = ""
		c.Turn, _ = json.Marshal(map[string]string{"token": "test", "deviceId": "test", "server": "127.0.0.1:48000", "credCacheDir": value})
		data, _ := json.Marshal(c)
		if err := os.WriteFile(configPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		loaded, err := Load(configPath, "turn")
		if err != nil {
			t.Fatal(err)
		}
		var turn map[string]any
		if err := json.Unmarshal(loaded.Turn, &turn); err != nil {
			t.Fatal(err)
		}
		want := value
		if want == "" {
			want = filepath.Join(".breach-cache", "turn")
		}
		if !filepath.IsAbs(want) {
			want = filepath.Join(dir, want)
		}
		if turn["credCacheDir"] != want {
			t.Fatalf("cache path %v want %s", turn["credCacheDir"], want)
		}
		if _, err := os.Stat(want); !os.IsNotExist(err) {
			t.Fatal("loading config created cache")
		}
	}
}
