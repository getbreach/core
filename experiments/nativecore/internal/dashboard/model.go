package dashboard

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"breach-nativecore/engine"
	"breach-nativecore/transport"
)

type journal struct {
	mu     sync.Mutex
	lines  []string
	redact func(string) string
}

func newJournal(cfg engine.Config) *journal {
	secrets := []string{cfg.Password}
	var turn any
	_ = json.Unmarshal(cfg.Turn, &turn)
	var collect func(any)
	collect = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, v := range x {
				key := strings.ToLower(k)
				if strings.Contains(key, "token") || strings.Contains(key, "password") || strings.Contains(key, "secret") || key == "deviceid" {
					if value, ok := v.(string); ok {
						secrets = append(secrets, value)
					}
				}
				collect(v)
			}
		case []any:
			for _, v := range x {
				collect(v)
			}
		}
	}
	collect(turn)
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	return &journal{redact: func(line string) string {
		for _, secret := range secrets {
			if secret != "" {
				line = strings.ReplaceAll(line, secret, "[redacted]")
			}
		}
		return safeText(line)
	}}
}
func (j *journal) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05") + "  " + j.redact(fmt.Sprintf(format, args...))
	if len(line) > 1024 {
		line = line[:1024]
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(j.lines) == 100 {
		copy(j.lines, j.lines[1:])
		j.lines = j.lines[:99]
	}
	j.lines = append(j.lines, line)
}
func (j *journal) tail(n int) []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	start := max(0, len(j.lines)-n)
	return append([]string(nil), j.lines[start:]...)
}
func (j *journal) Write(p []byte) (int, error) {
	j.logf("%s", strings.TrimSpace(string(p)))
	return len(p), nil
}

// Keep untrusted log/peer text out of terminal control sequences and avoid
// width ambiguity from wide/combining characters in a fixed-cell dashboard.
func safeText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return b.String()
}

type rateMeter struct {
	at       time.Time
	before   transport.Traffic
	up, down float64
	history  []float64
}

func (r *rateMeter) sample(at time.Time, traffic transport.Traffic) {
	if !r.at.IsZero() && at.After(r.at) {
		dt := at.Sub(r.at).Seconds()
		r.up, r.down = 0, 0
		if traffic.UpBytes >= r.before.UpBytes {
			r.up = float64(traffic.UpBytes-r.before.UpBytes) / dt
		}
		if traffic.DownBytes >= r.before.DownBytes {
			r.down = float64(traffic.DownBytes-r.before.DownBytes) / dt
		}
		r.history = append(r.history, r.down)
		if len(r.history) > 48 {
			r.history = r.history[len(r.history)-48:]
		}
	}
	r.at, r.before = at, traffic
}
