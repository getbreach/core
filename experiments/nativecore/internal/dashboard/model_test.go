package dashboard

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"breach-nativecore/engine"
	"breach-nativecore/transport"
)

func TestJournalRedactsAndBoundsRemoteText(t *testing.T) {
	j := newJournal(engine.Config{Password: "private-hy2-password", Turn: json.RawMessage(`{"accounts":[{"token":"private-turn-token","deviceId":"private-device-id"}]}`)})
	for i := 0; i < 120; i++ {
		j.logf("private-hy2-password private-turn-token private-device-id\x1b[2J\nremote")
	}
	lines := j.tail(200)
	if len(lines) != 100 {
		t.Fatalf("unbounded journal: %d", len(lines))
	}
	for _, line := range lines {
		if strings.Contains(line, "private-") || strings.ContainsAny(line, "\x1b\r\n") {
			t.Fatalf("unsafe terminal log: %q", line)
		}
		if strings.Count(line, "[redacted]") != 3 {
			t.Fatal("secret redaction incomplete")
		}
	}
}
func TestRateMeterHandlesCounterReset(t *testing.T) {
	r := rateMeter{}
	now := time.Now()
	r.sample(now, transport.Traffic{UpBytes: 1024, DownBytes: 2048})
	r.sample(now.Add(2*time.Second), transport.Traffic{UpBytes: 2048, DownBytes: 6144})
	if r.up != 512 || r.down != 2048 {
		t.Fatalf("wrong rates: %+v", r)
	}
	r.sample(now.Add(3*time.Second), transport.Traffic{})
	if r.up != 0 || r.down != 0 {
		t.Fatal("unsigned underflow after reset")
	}
}
func TestRenderFitsTerminalAndDoesNotClaimMissingMetrics(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	sgr := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	v := view{config: engine.Config{Inbound: "tun", Mode: "turn"}, status: engine.Snapshot{Phase: "online", Device: "utun4"}, logs: []string{strings.Repeat("long log ", 50)}}
	for _, size := range [][2]int{{1, 1}, {40, 10}, {60, 18}, {80, 24}, {90, 26}, {100, 30}, {120, 40}} {
		lines := render(v, size[0], size[1], false, false, true)
		if len(lines) > size[1] {
			t.Fatalf("too many rows for %v", size)
		}
		for _, line := range lines {
			clean := sgr.ReplaceAllString(line, "")
			if utf8.RuneCountInString(clean) > max(1, size[0]-1) || strings.ContainsRune(clean, '\x1b') {
				t.Fatalf("unsafe/wrapped line for %v: %q", size, line)
			}
		}
	}
	text := sgr.ReplaceAllString(strings.Join(render(v, 100, 30, false, false, true), "\n"), "")
	if !strings.Contains(text, "CPU  --") || !strings.Contains(text, "RSS  --") {
		t.Fatalf("missing metrics shown as measured zero: %s", text)
	}
	t.Setenv("NO_COLOR", "1")
	v.status.Device = "remote\x1b[2Jdevice"
	v.logs = []string{"log\x1b[2Jinjection"}
	text = strings.Join(render(v, 100, 30, false, false, true), "\n")
	if strings.ContainsRune(text, '\x1b') {
		t.Fatal("color disabled or external ANSI escaped sanitization")
	}
	if p, ok := cpuPercent(1, 4); !ok || p != 25 {
		t.Fatal("system CPU normalization")
	}
}

func TestPoolEditorAndOverlayFit(t *testing.T) {
	e := &poolEditor{mints: 3, streams: 4, accounts: 2}
	e.key('+')
	e.key(']')
	if e.mints != 4 || e.streams != 5 {
		t.Fatal("draft edits lost")
	}
	for i := 0; i < 30; i++ {
		e.key('-')
		e.key('[')
	}
	if e.mints != 1 || e.streams != 1 {
		t.Fatal("invalid zero pool")
	}
	t.Setenv("NO_COLOR", "1")
	for _, size := range [][2]int{{60, 18}, {80, 24}, {100, 30}} {
		lines := render(view{poolEdit: e}, size[0], size[1], false, false, true)
		for _, line := range lines {
			if utf8.RuneCountInString(line) > size[0]-1 {
				t.Fatal("editor wrapped")
			}
		}
		if !strings.Contains(strings.Join(lines, "\n"), "Enter apply") {
			t.Fatal("editor missing")
		}
	}
}
