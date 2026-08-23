package breachmobile

import (
	"bytes"
	"strings"
	"testing"
)

type recorder struct{ lines []string }

func (r *recorder) Line(s string) { r.lines = append(r.lines, s) }

// The installer prints the client keys and the management handle to stdout. They
// must reach the PARSER (the capture buffer) and must not reach the progress
// stream, which the app renders into a screenshot-able log.
func TestStreamLinesWithholdsSecretBlocks(t *testing.T) {
	const secret = `{"url":"https://1.2.3.4:48000/DEADBEEF","secret":"DEADBEEF"}`
	const key = `{"name":"phoneA","wireguard":{"privateKey":"TOPSECRETKEY="}}`
	input := strings.Join([]string{
		"installing docker …",
		"===BREACH-CLIENT-CONFIG-BEGIN===",
		key,
		"===BREACH-CLIENT-CONFIG-END===",
		"starting container …",
		"===BREACH-MGMT-BEGIN===",
		secret,
		"===BREACH-MGMT-END===",
		"done — exit is live",
	}, "\n") + "\n"

	var capture bytes.Buffer
	rec := &recorder{}
	streamLines(strings.NewReader(input), rec, &capture)

	shown := strings.Join(rec.lines, "\n")
	for _, leak := range []string{"DEADBEEF", "TOPSECRETKEY", secret, key} {
		if strings.Contains(shown, leak) {
			t.Fatalf("progress stream leaked %q:\n%s", leak, shown)
		}
	}
	// The ordinary output still has to get through, or the log is useless.
	for _, want := range []string{"installing docker …", "starting container …", "done — exit is live"} {
		if !strings.Contains(shown, want) {
			t.Fatalf("progress stream dropped %q:\n%s", want, shown)
		}
	}
	// The capture buffer is what ProvisionServer parses — it must be intact.
	if got := capture.String(); !strings.Contains(got, secret) || !strings.Contains(got, key) {
		t.Fatalf("capture buffer lost a block:\n%s", got)
	}
}

// Withholding must not swallow the rest of the output if a block never closes
// (a truncated install) — but it must also not start emitting the block.
func TestStreamLinesUnterminatedBlockStaysWithheld(t *testing.T) {
	input := "ok\n===BREACH-MGMT-BEGIN===\nSECRETLINE\n"
	var capture bytes.Buffer
	rec := &recorder{}
	streamLines(strings.NewReader(input), rec, &capture)

	shown := strings.Join(rec.lines, "\n")
	if strings.Contains(shown, "SECRETLINE") {
		t.Fatalf("unterminated block leaked:\n%s", shown)
	}
	if !strings.Contains(shown, "ok") {
		t.Fatalf("output before the block was dropped:\n%s", shown)
	}
}

// The reason an install failed is on stderr; stdout ends on the last step that
// worked. Reporting stdout alone produced "install failed: status 1" followed by
// a tail that looked like a healthy run — which is exactly what it did.
func TestFailureTailPrefersStderr(t *testing.T) {
	const reason = "no such attribute: !reset (needs Compose v2.24+)"
	got := failureTail(reason, "==> starting exit (PROTO=hy2, udp/48000)")
	if !strings.Contains(got, reason) {
		t.Fatalf("failure tail dropped the stderr reason: %q", got)
	}
}

func TestFailureTailFallsBackToStdout(t *testing.T) {
	const last = "==> starting exit"
	if got := failureTail("   \n\t ", last); !strings.Contains(got, last) {
		t.Fatalf("with empty stderr the tail should fall back to stdout, got %q", got)
	}
}
