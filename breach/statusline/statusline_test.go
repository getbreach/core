package statusline

import (
	"io"
	"os"
	"testing"
)

// capture returns a Line writing to a temp file with tty forced, plus a reader
// of everything written so far.
func capture(t *testing.T, tty bool) (*Line, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "sl")
	if err != nil {
		t.Fatal(err)
	}
	l := &Line{out: f, tty: tty}
	return l, func() string {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		b, err := io.ReadAll(f)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
}

func TestStickyTTY(t *testing.T) {
	l, read := capture(t, true)
	l.Set("S1")
	l.Writer().Write([]byte("logline\n"))
	l.Set("S2")

	// Set draws "\r"+s+clear; a log line wipes the parked status, prints, redraws.
	want := "\rS1\x1b[K" + "\r\x1b[K" + "logline\n" + "S1\x1b[K" + "\rS2\x1b[K"
	if got := read(); got != want {
		t.Errorf("sticky sequence\n got %q\nwant %q", got, want)
	}
}

func TestPassthroughOffTTY(t *testing.T) {
	l, read := capture(t, false)
	l.Set("ignored")                    // no-op off a terminal
	l.Writer().Write([]byte("plain\n")) // pure pass-through, no escapes
	if got := read(); got != "plain\n" {
		t.Errorf("off-tty output = %q, want %q", got, "plain\n")
	}
}
