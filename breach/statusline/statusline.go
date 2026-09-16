// Package statusline renders a sticky one-line status at the bottom of a
// terminal: Set rewrites it in place (carriage return + clear-to-end) while
// ordinary log output, routed through Writer, scrolls above it.
//
// On a non-terminal (a file, a pipe, journald, `docker logs`) it deliberately
// stays out of the way: TTY() reports false, Writer is a pass-through, and the
// caller keeps emitting stats as normal log lines. That keeps captured logs free
// of carriage returns and escape codes, where in-place updates would be noise.
package statusline

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
)

// Line is a sticky status line bound to one output (usually os.Stderr).
type Line struct {
	mu     sync.Mutex
	out    *os.File
	tty    bool
	status string
	parked bool // a status is currently drawn with no trailing newline
}

// New binds a status line to out and detects whether out is a terminal.
func New(out *os.File) *Line { return &Line{out: out, tty: isTerminal(out)} }

// TTY reports whether the output is an interactive terminal. Off a terminal the
// caller should log stats as ordinary lines instead of calling Set.
func (l *Line) TTY() bool { return l.tty }

// Writer wraps the output so the standard logger cooperates with the sticky
// line: each log record erases the parked status, prints, then the status is
// redrawn below it. Hand it to log.SetOutput only on a TTY; off a terminal it is
// a plain pass-through.
func (l *Line) Writer() io.Writer { return writer{l} }

type writer struct{ l *Line }

func (w writer) Write(p []byte) (int, error) {
	l := w.l
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.parked {
		fmt.Fprint(l.out, "\r\x1b[K") // wipe the parked status before the log line
		l.parked = false
	}
	n, err := l.out.Write(p)
	if l.tty && l.status != "" {
		fmt.Fprint(l.out, l.status+"\x1b[K") // redraw the status beneath it
		l.parked = true
	}
	return n, err
}

// Set updates and redraws the sticky status line in place. It is a no-op off a
// terminal (TTY() == false), where callers log stats as normal lines.
func (l *Line) Set(s string) {
	if !l.tty {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.status = s
	fmt.Fprint(l.out, "\r"+s+"\x1b[K")
	l.parked = true
}

func isTerminal(f *os.File) bool {
	if runtime.GOOS == "windows" {
		return false // avoid assuming VT processing on the Windows console
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
