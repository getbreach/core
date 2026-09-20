//go:build (darwin && !ios) || (linux && !android)

package dashboard

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

type terminal struct {
	fd    int
	state *term.State
}

func openTerminal() (*terminal, error) {
	if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("TERM") == "dumb" {
		return nil, errors.New("TUI requires an interactive terminal; use breach run for plain logs")
	}
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	state, err := term.MakeRaw(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &terminal{fd, state}, nil
}
func (t *terminal) close() error {
	err := term.Restore(t.fd, t.state)
	return errors.Join(err, unix.Close(t.fd))
}
func (*terminal) size() (int, int) {
	w, h, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || w <= 0 || h <= 0 {
		return 80, 24
	}
	return w, h
}
func (t *terminal) keys() ([]byte, error) {
	var buf [64]byte
	n, err := unix.Read(t.fd, buf[:])
	if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, errors.New("terminal input closed")
	}
	return buf[:n], nil
}
