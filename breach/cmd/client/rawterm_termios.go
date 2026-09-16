//go:build linux || darwin

package main

import "golang.org/x/sys/unix"

// Raw terminal mode for the arrow-key menu, on the two desktop targets. This is
// the cfmakeraw(3) recipe (mirrors golang.org/x/term) done against x/sys/unix,
// which the tree already depends on — so the menu needs no new module. Other
// platforms use the stub in rawterm_other.go and fall back to a numbered prompt.
type termState struct{ t unix.Termios }

func makeRawState(fd int) (*termState, error) {
	t, err := unix.IoctlGetTermios(fd, ioctlReadTermios)
	if err != nil {
		return nil, err
	}
	old := termState{t: *t}
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP | unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0
	if err := unix.IoctlSetTermios(fd, ioctlWriteTermios, t); err != nil {
		return nil, err
	}
	return &old, nil
}

func restoreState(fd int, s *termState) error {
	return unix.IoctlSetTermios(fd, ioctlWriteTermios, &s.t)
}
