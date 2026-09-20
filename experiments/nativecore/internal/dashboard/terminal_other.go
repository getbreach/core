//go:build (!darwin && !linux && !windows) || ios || android

package dashboard

import "errors"

type terminal struct{}

func openTerminal() (*terminal, error) {
	return nil, errors.New("interactive TUI is currently supported on macOS/Linux/Windows; use breach run")
}
func (*terminal) close() error          { return nil }
func (*terminal) size() (int, int)      { return 80, 24 }
func (*terminal) keys() ([]byte, error) { return nil, nil }
