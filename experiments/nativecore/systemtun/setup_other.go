//go:build !darwin || ios

package systemtun

import (
	"context"
	"errors"
	"io"
)

type Session struct{}

func Supported() bool { return false }
func Setup(context.Context, string, int, string) (*Session, error) {
	return nil, errors.New("automatic TUN routes/DNS are currently implemented only on macOS")
}
func (*Session) Close() error                          { return nil }
func (*Session) Done() <-chan struct{}                 { return nil }
func (*Session) Refresh(context.Context) (bool, error) { return false, nil }
func RunRouteGuardian(io.Reader, io.Writer) error      { return errors.New("route guardian requires macOS") }
