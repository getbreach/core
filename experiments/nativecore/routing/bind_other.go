//go:build !linux || android

package routing

import "errors"

func InterfaceControl(string) (Control, error) {
	return nil, errors.New("directInterface is implemented only for Linux CLI; mobile uses the platform socket protector")
}
