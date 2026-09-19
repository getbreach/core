//go:build (!linux && !darwin) || android || ios

package routing

import "errors"

func InterfaceControl(string) (Control, error) {
	return nil, errors.New("directInterface is implemented for Linux and macOS CLI; mobile uses the platform socket protector")
}
