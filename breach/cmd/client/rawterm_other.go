//go:build !linux && !darwin

package main

import "errors"

// Non-unix (or unsupported) build: no raw mode, so the menu falls back to the
// numbered prompt.
type termState struct{}

func makeRawState(int) (*termState, error) {
	return nil, errors.New("raw terminal not supported on this platform")
}

func restoreState(int, *termState) error { return nil }
