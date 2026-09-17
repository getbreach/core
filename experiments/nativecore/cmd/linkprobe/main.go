//go:build cgo

// linkprobe exists solely to verify that the complete bridge and Hy2 can be
// linked into a mobile native library. This is not the final mobile API.
package main

import "C"

import (
	"breach-nativecore/bridge"
	"breach-nativecore/hy2"
	"breach-nativecore/routing"
	"context"
)

//export BreachNativeLinkProbe
func BreachNativeLinkProbe() C.int {
	// Retain the real Hy2 constructor and its TLS/QUIC dependencies during
	// linking. Nil PacketConn fails before opening any network socket.
	if _, err := hy2.Dial(context.Background(), nil, nil, "", hy2.TLSOptions{}); err == nil {
		return 3
	}
	router, err := routing.New(routing.Config{}, &hy2.Client{}, routing.Options{})
	if err != nil {
		return 4
	}
	defer router.Close()
	b, err := bridge.New(router, bridge.Options{})
	if err != nil {
		return 1
	}
	if err := b.Close(); err != nil {
		return 2
	}
	return 0
}

func main() {}
