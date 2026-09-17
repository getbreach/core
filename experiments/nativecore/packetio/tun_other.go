//go:build !linux || android

package packetio

import "errors"

type TUN struct{}

func OpenTUN(string) (*TUN, error) {
	return nil, errors.New("nativecore prototype: OS TUN adapter currently implemented only for Linux")
}
func (*TUN) Name() string                    { return "" }
func (*TUN) ReadPacket([]byte) (int, error)  { return 0, errors.New("unsupported TUN adapter") }
func (*TUN) WritePacket([]byte) (int, error) { return 0, errors.New("unsupported TUN adapter") }
func (*TUN) Close() error                    { return nil }
