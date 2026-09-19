//go:build (!linux && !darwin) || android || ios

package packetio

import "errors"

type TUN struct{}

func OpenTUN(string) (*TUN, error) {
	return nil, errors.New("OS TUN adapter currently implemented for Linux and macOS; mobile requires its platform adapter")
}
func (*TUN) Name() string                    { return "" }
func (*TUN) ReadPacket([]byte) (int, error)  { return 0, errors.New("unsupported TUN adapter") }
func (*TUN) WritePacket([]byte) (int, error) { return 0, errors.New("unsupported TUN adapter") }
func (*TUN) Close() error                    { return nil }
