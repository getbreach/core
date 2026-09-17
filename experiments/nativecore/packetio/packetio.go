// Package packetio connects an OS packet device to the portable bridge.
package packetio

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"

	"breach-nativecore/bridge"
)

// Device reads/writes exactly one IP packet per call, with no Ethernet header.
// Close must unblock concurrent reads/writes. Implementations must report short
// writes; a packet can never be completed by writing its remainder separately.
// A future Apple adapter can implement this with packetFlow and bounded queues.
type Device interface {
	ReadPacket([]byte) (int, error)
	WritePacket([]byte) (int, error)
	Close() error
}

// Run takes ownership of dev and always closes it. The caller owns b.
func Run(ctx context.Context, b *bridge.Bridge, dev Device) error {
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var once sync.Once
	closeDevice := func() { once.Do(func() { dev.Close() }) }
	defer closeDevice()
	stop := context.AfterFunc(ctx, closeDevice)
	defer stop()
	done := make(chan error, 2)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, err := dev.ReadPacket(buf)
			if err != nil {
				done <- err
				return
			}
			if err := b.Inject(buf[:n]); errors.Is(err, net.ErrClosed) {
				done <- err
				return
			}
			// Bad/oversized IP packets are dropped, not a reason to kill the VPN.
		}
	}()
	go func() {
		for {
			p, err := b.ReadPacket(ctx)
			if err != nil {
				done <- err
				return
			}
			n, err := dev.WritePacket(p)
			if err == nil && n != len(p) {
				err = io.ErrShortWrite
			}
			if err != nil {
				done <- err
				return
			}
		}
	}()
	err := <-done
	cancel()
	closeDevice()
	<-done
	if parent.Err() != nil {
		return parent.Err()
	}
	return err
}
