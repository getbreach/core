package packetio

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"breach-nativecore/bridge"
	"breach-nativecore/hy2"
)

type blockedDevice struct {
	closed  chan struct{}
	entered chan struct{}
	once    sync.Once
	calls   atomic.Int32
	readErr error
}

func (d *blockedDevice) ReadPacket([]byte) (int, error) {
	close(d.entered)
	if d.readErr != nil {
		return 0, d.readErr
	}
	<-d.closed
	return 0, net.ErrClosed
}
func (d *blockedDevice) WritePacket(p []byte) (int, error) { return len(p), nil }
func (d *blockedDevice) Close() error {
	d.calls.Add(1)
	d.once.Do(func() { close(d.closed) })
	return nil
}

func TestPumpCancellationClosesDevice(t *testing.T) {
	for _, readErr := range []error{nil, io.EOF} {
		b, err := bridge.New(&hy2.Client{}, bridge.Options{})
		if err != nil {
			t.Fatal(err)
		}
		d := &blockedDevice{closed: make(chan struct{}), entered: make(chan struct{}), readErr: readErr}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Run(ctx, b, d) }()
		<-d.entered
		want := readErr
		if readErr == nil {
			cancel()
			want = context.Canceled
		}
		select {
		case err := <-done:
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		case <-time.After(time.Second):
			t.Fatal("pump did not stop")
		}
		cancel()
		b.Close()
		if d.calls.Load() != 1 {
			t.Fatalf("device Close called %d times", d.calls.Load())
		}
	}
}
