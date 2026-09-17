package hy2

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	hysteria "github.com/apernet/hysteria/core/v2/client"
)

// Model an exit which accepts QUIC but never answers a TCP connect request.
type stalledClient struct {
	release chan struct{}
	started chan struct{}
	conn    net.Conn
}

func (c *stalledClient) TCP(string) (net.Conn, error) {
	close(c.started)
	<-c.release
	return c.conn, nil
}
func (*stalledClient) UDP() (hysteria.HyUDPConn, error) { return nil, errors.New("unused") }
func (c *stalledClient) Close() error                   { close(c.release); return nil }

func TestCanceledTCPDialDisposesLateConnection(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	fake := &stalledClient{release: make(chan struct{}), started: make(chan struct{}), conn: a}
	c := &Client{client: fake, done: make(chan struct{}), pending: make(chan struct{}, 32)}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.DialTCP(ctx, "example.test:80"); done <- err }()
	<-fake.started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dial ignored cancellation")
	}
	c.Close() // Returns the late result from the upstream API.
	b.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := b.Read(make([]byte, 1)); err == nil {
		t.Fatal("late connection still open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("late connection leaked")
	}
}
