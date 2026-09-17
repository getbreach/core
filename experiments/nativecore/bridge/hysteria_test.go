package bridge

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	"breach-nativecore/internal/hy2test"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

type hy2Fixture struct{ Outbound }

func (o hy2Fixture) DialTCP(ctx context.Context, addr string) (net.Conn, error) {
	return o.Outbound.DialTCP(ctx, mapEndpoint(addr, true))
}
func (o hy2Fixture) OpenUDP(ctx context.Context) (Datagrams, error) {
	d, err := o.Outbound.OpenUDP(ctx)
	if err != nil {
		return nil, err
	}
	return localDatagrams{d}, nil
}
func newHy2Harness(t testing.TB, opts Options) *harness {
	return packetHarness(t, opts, hy2Fixture{hy2test.Client(t)})
}

func TestHysteriaTCPPackets(t *testing.T) {
	for _, host := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(host, func(t *testing.T) {
			ln := tcpEcho(t, host)
			h := newHy2Harness(t, Options{})
			addr, proto := endpoint(ln.Addr())
			c, err := gonet.DialContextTCP(h.ctx, h.os, addr, proto)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte("Hy2 TCP"), 8192)
			written := make(chan error, 1)
			go func() { _, err := c.Write(want); written <- err }()
			got := make([]byte, len(want))
			if _, err := io.ReadFull(c, got); err != nil {
				t.Fatal(err)
			}
			if err := <-written; err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("TCP payload mismatch")
			}
			if h.bridge.Stats().PacketsIn == 0 || h.bridge.Stats().PacketsOut == 0 {
				t.Fatal("bypassed packet bridge")
			}
		})
	}
}

func TestHysteriaUDPPackets(t *testing.T) { testUDPFlows(t, newHy2Harness, []int{32, 1200, 3000}) }
func TestHysteriaDNSPackets(t *testing.T) { testDNS(t, newHy2Harness) }
