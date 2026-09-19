//go:build darwin && !ios

package integration

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"breach-nativecore/bridge"
	"breach-nativecore/internal/hy2test"
	"breach-nativecore/outbound"
	"breach-nativecore/packetio"
)

const macTest4 = "198.19.99.1"
const macTest6 = "2001:db8:beef::1"

func macLocal(addr string) string {
	addr = strings.Replace(addr, macTest4+":", "127.0.0.1:", 1)
	return strings.Replace(addr, "["+macTest6+"]:", "[::1]:", 1)
}
func macVirtual(addr string) string {
	addr = strings.Replace(addr, "127.0.0.1:", macTest4+":", 1)
	return strings.Replace(addr, "[::1]:", "["+macTest6+"]:", 1)
}

type macOutbound struct{ outbound.Outbound }

func (o macOutbound) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	return o.Outbound.DialTCP(ctx, macLocal(target))
}
func (o macOutbound) OpenUDP(ctx context.Context) (outbound.Datagrams, error) {
	c, e := o.Outbound.OpenUDP(ctx)
	if e != nil {
		return nil, e
	}
	return macUDP{c}, nil
}

type macUDP struct{ outbound.Datagrams }

func (d macUDP) WriteTo(p []byte, target string) error {
	return d.Datagrams.WriteTo(p, macLocal(target))
}
func (d macUDP) ReadFrom(ctx context.Context) ([]byte, string, error) {
	p, a, e := d.Datagrams.ReadFrom(ctx)
	return p, macVirtual(a), e
}

// Only two documentation/benchmark host routes are added. This test does not
// change default routes or DNS, and all routes belong to this ephemeral utun.
func TestMacOSTUN(t *testing.T) {
	if os.Getenv("BREACH_NATIVE_MAC_TUN_TEST") != "1" {
		t.Skip("use scripts/macos-tun.sh")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c := hy2test.Client(t)
	b, e := bridge.New(macOutbound{c}, bridge.Options{MTU: 1280})
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	tun, e := packetio.OpenTUN("auto")
	if e != nil {
		t.Fatal(e)
	}
	name := tun.Name()
	t.Logf("kernel device: %s", name)
	done := make(chan error, 1)
	go func() { done <- packetio.Run(ctx, b, tun) }()
	defer func() {
		cancel()
		tun.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("utun pump did not stop")
		}
	}()
	run := func(path string, args ...string) {
		t.Helper()
		out, e := exec.CommandContext(ctx, path, args...).CombinedOutput()
		if e != nil {
			t.Fatalf("%s %v: %v: %s", path, args, e, out)
		}
	}
	run("/sbin/ifconfig", name, "inet", "198.19.255.1", "198.19.255.2", "netmask", "255.255.255.252", "mtu", "1280", "up")
	run("/sbin/ifconfig", name, "inet6", "fd00:198:19::1", "prefixlen", "126")
	run("/sbin/route", "-n", "add", "-inet", "-host", macTest4, "-interface", name)
	run("/sbin/route", "-n", "add", "-inet6", "-host", macTest6, "-interface", name)
	for _, address := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			ln, e := net.Listen("tcp", address)
			if e != nil {
				t.Fatal(e)
			}
			defer ln.Close()
			go func() {
				q, e := ln.Accept()
				if e != nil {
					return
				}
				defer q.Close()
				q.SetDeadline(time.Now().Add(5 * time.Second))
				io.Copy(q, q)
			}()
			q, e := (&net.Dialer{}).DialContext(ctx, "tcp", macVirtual(ln.Addr().String()))
			if e != nil {
				t.Fatal(e)
			}
			defer q.Close()
			q.SetDeadline(time.Now().Add(5 * time.Second))
			want := bytes.Repeat([]byte("utun over Hy2"), 1024)
			written := make(chan error, 1)
			go func() { _, e := q.Write(want); written <- e }()
			got := make([]byte, len(want))
			if _, e = io.ReadFull(q, got); e != nil {
				t.Fatal(e)
			}
			if e = <-written; e != nil || !bytes.Equal(got, want) {
				t.Fatalf("TCP echo mismatch: %v", e)
			}
			pc, e := net.ListenPacket("udp", address)
			if e != nil {
				t.Fatal(e)
			}
			defer pc.Close()
			go func() {
				buf := make([]byte, 4096)
				n, a, e := pc.ReadFrom(buf)
				if e == nil {
					pc.WriteTo(buf[:n], a)
				}
			}()
			u, e := (&net.Dialer{}).DialContext(ctx, "udp", macVirtual(pc.LocalAddr().String()))
			if e != nil {
				t.Fatal(e)
			}
			defer u.Close()
			u.SetDeadline(time.Now().Add(5 * time.Second))
			want = bytes.Repeat([]byte{0x41}, 3000)
			if _, e = u.Write(want); e != nil {
				t.Fatal(e)
			}
			got = make([]byte, 4096)
			n, e := u.Read(got)
			if e != nil || !bytes.Equal(got[:n], want) {
				t.Fatalf("UDP fragment/reassembly mismatch: %v", e)
			}
		})
	}
	if b.Stats().PacketsIn == 0 || b.Stats().PacketsOut == 0 {
		t.Fatal("kernel bypassed utun")
	}
}
