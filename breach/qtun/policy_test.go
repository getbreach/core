package qtun_test

import (
	"context"
	"net"
	"testing"
	"time"

	"breach/qtun"
)

// The exit dials on a client's behalf, so without a policy an authenticated
// client can point it at the exit's OWN loopback — where the Clash API and the
// management daemon live — or at the host's LAN. These must be refused by
// DEFAULT, which is why the tunnel tests have to opt into AllowPrivate.
func TestDefaultPolicyRefusesPrivateDestinations(t *testing.T) {
	echo := echoServer(t) // on 127.0.0.1

	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, pin, err := qtun.ServerTLS(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// NOTE: no AllowPrivate — this is the shipping default.
	go func() {
		_ = qtun.Serve(ctx, srvPC, tlsConf, qtun.ServerOptions{Auth: func(string) bool { return true }})
	}()

	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliTLS, err := qtun.ClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	c, err := qtun.Dial(dctx, cliPC, srvPC.LocalAddr(), cliTLS, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for _, target := range []string{
		echo.Addr().String(), // the exit's own loopback
		"127.0.0.1:51822",    // the Clash API
		"10.0.0.1:80",        // RFC1918
		"192.168.1.1:80",
		"169.254.169.254:80", // cloud metadata
	} {
		octx, ocancel := context.WithTimeout(context.Background(), 8*time.Second)
		conn, err := c.Open(octx, target)
		ocancel()
		if err == nil {
			conn.Close()
			t.Errorf("exit dialled %s on a client's behalf", target)
		}
	}
}

// The same policy has to cover UDP, or the hole simply moves.
func TestDefaultPolicyRefusesPrivateUDP(t *testing.T) {
	echo := udpEcho(t) // 127.0.0.1

	srvPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsConf, pin, err := qtun.ServerTLS(t.TempDir()+"/c.pem", t.TempDir()+"/k.pem")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = qtun.Serve(ctx, srvPC, tlsConf, qtun.ServerOptions{Auth: func(string) bool { return true }})
	}()

	cliPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cliTLS, err := qtun.ClientTLS(pin)
	if err != nil {
		t.Fatal(err)
	}
	dctx, dcancel := context.WithTimeout(ctx, 10*time.Second)
	defer dcancel()
	c, err := qtun.Dial(dctx, cliPC, srvPC.LocalAddr(), cliTLS, "tok")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.WriteTo([]byte("probe"), echo.String()); err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rcancel()
	if _, _, err := sess.ReadFrom(rctx); err == nil {
		t.Fatal("exit relayed UDP to its own loopback")
	}
}
