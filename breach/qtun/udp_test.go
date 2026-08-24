package qtun_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// udpEcho is the "internet" for UDP: it returns whatever it receives.
func udpEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, src, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = pc.WriteToUDP(buf[:n], src)
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr)
}

func TestUDPRoundTrip(t *testing.T) {
	echo := udpEcho(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatalf("open udp: %v", err)
	}
	defer sess.Close()

	if err := sess.WriteTo([]byte("dns-ish"), echo.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, from, err := sess.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "dns-ish" {
		t.Fatalf("got %q", got)
	}
	if from != echo.String() {
		t.Fatalf("reply attributed to %s, want %s", from, echo.String())
	}
}

// The reason fragmentation exists: the inner QUIC insists on datagrams of at
// least 1200 bytes, which do not fit our budget on this path.
func TestUDPFragmentsLargePacket(t *testing.T) {
	echo := udpEcho(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	// Sizes that actually occur: a QUIC Initial (1200), a full path MTU, and an
	// EDNS0 answer. Beyond ~7 KB payloads are dropped by design, see maxFragments.
	for _, size := range []int{1200, 1500, 4096} {
		payload := make([]byte, size)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		if err := sess.WriteTo(payload, echo.String()); err != nil {
			t.Fatalf("%d bytes: write: %v", size, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		got, _, err := sess.ReadFrom(ctx)
		cancel()
		if err != nil {
			t.Fatalf("%d bytes: read: %v", size, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%d bytes: payload came back wrong (%d bytes)", size, len(got))
		}
	}
}

// A payload too big to deliver must be dropped outright rather than sent in
// pieces that can never be reassembled — and must not break the session.
func TestUDPOversizedIsDroppedNotFatal(t *testing.T) {
	echo := udpEcho(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")
	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.WriteTo(make([]byte, 64<<10), echo.String()); err != nil {
		t.Fatalf("an oversized packet must be dropped, not reported: %v", err)
	}

	// The session still works afterwards.
	if err := sess.WriteTo([]byte("still here"), echo.String()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	got, _, err := sess.ReadFrom(ctx)
	if err != nil {
		t.Fatalf("session broken by an oversized packet: %v", err)
	}
	if string(got) != "still here" {
		t.Fatalf("got %q", got)
	}
}

// One association may address many destinations, and replies must be
// attributed to the right one.
func TestUDPManyDestinations(t *testing.T) {
	a, b := udpEcho(t), udpEcho(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")

	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.WriteTo([]byte("to-a"), a.String()); err != nil {
		t.Fatal(err)
	}
	if err := sess.WriteTo([]byte("to-b"), b.String()); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		got, from, err := sess.ReadFrom(ctx)
		cancel()
		if err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
		seen[from] = string(got)
	}
	if seen[a.String()] != "to-a" || seen[b.String()] != "to-b" {
		t.Fatalf("replies mixed up: %v", seen)
	}
}

// A UDP session must be authenticated like everything else: the exit is
// reachable by anyone who can talk to the relay.
func TestUDPRejectsBadToken(t *testing.T) {
	c := endToEnd(t, func(tok string) bool { return tok == "right" }, "wrong")
	if _, err := c.OpenUDP(context.Background()); err == nil {
		t.Fatal("a bad token opened a UDP session")
	}
}

// Closing the association must free the exit's socket, not leak it.
func TestUDPSessionCloses(t *testing.T) {
	echo := udpEcho(t)
	c := endToEnd(t, func(string) bool { return true }, "tok")
	sess, err := c.OpenUDP(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.WriteTo([]byte("x"), echo.String()); err != nil {
		t.Fatal(err)
	}
	sess.Close()
	if err := sess.WriteTo([]byte("y"), echo.String()); err == nil {
		t.Fatal("write on a closed session should fail")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := sess.ReadFrom(ctx); err == nil {
		t.Fatal("read on a closed session should fail")
	}
}
