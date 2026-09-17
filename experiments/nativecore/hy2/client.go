// Package hy2 embeds the official Hysteria2 client over a Breach PacketConn.
package hy2

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"breach-nativecore/outbound"
	hysteria "github.com/apernet/hysteria/core/v2/client"
)

type TLSOptions struct {
	ServerName string `json:"serverName"`
	CertSHA256 string `json:"certSha256,omitempty"`
	// Only for explicit compatibility with legacy self-signed deployments.
	Insecure bool `json:"insecure,omitempty"`
}

var ErrCertificatePinMismatch = errors.New("Hy2 certificate pin mismatch")

// ValidateOptions checks configuration before starting the outer transport.
func ValidateOptions(auth string, opts TLSOptions) error {
	if auth == "" {
		return errors.New("Hy2 password is required")
	}
	_, err := tlsConfig(opts)
	return err
}

type Client struct {
	client     hysteria.Client
	UDPEnabled bool
	once       sync.Once
	done       chan struct{}
	pending    chan struct{}
}

var _ outbound.Outbound = (*Client)(nil)

type packetFactory struct{ conn net.PacketConn }

func (f packetFactory) New(net.Addr) (net.PacketConn, error) { return f.conn, nil }

func tlsConfig(opts TLSOptions) (hysteria.TLSConfig, error) {
	cfg := hysteria.TLSConfig{ServerName: opts.ServerName, InsecureSkipVerify: opts.Insecure}
	if opts.CertSHA256 == "" {
		if opts.ServerName == "" {
			return cfg, errors.New("Hy2 serverName is required without a certificate pin")
		}
		return cfg, nil
	}
	if opts.Insecure {
		return cfg, errors.New("choose certSha256 or insecure, not both")
	}
	want, err := hex.DecodeString(opts.CertSHA256)
	if err != nil || len(want) != sha256.Size {
		return cfg, errors.New("certSha256 must contain 64 hexadecimal characters")
	}
	// A trusted leaf-certificate pin replaces CA/name verification for a
	// self-signed server; an arbitrary self-signed certificate is never accepted.
	cfg.InsecureSkipVerify = true
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) == 0 {
			return errors.New("Hy2 server sent no certificate")
		}
		got := sha256.Sum256(raw[0])
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return ErrCertificatePinMismatch
		}
		return nil
	}
	return cfg, nil
}

// Dial takes ownership of pc on all paths. ctx limits authentication, not the
// session lifetime; Close ends the session. QUIC stays at its conservative MTU
// through the SRTP/TURN wrapper. No qtun marker is added to Hy2 packets.
func Dial(ctx context.Context, pc net.PacketConn, peer net.Addr, auth string, opts TLSOptions) (*Client, error) {
	if pc == nil {
		return nil, errors.New("Hy2 PacketConn is required")
	}
	tls, err := tlsConfig(opts)
	if err != nil {
		pc.Close()
		return nil, err
	}
	if peer == nil || auth == "" {
		pc.Close()
		return nil, errors.New("Hy2 peer and password are required")
	}
	if err := ctx.Err(); err != nil {
		pc.Close()
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { pc.Close() })
	c, info, err := hysteria.NewClient(&hysteria.Config{
		ConnFactory: packetFactory{pc}, ServerAddr: peer, Auth: auth, TLSConfig: tls,
		QUICConfig: hysteria.QUICConfig{DisablePathMTUDiscovery: true, DisableGSO: true},
	})
	stop()
	if ctx.Err() != nil {
		if c != nil {
			c.Close()
		}
		pc.Close()
		return nil, ctx.Err()
	}
	if err != nil {
		pc.Close()
		return nil, err
	}
	return &Client{client: c, UDPEnabled: info.UDPEnabled, done: make(chan struct{}), pending: make(chan struct{}, 32)}, nil
}

func (c *Client) Close() error {
	c.once.Do(func() { close(c.done); c.client.Close() })
	return nil
}

// The upstream TCP API has no context. Bound outstanding negotiations so a
// stalled exit cannot accumulate unlimited goroutines. Late results are closed;
// closing the client interrupts all remaining negotiations.
func (c *Client) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, net.ErrClosed
	case c.pending <- struct{}{}:
	}
	type result struct {
		conn net.Conn
		err  error
	}
	ready := make(chan result)
	go func() {
		defer func() { <-c.pending }()
		conn, err := c.client.TCP(target)
		select {
		case ready <- result{conn, err}:
		case <-ctx.Done():
			if conn != nil {
				conn.Close()
			}
		case <-c.done:
			if conn != nil {
				conn.Close()
			}
		}
	}()
	select {
	case r := <-ready:
		return r.conn, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, net.ErrClosed
	}
}

func (c *Client) OpenUDP(ctx context.Context) (outbound.Datagrams, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case <-c.done:
		return nil, net.ErrClosed
	default:
	}
	u, err := c.client.UDP()
	if err != nil {
		return nil, err
	}
	return &datagrams{conn: u}, nil
}

type datagrams struct {
	conn    hysteria.HyUDPConn
	send    sync.Mutex // upstream Send reuses a buffer and is not concurrency-safe
	receive sync.Mutex
	once    sync.Once
	closed  atomic.Bool
}

func (d *datagrams) WriteTo(p []byte, target string) error {
	d.send.Lock()
	defer d.send.Unlock()
	if d.closed.Load() {
		return net.ErrClosed
	}
	// v2.12.3 drops empty messages on receive and silently drops messages
	// exceeding its 4096-byte serialization buffer before fragmentation.
	// Reject them explicitly instead of reporting a successful transmission.
	addressLenBytes := 1
	if len(target) > 63 {
		addressLenBytes = 2
	}
	if len(p) == 0 || len(target) == 0 || len(target) > 2048 || 8+addressLenBytes+len(target)+len(p) > 4096 {
		return errors.New("datagram exceeds Hysteria v2.12.3 limits (nonempty, at most 4096 bytes including address/header)")
	}
	return d.conn.Send(p, target)
}

// Cancellation ends this association, unblocking Receive without allocating
// a goroutine for every packet. A canceled association must not be reused.
func (d *datagrams) ReadFrom(ctx context.Context) ([]byte, string, error) {
	d.receive.Lock()
	defer d.receive.Unlock()
	if err := ctx.Err(); err != nil {
		d.Close()
		return nil, "", err
	}
	stop := context.AfterFunc(ctx, func() { d.Close() })
	p, addr, err := d.conn.Receive()
	stop()
	if ctx.Err() != nil {
		return nil, "", ctx.Err()
	}
	return p, addr, err
}

func (d *datagrams) Close() error {
	d.once.Do(func() { d.closed.Store(true); d.conn.Close() })
	return nil
}
