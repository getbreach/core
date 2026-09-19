package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"breach-nativecore/bridge"
	"breach-nativecore/hy2"
	"breach-nativecore/inbound"
	"breach-nativecore/packetio"
	"breach-nativecore/reconnect"
	"breach-nativecore/routing"
	"breach-nativecore/systemtun"
	"breach-nativecore/transport"
	breachmobile "breach/mobile"
	coreErrors "github.com/apernet/hysteria/core/v2/errors"
	quic "github.com/apernet/quic-go"
)

// The existing TURN library owns process-global DNS/socket hooks. Serialize its
// lifecycle until those hooks have been made instance-local.
var turnOwner sync.Mutex
var errUDPDisabled = errors.New("Hy2 server must enable UDP")

type logger func(string, ...any)

func (l logger) Log(s string) { l("TURN: %s", s) }

type protector struct{ control routing.Control }

func (p protector) Protect(fd int) bool {
	return p.control == nil || p.control("", "", rawFD(fd)) == nil
}

type rawFD int

func (f rawFD) Control(fn func(uintptr)) error { fn(uintptr(f)); return nil }
func (f rawFD) Read(func(uintptr) bool) error  { return errors.New("unsupported raw read") }
func (f rawFD) Write(func(uintptr) bool) error { return errors.New("unsupported raw write") }

// packetio.Run owns its device. Remove DNS/routes while utun still exists, then
// close the fd; this also makes setup failures and ordinary cancellation agree.
type configuredTUN struct {
	*packetio.TUN
	network *systemtun.Session
	logf    func(string, ...any)
	once    sync.Once
	err     error
}

func (t *configuredTUN) Close() error {
	t.once.Do(func() {
		if e := t.network.Close(); e != nil {
			t.logf("TUN cleanup: %v", e)
		}
		t.err = t.TUN.Close()
	})
	return t.err
}

func permanent(err error) bool {
	var auth coreErrors.AuthError
	var cert *tls.CertificateVerificationError
	// Chrome/uTLS mode can flatten verification errors into a local QUIC
	// INTERNAL_ERROR, losing their Go cause. Classify by the typed protocol code,
	// never by matching error text. Local TLS/internal failures are not outages.
	var transportError *quic.TransportError
	if errors.As(err, &transportError) && !transportError.Remote {
		code := uint64(transportError.ErrorCode)
		if transportError.ErrorCode == quic.InternalError || (code >= 0x100 && code <= 0x1ff) {
			return true
		}
	}
	return errors.As(err, &auth) || errors.As(err, &cert) || errors.Is(err, hy2.ErrCertificatePinMismatch) || errors.Is(err, errUDPDisabled)
}

// Run keeps the inbound and router alive across session replacements, including
// FakeIP state. It returns only on shutdown or an unrecoverable error.
func Run(ctx context.Context, cfg Config, logf func(string, ...any)) error {
	parent := ctx
	if err := cfg.Validate(); err != nil {
		return err
	}
	if cfg.AutoRoute && os.Geteuid() != 0 {
		return errors.New("automatic macOS TUN requires root; run breach with sudo")
	}
	if logf == nil {
		logf = func(string, ...any) {}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if cfg.AutoRoute && cfg.DirectInterface == "" {
		cfg.DirectInterface = "auto"
	}
	var control routing.Control
	if cfg.DirectInterface != "" {
		var err error
		control, err = routing.InterfaceControl(cfg.DirectInterface)
		if err != nil {
			return err
		}
	}
	remote, mode := cfg.Remote, cfg.Mode
	var turn *breachmobile.Tunnel
	if mode == "turn" {
		if !turnOwner.TryLock() {
			return errors.New("only one embedded TURN engine may run per process")
		}
		defer turnOwner.Unlock()
		body, err := cfg.turnJSON()
		if err != nil {
			return err
		}
		if err = ctx.Err(); err != nil {
			return err
		}
		previousResolver := net.DefaultResolver
		turn, err = breachmobile.StartTransport(body, protector{control}, logger(logf))
		if err != nil {
			net.DefaultResolver = previousResolver
			return err
		}
		defer func() { turn.Stop(); net.DefaultResolver = previousResolver }()
		remote, mode = turn.LocalAddress(), "pipe"
		logf("TURN embedded in this process; private UDP handoff on %s", remote)
	}
	if cfg.TLS.Insecure {
		logf("Hy2 TLS certificate verification explicitly disabled in this config")
	}
	r := reconnect.New(ctx, func(ctx context.Context) (reconnect.Session, error) {
		pc, peer, err := transport.OpenControlled(remote, mode, control)
		if err != nil {
			return nil, err
		}
		c, err := hy2.Dial(ctx, pc, peer, cfg.Password, cfg.TLS)
		if err != nil {
			return nil, err
		}
		if !c.UDPEnabled {
			c.Close()
			return nil, errUDPDisabled
		}
		return c, nil
	}, reconnect.Options{Logf: logf, Permanent: permanent})
	defer r.Close()
	startup, stop := context.WithTimeout(ctx, time.Duration(cfg.StartupTimeoutSeconds)*time.Second)
	err := r.WaitReady(startup)
	stop()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("Hy2 startup: %w", err)
	}
	router, err := routing.New(cfg.Routing, r, routing.Options{Control: control})
	if err != nil {
		return err
	}
	defer router.Close()
	var ln net.Listener
	var b *bridge.Bridge
	var tun *packetio.TUN
	var device packetio.Device
	var network *systemtun.Session
	if cfg.Inbound == "socks" {
		ln, err = net.Listen("tcp", cfg.SOCKSListen)
		if err != nil {
			return err
		}
		defer ln.Close()
		logf("SOCKS5 ready on %s (TCP + UDP over Hy2)", ln.Addr())
	} else {
		b, err = bridge.New(router, bridge.Options{MTU: cfg.MTU})
		if err != nil {
			return err
		}
		defer b.Close()
		tun, err = packetio.OpenTUN(cfg.Interface)
		if err != nil {
			return err
		}
		defer tun.Close()
		device = tun
		if cfg.AutoRoute {
			network, err = systemtun.Setup(ctx, tun.Name(), cfg.MTU, cfg.DirectInterface)
			if err != nil {
				return err
			}
			device = &configuredTUN{TUN: tun, network: network, logf: logf}
			defer device.Close()
			logf("TUN %s ready; automatic IPv4/IPv6 routes and temporary DNS enabled", tun.Name())
		} else {
			logf("TUN %s ready; set MTU=%d and routes/DNS manually", tun.Name(), cfg.MTU)
		}
	}
	var wg sync.WaitGroup
	// Register this after the resource defers so workers stop before teardown.
	defer func() { cancel(); wg.Wait() }()
	if network != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-ctx.Done():
			case <-network.Done():
				logf("temporary TUN network owner stopped; shutting down TUN")
				cancel()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var prepare func(context.Context) (bool, error)
		if network != nil {
			prepare = network.Refresh
		}
		watchNetwork(ctx, prepare, func() {
			logf("Network changed or system resumed; rebuilding transport")
			if turn != nil {
				turn.NetworkChanged()
			}
			r.Reset()
		}, func(err error) { logf("Waiting for physical network/routes: %v", err) })
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		select {
		case <-ctx.Done():
		case <-r.Done():
			cancel()
		}
	}()
	if ln != nil {
		err = inbound.ServeSOCKS(ctx, ln, router)
	} else {
		err = packetio.Run(ctx, b, device)
	}
	if parent.Err() != nil {
		return parent.Err()
	}
	select {
	case <-r.Done():
		if ctx.Err() != nil {
			return r.Err()
		}
	default:
	}
	return err
}
