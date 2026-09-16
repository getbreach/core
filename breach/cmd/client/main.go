// breach-client: censored-side endpoint. Mints MAX TURN credentials, opens a
// pool of TURN allocations, runs a real DTLS-SRTP session over each (handshake
// then SRTP-AEAD media — exactly a WebRTC call on the wire), and shards local
// WireGuard/Hysteria UDP across them. A low-rate bidirectional SRTP keepalive
// keeps every allocation symmetric — MAX throttles unidirectional relay to ~8 pps.
// (Sustained DTLS app-data is throttled; SRTP media is not — see README.)
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"breach/maxproto"
	"breach/media"
	"breach/provider"
	"breach/statusline"
	"breach/turn"
	"breach/wbproto"
)

// stream = one TURN allocation running a DTLS-SRTP session (each allocation is a
// separate WebRTC-like media stream: DTLS handshake then SRTP-AEAD media).
type stream struct {
	a    *turn.Alloc
	sess *media.Session
}

func (s *stream) close() { s.a.Close() }

// stripeChunk is how many consecutive packets ride one allocation before the
// round-robin advances. Striping every single packet across relays with
// different RTTs delivers the inner flow badly out of order: WireGuard accepts
// the reordered transport packets (its replay window is wide) but hands them to
// the tun out of sequence, so the inner TCP sees constant reordering, reads it
// as loss, and collapses its window — the whole tunnel then crawls at a small
// fraction of the relays' aggregate. Keeping a burst on one relay before
// rotating holds each flow near-ordered while still spreading load; a full
// sweep of the pool stays well inside WireGuard's replay window.
// Settable so the value can be measured rather than assumed: the optimum depends
// on how far apart the relays' RTTs are. -stripe 1 restores per-packet striping.
var stripeChunk uint64 = 16

type pool struct {
	mu      sync.RWMutex
	streams []*stream
	rr      uint64
}

func (p *pool) set(s []*stream) []*stream {
	p.mu.Lock()
	old := p.streams
	p.streams = s
	p.mu.Unlock()
	return old
}

func (p *pool) snapshot() []*stream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]*stream(nil), p.streams...)
}

func (p *pool) pick() *stream {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if len(p.streams) == 0 {
		return nil
	}
	i := atomic.AddUint64(&p.rr, 1)
	// Divide BEFORE narrowing: on a 32-bit int, converting the raw counter first
	// wraps negative after a few tens of billions of packets and indexes out of
	// range. Kept in uint64 the whole way.
	return p.streams[(i/stripeChunk)%uint64(len(p.streams))]
}

// clientID tags every upstream packet so one server can demux multiple clients.
var clientID [8]byte

// socksIn is non-nil only in stream mode: downstream payloads go to QUIC
// instead of the local UDP mouth.
var socksIn chan []byte

var (
	wgConn      *net.UDPConn
	wgClient    atomic.Pointer[net.UDPAddr]
	upCount     atomic.Int64
	downAll     atomic.Int64
	downRTP     atomic.Int64
	downDecFail atomic.Int64
	downData    atomic.Int64
)

func main() {
	cfgPath := flag.String("config", "config.json", "MAX mint + tunnel config")
	server := flag.String("server", "", "breach-server public UDP address ip:port")
	wgListen := flag.String("wg-listen", "127.0.0.1:51821", "local UDP the WireGuard client targets")
	streams := flag.Int("streams", 4, "allocations per minted credential")
	mints := flag.Int("mints", 2, "credentials to mint (each rings the callee once)")
	turnOverride := flag.String("turn", "", "force a TURN host:port (default: each credential's own)")
	turnTransport := flag.String("turn-transport", "", "TURN transport: auto|udp|tcp (default from config, else auto)")
	kaMs := flag.Int("keepalive-ms", 50, "keepalive interval per allocation (ms)")
	login := flag.String("login", "", "authenticate a phone number (+7...) by SMS, save the session and print a config block")
	loginHost := flag.String("login-host", "", "MAX API host for -login (default "+maxproto.DefaultHost+")")
	sessionPath := flag.String("session", "", "session file: -login writes it, and a later run loads the token from it instead of -config")
	device := flag.String("device", "", `-login: spoof cosmetic device info, JSON e.g. '{"deviceName":"samsung SM-S918B","osVersion":"Android 14","screen":"480dpi 480dpi 1440x3088"}' (appVersion/arch stay locked)`)
	dnsFlag := flag.String("dns", "", "resolver for the MAX API host (default 1.1.1.1:53 or config \"dns\")")
	socksListen := flag.String("socks", "", "serve SOCKS5 here instead of the UDP mouth: the exit dials out itself, so no WireGuard/sing-box and no root (e.g. 127.0.0.1:1080)")
	socksToken := flag.String("socks-token", "", "this client's password on the exit (stream mode)")
	socksPin := flag.String("socks-pin", "", "sha256 of the exit's stream-mode certificate, from its /etc/breach/qtun-pin")
	socksUser := flag.String("socks-user", "", "optional username for the local SOCKS5 listener")
	socksPass := flag.String("socks-pass", "", "optional password for the local SOCKS5 listener")
	stripe := flag.Int("stripe", 16, "consecutive packets per allocation before the round-robin advances (1 = per-packet striping)")
	providerName := flag.String("provider", "", "TURN provider: max|wb (default: from config's \"provider\", else max)")
	setup := flag.Bool("setup", false, "run the interactive setup wizard (pick provider, log in, write a config), then offer to start")
	wbSession := flag.String("wb-session", "", "provider=wb: WBID session file")
	wbChat := flag.String("wb-chat", "", "provider=wb: personal chat 'chats/<id>' to resolve the peer from")
	wbCallee := flag.String("wb-callee", "", "provider=wb: peer userID to call (alternative to -wb-chat)")
	wbCallType := flag.String("wb-calltype", "AUDIO", "provider=wb: call type AUDIO|VIDEO")
	wbLogin := flag.Bool("wb-login", false, "provider=wb: authenticate via WB ID (prints a link, reads the callback URL) and save the session to -wb-session")
	flag.BoolVar(&maxproto.Verbose, "v", false, "verbose")
	flag.Parse()

	// -login runs before the config is loaded: its whole point is producing a
	// config for someone who has no token yet.
	if *login != "" {
		setResolver(*dnsFlag)
		if err := runLogin(*login, *loginHost, *sessionPath, *device); err != nil {
			log.Fatalf("login: %v", err)
		}
		return
	}

	// WB ID browser-callback login (provider=wb): also runs before any config is
	// loaded — its whole point is producing a session for someone who has none.
	if *wbLogin {
		setResolver(*dnsFlag)
		if err := runWBLogin(*wbSession); err != nil {
			log.Fatalf("wb-login: %v", err)
		}
		return
	}

	// Setup wizard: explicit -setup, or a bare interactive first run with nothing
	// configured yet. It picks a provider, logs the user in, writes a runnable
	// config to -config, and offers to start right away. wantSetup is guarded on a
	// TTY so headless/piped/Android runs never block on stdin — they fall through
	// to the normal "config required" path.
	if *setup || wantSetup(*providerName, *cfgPath, *sessionPath, *wbSession, *server, *socksListen) {
		prov, runNow, err := runSetup(*cfgPath, *dnsFlag)
		if err == errSetupCancelled {
			fmt.Fprintln(os.Stderr, "setup cancelled")
			return
		}
		if err != nil {
			log.Fatalf("setup: %v", err)
		}
		if !runNow {
			return
		}
		// The wizard wrote everything to *cfgPath; let the config drive the run.
		*providerName = prov
	}

	rand.Read(clientID[:])

	if *stripe < 1 {
		log.Fatalf("-stripe must be >= 1 (got %d)", *stripe)
	}
	stripeChunk = uint64(*stripe)

	// Tunnel settings default to the flags; the config overrides them (so an
	// Android/no-args or wizard-written run works from config alone). Socks-mode
	// settings live in the same locals so config can drive stream mode too.
	srv, wgl := *server, *wgListen
	nStreams, nMints := *streams, *mints
	socksAddr, socksTok, socksPinV := *socksListen, *socksToken, *socksPin
	socksU, socksP := *socksUser, *socksPass

	// Resolve the provider: an explicit -provider wins; otherwise the config file
	// declares it (wizard/WB configs carry "provider"), else MAX.
	prov := *providerName
	if prov == "" {
		prov = detectProvider(*cfgPath)
	}
	if prov == "" {
		prov = "max"
	}

	// The provider decides only WHERE the TURN creds come from; everything below
	// buildPool (allocations, DTLS-SRTP, the pool) is identical for MAX and WB.
	var minters []provider.Minter
	switch prov {
	case "max":
		cfg, err := loadClientConfig(*cfgPath, *sessionPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		if *turnTransport != "" {
			cfg.TurnTransport = *turnTransport
		}
		dns := *dnsFlag
		if dns == "" {
			dns = cfg.DNS
		}
		setResolver(dns)
		if cfg.Server != "" {
			srv = cfg.Server
		}
		if cfg.WGListen != "" {
			wgl = cfg.WGListen
		}
		if cfg.Streams > 0 {
			nStreams = cfg.Streams
		}
		if cfg.Mints > 0 {
			nMints = cfg.Mints
		}
		// Stream mode from config when no -socks flag was given.
		if socksAddr == "" && cfg.Socks != "" {
			socksAddr, socksTok, socksPinV = cfg.Socks, cfg.SocksToken, cfg.SocksPin
			socksU, socksP = cfg.SocksUser, cfg.SocksPass
		}
		minters = cfg.Minters()
	case "wb":
		// WB config parity with MAX: load tunnel/session/callee from the config
		// file, then let any explicit flag override it (so both a bare config run
		// and the old all-flags run work).
		wc, err := loadWBConfig(*cfgPath)
		if err != nil {
			log.Fatalf("wb config: %v", err)
		}
		wbSess := firstNonEmpty(*wbSession, wc.WBSession)
		wbCh := firstNonEmpty(*wbChat, wc.WBChat)
		wbCe := firstNonEmpty(*wbCallee, wc.WBCallee)
		wbCt := *wbCallType
		if wbCt == "AUDIO" && wc.WBCallType != "" { // AUDIO is the flag default
			wbCt = wc.WBCallType
		}
		transport := firstNonEmpty(*turnTransport, wc.Transport)
		dns := firstNonEmpty(*dnsFlag, wc.DNS)
		setResolver(dns)
		if srv == "" {
			srv = wc.Server
		}
		if wgl == "127.0.0.1:51821" && wc.WGListen != "" { // wg-listen flag default
			wgl = wc.WGListen
		}
		if nStreams == 4 && wc.Streams > 0 { // streams flag default
			nStreams = wc.Streams
		}
		if nMints == 2 && wc.Mints > 0 { // mints flag default
			nMints = wc.Mints
		}
		if socksAddr == "" && wc.Socks != "" {
			socksAddr, socksTok, socksPinV = wc.Socks, wc.SocksToken, wc.SocksPin
			socksU, socksP = wc.SocksUser, wc.SocksPass
		}
		m, err := wbproto.NewMinter(wbSess, wbCh, wbCe, wbCt, transport)
		if err != nil {
			log.Fatalf("wb: %v", err)
		}
		minters = []provider.Minter{m}
	default:
		log.Fatalf("unknown -provider %q (want max|wb)", prov)
	}

	if srv == "" {
		log.Fatal("need server (flag -server or \"server\" in config.json)")
	}
	peer, err := net.ResolveUDPAddr("udp", srv)
	if err != nil {
		log.Fatalf("resolve server: %v", err)
	}
	streamMode := socksAddr != ""
	if streamMode {
		// Downstream goes to QUIC, not to a local socket. Must be in place before
		// buildPool, which starts the per-allocation readers.
		socksIn = make(chan []byte, 1024)
	} else {
		laddr, err := net.ResolveUDPAddr("udp", wgl)
		if err != nil {
			log.Fatalf("resolve wg-listen: %v", err)
		}
		wgConn, err = net.ListenUDP("udp", laddr)
		if err != nil {
			log.Fatalf("listen %s: %v", wgl, err)
		}
		wgConn.SetReadBuffer(16 << 20)
		wgConn.SetWriteBuffer(16 << 20)
	}

	kaInterval := time.Duration(*kaMs) * time.Millisecond
	p := &pool{}
	expiry := buildPool(p, minters, peer, nMints, nStreams, *turnOverride, kaInterval)
	if len(p.snapshot()) == 0 {
		log.Fatal("no allocations established")
	}

	// On a terminal the per-second stat refreshes on one sticky line and real log
	// lines scroll above it; off a terminal it stays plain line-by-line.
	sl := statusline.New(os.Stderr)
	if sl.TTY() {
		log.SetOutput(sl.Writer())
	}

	go turnKeepaliveLoop(p)
	go remintLoop(p, minters, peer, nMints, nStreams, *turnOverride, kaInterval, expiry)
	go func() {
		for range time.Tick(time.Second) {
			line := fmt.Sprintf("[stat] upstream=%d turnSends=%d downAll=%d downRTP=%d decFail=%d downData=%d",
				upCount.Load(), turn.SentPackets.Load(), downAll.Load(), downRTP.Load(), downDecFail.Load(), downData.Load())
			if sl.TTY() {
				sl.Set(line)
			} else {
				log.Print(line)
			}
		}
	}()

	if streamMode {
		log.Printf("breach-client: %d allocations up, server=%s", len(p.snapshot()), srv)
		if err := runSocksMode(p, peer, socksAddr, socksTok, socksPinV, socksU, socksP); err != nil {
			log.Fatalf("socks: %v", err)
		}
		return
	}

	log.Printf("breach-client: %d allocations up, wg-listen=%s server=%s", len(p.snapshot()), wgl, srv)

	buf := make([]byte, 65536)
	for {
		n, src, err := wgConn.ReadFromUDP(buf)
		if err != nil {
			log.Fatalf("wg read: %v", err)
		}
		wgClient.Store(src)
		if s := p.pick(); s != nil {
			msg := make([]byte, len(clientID)+n)
			copy(msg, clientID[:])
			copy(msg[len(clientID):], buf[:n])
			if wire, err := s.sess.Protect(media.PTData, msg); err == nil {
				if s.a.Send(wire) == nil {
					upCount.Add(1)
				}
			}
		}
	}
}

func buildPool(p *pool, minters []provider.Minter, peer *net.UDPAddr, mints, streams int, turnOverride string, ka time.Duration) time.Time {
	var out []*stream
	earliest := time.Time{}

	// One Minter per account (just the base identity when there is no accounts[]
	// list). Spreading mints across accounts is how throughput scales past the
	// per-account relay cap — each account has its own throttle bucket.
	for ai, mtr := range minters {
		// Each mint creates its OWN group call by default so it gets its own
		// throttle bucket (throughput scales with mints). A provider that reuses a
		// conference (MAX ReuseGroupCall) instead threads the link back — fewer
		// calls in history, but one shared bucket.
		reuseLink := ""
		for m := 0; m < mints; m++ {
			creds, err := mtr.Mint(reuseLink)
			if err != nil {
				log.Printf("acct%d mint %d failed: %v", ai, m, err)
				continue
			}
			if mtr.Reuses() {
				reuseLink = creds.JoinLink
			}
			if earliest.IsZero() || creds.ExpiresAt.Before(earliest) {
				earliest = creds.ExpiresAt
			}
			hosts := creds.TurnHosts
			if turnOverride != "" {
				hosts = []string{turnOverride}
			}
			ok := 0
			for i := 0; i < streams; i++ {
				host := hosts[i%len(hosts)]
				a, err := turn.NewAlloc(host, creds.Username, creds.Credential, peer, 0x4000, creds.Transport)
				if err != nil {
					log.Printf("acct%d mint %d alloc %d (%s): %v", ai, m, i, host, err)
					continue
				}
				sess, err := media.Client(a.NetConn()) // DTLS handshake over the channel
				if err != nil {
					log.Printf("acct%d mint %d dtls %d (%s): %v", ai, m, i, host, err)
					a.Close()
					continue
				}
				s := &stream{a: a, sess: sess}
				startReader(s)
				go keepalive(s, ka)
				out = append(out, s)
				ok++
			}
			log.Printf("acct%d mint %d: %d/%d allocations on %v (cred expires %s)",
				ai, m, ok, streams, hosts, creds.ExpiresAt.Format(time.RFC3339))
		}
	}

	old := p.set(out)
	for _, s := range old {
		s.close()
	}
	return earliest
}

// startReader drains one stream's inbound to the WireGuard client, dropping
// keepalive RTP packets and anything not framed as our data.
func startReader(s *stream) {
	go func() {
		for raw := range s.a.In() {
			downAll.Add(1)
			if !media.IsRTP(raw) { // drop late DTLS handshake retransmits
				continue
			}
			downRTP.Add(1)
			pt, payload, err := s.sess.Unprotect(raw)
			if err != nil {
				downDecFail.Add(1)
				continue
			}
			if pt != media.PTData {
				continue
			}
			downData.Add(1)
			if socksIn != nil {
				// Copy: payload aliases the reader's buffer, which is reused.
				pkt := make([]byte, len(payload))
				copy(pkt, payload)
				select {
				case socksIn <- pkt:
				default: // receiver is behind; QUIC recovers from a lost datagram
				}
				continue
			}
			if c := wgClient.Load(); c != nil {
				wgConn.WriteToUDP(payload, c)
			}
		}
	}()
}

// keepalive sends small SRTP "media" packets so MAX keeps this allocation's
// client→server direction unthrottled even when real upstream is idle/asymmetric.
func keepalive(s *stream, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for range t.C {
		// keepalive carries the clientID too, so the server can register this
		// allocation under the right client before any data flows.
		wire, err := s.sess.Protect(media.PTKeepalive, clientID[:])
		if err != nil {
			return
		}
		if err := s.a.Send(wire); err != nil {
			return
		}
	}
}

// turnKeepaliveLoop refreshes each allocation + channel binding before their
// ~600s TURN lifetime expires (otherwise the relay stops forwarding downstream).
func turnKeepaliveLoop(p *pool) {
	t := time.NewTicker(4 * time.Minute)
	defer t.Stop()
	for range t.C {
		for _, s := range p.snapshot() {
			if err := s.a.Keepalive(); err != nil {
				log.Printf("turn keepalive: %v", err)
			}
		}
	}
}

func remintLoop(p *pool, minters []provider.Minter, peer *net.UDPAddr, mints, streams int, turnOverride string, ka time.Duration, expiry time.Time) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for range t.C {
		if time.Until(expiry) > 20*time.Minute {
			continue
		}
		log.Printf("re-minting (creds expire %s)...", expiry.Format(time.RFC3339))
		expiry = buildPool(p, minters, peer, mints, streams, turnOverride, ka)
		log.Printf("re-mint done: %d allocations", len(p.snapshot()))
	}
}

// setResolver points the pure-Go resolver at an explicit DNS server. Android has
// no /etc/resolv.conf, so the default resolver fails there; only the MAX API
// host needs resolving, since TURN hosts arrive as IPs.
func setResolver(dns string) {
	if dns == "" {
		dns = "1.1.1.1:53"
	}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "udp", dns)
		},
	}
}

// authenticateMax runs the SMS (and optional 2FA) login for a phone number and
// returns a Config carrying the resulting LOGIN token bound to a freshly minted
// device identity. When sessionPath is set it also saves a session so later runs
// skip the SMS. Shared by -login (which prints a config block) and the setup
// wizard (which folds tunnel settings in and writes a full config).
func authenticateMax(phone, host, sessionPath, deviceJSON string) (*maxproto.Config, error) {
	cfg, err := maxproto.NewAuthConfig(host, nil)
	if err != nil {
		return nil, err
	}
	// Spoof only the cosmetic device fields; appVersion/buildNumber/arch stay
	// locked to the fingerprint build. With no -device, pick a RANDOM device so
	// installs don't all report the same phone.
	if deviceJSON != "" {
		var d maxproto.DeviceInfo
		if err := json.Unmarshal([]byte(deviceJSON), &d); err != nil {
			return nil, fmt.Errorf("bad -device JSON: %w", err)
		}
		cfg.UserAgent = maxproto.UserAgentFor(d)
	} else {
		cfg.UserAgent = maxproto.RandomDeviceUserAgent()
	}
	log.Printf("device: %s", cfg.UserAgent.DeviceName)
	stdin := bufio.NewReader(os.Stdin)

	log.Printf("authenticating %s via %s", maxproto.MaskPhone(maxproto.NormalizePhone(phone)), cfg.Host)
	token, profile, err := maxproto.LoginByPhone(cfg, phone,
		func() (string, error) {
			return prompt(stdin, "SMS code: ")
		},
		func(hint string) (string, error) {
			msg := "2FA password"
			if hint != "" {
				msg += " (hint: " + hint + ")"
			}
			return prompt(stdin, msg+": ")
		},
	)
	if err != nil {
		return nil, err
	}
	cfg.Token = token

	var accountID int64
	if profile != nil {
		accountID = profile.UserID
		if profile.UserID != 0 {
			log.Printf("logged in as %s (id %d)", profile.Name, profile.UserID)
		}
	}

	if sessionPath != "" {
		if err := maxproto.SaveSession(sessionPath, maxproto.SessionFromConfig(cfg, accountID, profile)); err != nil {
			return nil, fmt.Errorf("saving session: %w", err)
		}
		log.Printf("session saved to %s — run with -session %s to reuse it (no SMS)", sessionPath, sessionPath)
	}
	return cfg, nil
}

// runLogin authenticates a phone number by SMS (handling a 2FA password if the
// account has one), prints a config block with the resulting LOGIN token, and —
// when sessionPath is set — saves a session so later runs skip the SMS. The
// token is bound to the generated device identity, so both are kept together;
// re-running -login sends a new SMS and mints a new identity.
func runLogin(phone, host, sessionPath, deviceJSON string) error {
	cfg, err := authenticateMax(phone, host, sessionPath, deviceJSON)
	if err != nil {
		return err
	}

	block := map[string]any{
		"host":            cfg.Host,
		"port":            cfg.Port,
		"token":           cfg.Token,
		"deviceId":        cfg.DeviceID,
		"instanceId":      cfg.InstanceID,
		"clientSessionId": cfg.ClientSessionID,
		"userAgent":       cfg.UserAgent,
		"mintMode":        cfg.MintMode,
		"sdkVersion":      cfg.SdkVersion,
		"clientAppKey":    cfg.ClientAppKey,
		"capabilities":    cfg.Capabilities,
	}
	out, err := json.MarshalIndent(block, "", "  ")
	if err != nil {
		return err
	}
	// Config to stdout, progress to stderr, so this can be redirected to a file.
	fmt.Println(string(out))
	log.Printf("token is bound to deviceId %s — keep them together", cfg.DeviceID)
	return nil
}

// prompt writes a prompt to stderr and reads one line from r.
func prompt(r *bufio.Reader, label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	line, err := r.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading input: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// loadClientConfig builds the mint config from a saved session when sessionPath
// is set (the identity and token come from it, tunnel settings from -config if
// that file exists), otherwise straight from -config. Letting a session drive
// the run is what makes token reuse work: no SMS, no pasted token.
func loadClientConfig(cfgPath, sessionPath string) (*maxproto.Config, error) {
	if sessionPath == "" {
		return maxproto.LoadConfig(cfgPath)
	}
	sess, err := maxproto.LoadSession(sessionPath)
	if err != nil {
		return nil, err
	}
	if sess == nil {
		return nil, fmt.Errorf("session file %s does not exist — run -login -session %s first", sessionPath, sessionPath)
	}
	cfg := sess.Config("")

	// Overlay tunnel settings (server/wgListen/streams/mints/dns) from -config if
	// it is present; the session only carries the MAX identity.
	if tunnel, err := maxproto.LoadConfig(cfgPath); err == nil {
		cfg.Server, cfg.WGListen = tunnel.Server, tunnel.WGListen
		cfg.Streams, cfg.Mints, cfg.DNS = tunnel.Streams, tunnel.Mints, tunnel.DNS
		if tunnel.MintMode != "" {
			cfg.MintMode = tunnel.MintMode
		}
		cfg.CalleeID = tunnel.CalleeID
	}
	log.Printf("using saved session %s (account %d)", sessionPath, sess.AccountID)
	return cfg, nil
}
