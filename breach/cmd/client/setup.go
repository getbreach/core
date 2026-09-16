package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"breach/maxproto"
	"breach/wbproto"
)

// errSetupCancelled is returned when the user aborts a menu (Ctrl-C / Esc). main
// treats it as a clean exit, not a failure.
var errSetupCancelled = errors.New("setup cancelled")

// tr is the active translation for the wizard's line-prompt helpers (menus take
// their strings explicitly). Set at the top of runSetup.
var tr = ruMsgs

// wantSetup reports whether a bare run should drop into the setup wizard: an
// interactive terminal, no provider chosen, no config file yet, and none of the
// flags that already say "I know what I'm doing". Headless/piped/Android runs
// (no TTY) never enter it — they fall through to the normal config-required path
// so nothing hangs waiting on stdin.
func wantSetup(providerFlag, cfgPath, sessionPath, wbSession, server, socksListen string) bool {
	if providerFlag != "" {
		return false
	}
	if sessionPath != "" || wbSession != "" || server != "" || socksListen != "" {
		return false
	}
	if _, err := os.Stat(cfgPath); err == nil {
		return false // already configured
	}
	return stdinIsTTY()
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// runSetup is the interactive first-run wizard. It asks for a language, picks a
// provider (arrow-key menus), walks the user through that provider's login,
// collects the tunnel settings, writes a self-contained config to cfgPath, and
// asks whether to start now. It returns the chosen provider and whether the
// caller should proceed into the run using that config. Progress goes to stderr.
func runSetup(cfgPath, dnsFlag string) (provider string, runNow bool, err error) {
	r := bufio.NewReader(os.Stdin)
	out := os.Stderr

	// 0) Language — before anything else, so every prompt below is localized.
	li, err := selectMenu(r, "Language / Язык", []string{"Русский", "English"}, 0, "↑/↓ · Enter")
	if err != nil {
		return "", false, err
	}
	tr = ruMsgs
	if li == 1 {
		tr = enMsgs
	}
	t := tr

	fmt.Fprintf(out, "\n%s\n", t.banner)
	if _, statErr := os.Stat(cfgPath); statErr == nil {
		fmt.Fprintf(out, t.overwrite+"\n", cfgPath)
	}

	// The API host must resolve during login; force an explicit resolver now
	// (same as a normal run) so login works even without /etc/resolv.conf.
	setResolver(dnsFlag)

	// 1) Provider.
	pi, err := selectMenu(r, t.provTitle, []string{t.provMax, t.provWB}, 0, t.menuHelp)
	if err != nil {
		return "", false, err
	}
	provider = "max"
	if pi == 1 {
		provider = "wb"
	}

	// 2) Exit mode.
	mi, err := selectMenu(r, t.modeTitle, []string{t.modeWG, t.modeSocks}, 0, t.menuHelp)
	if err != nil {
		return "", false, err
	}
	socksMode := mi == 1

	// 3) Server (the breach-server exit) — needed in both modes.
	server := askRequired(r, t.server)

	// 4) Mode-specific listener settings.
	var wgListen, socksAddr, socksToken, socksPin, socksUser, socksPass string
	if socksMode {
		socksAddr = ask(r, t.socksAddr, "127.0.0.1:1080")
		socksToken = askRequired(r, t.socksToken)
		socksPin = askRequired(r, t.socksPin)
		socksUser = ask(r, t.socksUser, "")
		if socksUser != "" {
			socksPass = ask(r, t.socksPass, "")
		}
	} else {
		wgListen = ask(r, t.wgListen, "127.0.0.1:51821")
	}

	// 5) Pool sizing.
	streams := askInt(r, t.streams, 4)
	mints := askInt(r, t.mints, 2)

	dns := strings.TrimSpace(dnsFlag) // stored in the config only if the user set one

	// 6) Provider login + config write.
	switch provider {
	case "max":
		phone := askRequired(r, t.maxPhone)
		cfg, aerr := authenticateMax(phone, "", "", "")
		if aerr != nil {
			return "", false, fmt.Errorf("%s: %w", t.maxLoginErr, aerr)
		}
		cfg.Server = server
		cfg.WGListen = wgListen
		cfg.Streams = streams
		cfg.Mints = mints
		cfg.DNS = dns
		cfg.Socks, cfg.SocksToken, cfg.SocksPin = socksAddr, socksToken, socksPin
		cfg.SocksUser, cfg.SocksPass = socksUser, socksPass
		if werr := writeMaxConfig(cfgPath, cfg); werr != nil {
			return "", false, werr
		}

	case "wb":
		wbSession := filepath.Join(filepath.Dir(cfgPath), "wb-session.json")
		fmt.Fprintf(out, "\n"+t.wbSignIn+"\n", wbSession)
		if lerr := runWBLoginR(r, wbSession); lerr != nil {
			return "", false, fmt.Errorf("WB login: %w", lerr)
		}
		chat := ask(r, t.wbChat, "")
		var callee string
		if chat == "" {
			callee = askRequired(r, t.wbCallee)
		} else {
			validateWBChat(wbSession, chat)
		}
		wc := wbConfig{
			Provider:   "wb",
			Server:     server,
			WGListen:   wgListen,
			Streams:    streams,
			Mints:      mints,
			DNS:        dns,
			WBSession:  wbSession,
			WBChat:     chat,
			WBCallee:   callee,
			WBCallType: "AUDIO",
			Socks:      socksAddr,
			SocksToken: socksToken,
			SocksPin:   socksPin,
			SocksUser:  socksUser,
			SocksPass:  socksPass,
		}
		if werr := writeJSONConfig(cfgPath, wc); werr != nil {
			return "", false, werr
		}
	}

	fmt.Fprintf(out, "\n"+t.written+"\n", cfgPath)
	suffix := ""
	if cfgPath != "config.json" {
		suffix = " -config " + cfgPath
	}
	fmt.Fprintf(out, t.futureRuns+"\n", suffix)

	si, err := selectMenu(r, "\n"+t.startNow, []string{t.yes, t.no}, 0, t.menuHelp)
	if err != nil {
		return "", false, err
	}
	return provider, si == 0, nil
}

// validateWBChat resolves a WB personal chat to its single peer, turning "the
// tunnel silently fails minutes later" into an immediate warning. A failure here
// is only a warning: the chat is still written to the config.
func validateWBChat(sessionPath, chat string) {
	client, err := wbproto.Load(sessionPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, tr.wbWarnOpen+"\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	peer, err := client.ResolvePeer(ctx, chat)
	if err != nil {
		fmt.Fprintf(os.Stderr, tr.wbWarnResolve+"\n", chat, err)
		return
	}
	fmt.Fprintf(os.Stderr, tr.wbChatOK+"\n", chat, peer)
}

// writeMaxConfig marshals a MAX Config and tags it with "provider":"max" so a
// bare future run auto-detects the branch. Written 0600 — it holds the token.
func writeMaxConfig(path string, cfg *maxproto.Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	m["provider"] = "max"
	return writeJSONConfig(path, m)
}

func writeJSONConfig(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

// --- arrow-key menu ---------------------------------------------------------

// selectMenu shows an arrow-key menu on the terminal and returns the chosen
// index. ↑/↓ (or k/j) move, Enter selects, Ctrl-C/Esc cancels, a digit jumps.
// When raw mode is unavailable (no TTY, unsupported platform) it degrades to a
// numbered prompt read from r.
func selectMenu(r *bufio.Reader, title string, options []string, def int, help string) (int, error) {
	fd := int(os.Stdin.Fd())
	st, err := makeRawState(fd)
	if err != nil {
		return numberedMenu(r, title, options, def)
	}
	defer restoreState(fd, st)

	w := os.Stderr
	cur := def
	if cur < 0 || cur >= len(options) {
		cur = 0
	}
	fmt.Fprintf(w, "\r\n%s\r\n", title)
	if help != "" {
		fmt.Fprintf(w, "\x1b[90m%s\x1b[0m\r\n", help) // dim
	}
	draw := func() {
		for i, o := range options {
			if i == cur {
				fmt.Fprintf(w, "\x1b[2K\r\x1b[36m❯ %s\x1b[0m\r\n", o) // cyan + arrow
			} else {
				fmt.Fprintf(w, "\x1b[2K\r  %s\r\n", o)
			}
		}
	}
	draw()

	buf := make([]byte, 8)
	for {
		n, rerr := os.Stdin.Read(buf)
		if rerr != nil || n == 0 {
			return cur, nil
		}
		switch b := buf[0]; {
		case b == 3: // Ctrl-C
			fmt.Fprint(w, "\r\n")
			return 0, errSetupCancelled
		case b == '\r' || b == '\n':
			return cur, nil
		case b == 0x1b && n >= 3 && buf[1] == '[':
			switch buf[2] {
			case 'A':
				cur = (cur - 1 + len(options)) % len(options)
			case 'B':
				cur = (cur + 1) % len(options)
			}
		case b == 0x1b: // lone Esc
			fmt.Fprint(w, "\r\n")
			return 0, errSetupCancelled
		case b == 'k':
			cur = (cur - 1 + len(options)) % len(options)
		case b == 'j':
			cur = (cur + 1) % len(options)
		case b >= '1' && b <= '9':
			if idx := int(b - '1'); idx < len(options) {
				cur = idx
			}
		}
		fmt.Fprintf(w, "\x1b[%dA", len(options)) // back to the top of the list
		draw()
	}
}

// numberedMenu is the no-raw-terminal fallback for selectMenu.
func numberedMenu(r *bufio.Reader, title string, options []string, def int) (int, error) {
	fmt.Fprintln(os.Stderr, title)
	for i, o := range options {
		fmt.Fprintf(os.Stderr, "  %d) %s\n", i+1, o)
	}
	for {
		v := ask(r, "#", strconv.Itoa(def+1))
		if n, err := strconv.Atoi(v); err == nil && n >= 1 && n <= len(options) {
			return n - 1, nil
		}
		if stdinClosed {
			return def, nil
		}
	}
}

// --- line-prompt helpers (all read from r, all write prompts to stderr) -----

// stdinClosed is set once a read hits EOF (Ctrl-D, or exhausted piped input),
// so the looping prompts below abort instead of spinning forever.
var stdinClosed bool

func ask(r *bufio.Reader, label, def string) string {
	if def != "" {
		fmt.Fprintf(os.Stderr, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(os.Stderr, "%s: ", label)
	}
	line, err := r.ReadString('\n')
	if err != nil && line == "" {
		stdinClosed = true
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return def
	}
	return line
}

// abortOnClosedStdin exits the wizard cleanly if stdin is gone. Called from the
// looping prompts so EOF ends the run instead of an infinite reprompt.
func abortOnClosedStdin() {
	if stdinClosed {
		fmt.Fprintln(os.Stderr, "\n"+errSetupCancelled.Error())
		os.Exit(1)
	}
}

func askRequired(r *bufio.Reader, label string) string {
	for {
		if v := ask(r, label, ""); v != "" {
			return v
		}
		abortOnClosedStdin()
		fmt.Fprintln(os.Stderr, tr.required)
	}
}

func askInt(r *bufio.Reader, label string, def int) int {
	for {
		v := ask(r, label, strconv.Itoa(def))
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			return n
		}
		abortOnClosedStdin()
		fmt.Fprintln(os.Stderr, tr.positiveNum)
	}
}

func askYesNo(r *bufio.Reader, label string, defYes bool) bool {
	hint := "[Y/n]"
	if !defYes {
		hint = "[y/N]"
	}
	fmt.Fprintf(os.Stderr, "%s %s: ", label, hint)
	line, _ := r.ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return defYes
	}
}
