// Package engine owns the TURN transport, reconnecting Hy2, routing and inbounds.
package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"

	"breach-nativecore/hy2"
	"breach-nativecore/routing"
	"breach-nativecore/systemtun"
	"breach/maxproto"
	"breach/wbproto"
)

type Config struct {
	Mode string `json:"mode"`
	// Turn embeds the existing MAX/WB transport configuration. wgListen is private
	// to this engine and always replaced with an ephemeral loopback address.
	Turn                  json.RawMessage `json:"turn,omitempty"`
	Remote                string          `json:"remote,omitempty"`
	Password              string          `json:"password"`
	TLS                   hy2.TLSOptions  `json:"tls"`
	Inbound               string          `json:"inbound"`
	SOCKSListen           string          `json:"socksListen"`
	Interface             string          `json:"interface"`
	DirectInterface       string          `json:"directInterface,omitempty"`
	MTU                   int             `json:"mtu"`
	AutoRoute             bool            `json:"autoRoute,omitempty"`
	Routing               routing.Config  `json:"routing"`
	StartupTimeoutSeconds int             `json:"startupTimeoutSeconds,omitempty"`
}

func Load(path, defaultMode string) (Config, error) {
	c := Config{Mode: defaultMode, Inbound: "socks", SOCKSListen: "127.0.0.1:1080", Interface: "breach0", MTU: 1280, StartupTimeoutSeconds: 90}
	if runtime.GOOS == "darwin" {
		c.Interface = "auto"
	}
	if defaultMode == "pipe" {
		c.Remote = "127.0.0.1:51821"
	}
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, (4<<20)+1))
	if err != nil {
		return c, err
	}
	if len(b) > 4<<20 {
		return c, errors.New("config exceeds 4 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, errors.New("config must contain exactly one JSON object")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Mode != "turn" && c.Mode != "pipe" && c.Mode != "direct" {
		return errors.New("mode must be turn, pipe or direct")
	}
	if c.Mode == "turn" {
		if c.Remote != "" {
			return errors.New("remote must be omitted in turn mode; use turn.server")
		}
		if _, err := c.turnJSON(); err != nil {
			return err
		}
	} else {
		if len(c.Turn) > 0 {
			return errors.New("turn configuration requires mode=turn")
		}
		p, err := netip.ParseAddrPort(c.Remote)
		if err != nil || p.Port() == 0 {
			return errors.New("remote must be an IP literal with a nonzero port")
		}
		if c.Mode == "pipe" && !p.Addr().IsLoopback() {
			return errors.New("pipe remote must be loopback")
		}
	}
	if err := hy2.ValidateOptions(c.Password, c.TLS); err != nil {
		return err
	}
	if c.Inbound != "socks" && c.Inbound != "tun" {
		return errors.New("inbound must be socks or tun")
	}
	if c.Inbound == "socks" {
		p, err := netip.ParseAddrPort(c.SOCKSListen)
		if err != nil || !p.Addr().IsLoopback() {
			return errors.New("socksListen must be a loopback IP:port")
		}
	}
	if c.MTU < 1280 || c.MTU > 65535 {
		return errors.New("mtu must be between 1280 and 65535")
	}
	if c.StartupTimeoutSeconds < 1 || c.StartupTimeoutSeconds > 600 {
		return errors.New("startupTimeoutSeconds must be between 1 and 600")
	}
	if err := routing.Validate(c.Routing); err != nil {
		return err
	}
	if c.AutoRoute {
		if !systemtun.Supported() {
			return errors.New("autoRoute is currently supported only on macOS")
		}
		if c.Inbound != "tun" {
			return errors.New("autoRoute requires inbound=tun")
		}
		if !c.Routing.DNS.FakeIP || c.Routing.DNS.StateFile == "" {
			return errors.New("autoRoute requires routing.dns.fakeIP and a persistent stateFile")
		}
	}
	hasDirect := c.Routing.DefaultAction == "direct"
	for _, rule := range c.Routing.Rules {
		hasDirect = hasDirect || rule.Action == "direct"
	}
	if c.Inbound == "tun" && c.DirectInterface == "" && !c.AutoRoute && (hasDirect || c.Mode != "pipe") {
		return errors.New("TUN requires directInterface to keep outer and direct sockets outside the tunnel")
	}
	return nil
}

func (c Config) turnJSON() (string, error) {
	var v map[string]json.RawMessage
	if err := json.Unmarshal(c.Turn, &v); err != nil || v == nil {
		return "", errors.New("turn must contain a MAX/WB transport configuration")
	}
	var server string
	if json.Unmarshal(v["server"], &server) != nil {
		return "", errors.New("turn.server is required")
	}
	p, err := netip.ParseAddrPort(server)
	if err != nil || p.Port() == 0 {
		return "", errors.New("turn.server must be an IP literal with a nonzero port")
	}
	for _, key := range []string{"socks", "socksToken", "socksPin", "socksUser", "socksPass"} {
		var value string
		if raw, ok := v[key]; ok {
			if json.Unmarshal(raw, &value) != nil || value != "" {
				return "", fmt.Errorf("turn.%s is a legacy stream setting; use the local SOCKS inbound", key)
			}
			delete(v, key)
		}
	}
	v["wgListen"] = json.RawMessage(`"127.0.0.1:0"`)
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var provider string
	if raw, ok := v["provider"]; ok {
		if err = json.Unmarshal(raw, &provider); err != nil {
			return "", errors.New("turn.provider must be max or wb")
		}
	}
	switch provider {
	case "", "max":
		if _, err = maxproto.ParseConfig(b); err != nil {
			return "", err
		}
	case "wb":
		var wc struct {
			Session   string `json:"wbSession"`
			Chat      string `json:"wbChat"`
			Callee    string `json:"wbCallee"`
			CallType  string `json:"wbCallType"`
			Transport string `json:"turnTransport"`
		}
		if err = json.Unmarshal(b, &wc); err != nil {
			return "", err
		}
		if wc.Transport != "" && wc.Transport != "auto" && wc.Transport != "udp" && wc.Transport != "tcp" {
			return "", errors.New("turn.turnTransport must be auto, udp or tcp")
		}
		if _, err = wbproto.NewMinter(wc.Session, wc.Chat, wc.Callee, wc.CallType, wc.Transport); err != nil {
			return "", err
		}
	default:
		return "", errors.New("turn.provider must be max or wb")
	}
	return string(b), nil
}
