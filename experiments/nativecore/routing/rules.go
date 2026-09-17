// Package routing applies one ordered policy to SOCKS and TUN TCP/UDP flows.
package routing

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

type Rule struct {
	Name    string   `json:"name,omitempty"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
	Ports   string   `json:"ports,omitempty"`
	Network string   `json:"network,omitempty"`
	Action  string   `json:"action"`
}
type Set struct {
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}
type DNSConfig struct {
	FakeIP    bool   `json:"fakeIP"`
	Upstream  string `json:"upstream,omitempty"`
	StateFile string `json:"stateFile,omitempty"`
}
type Config struct {
	SetFiles      map[string]string `json:"setFiles,omitempty"`
	DefaultAction string            `json:"defaultAction,omitempty"`
	Rules         []Rule            `json:"rules,omitempty"`
	Sets          map[string]Set    `json:"sets,omitempty"`
	DNS           DNSConfig         `json:"dns,omitempty"`
}
type domains struct {
	exact, suffix map[string]bool
	keywords      []string
	regex         []*regexp.Regexp
}
type portRange struct{ lo, hi uint16 }
type compiledRule struct {
	Rule
	domains  domains
	prefixes map[netip.Prefix]bool
	ports    []portRange
}

func validAction(a string) bool { return a == "tunnel" || a == "direct" || a == "block" }
func domainName(s string) (string, error) {
	s = strings.TrimSuffix(strings.ToLower(s), ".")
	s, err := idna.Lookup.ToASCII(s)
	if err != nil || s == "" || len(s) > 253 {
		return "", fmt.Errorf("invalid domain %q", s)
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("invalid domain %q", s)
		}
	}
	return s, nil
}
func (d *domains) add(s string) error {
	kind, value, has := strings.Cut(s, ":")
	if !has {
		kind, value = "domain", s
	}
	switch kind {
	case "regexp":
		r, e := regexp.Compile(value)
		if e != nil {
			return e
		}
		d.regex = append(d.regex, r)
	case "keyword":
		if value == "" {
			return fmt.Errorf("empty domain keyword")
		}
		d.keywords = append(d.keywords, strings.ToLower(value))
	case "full", "domain":
		v, e := domainName(value)
		if e != nil {
			return e
		}
		if kind == "full" {
			d.exact[v] = true
		} else {
			d.suffix[v] = true
		}
	default:
		return fmt.Errorf("unsupported domain matcher %q", kind)
	}
	return nil
}
func (d domains) match(s string) bool {
	if d.exact[s] {
		return true
	}
	for sub := s; sub != ""; {
		if d.suffix[sub] {
			return true
		}
		_, tail, ok := strings.Cut(sub, ".")
		if !ok {
			break
		}
		sub = tail
	}
	for _, v := range d.keywords {
		if strings.Contains(s, v) {
			return true
		}
	}
	for _, v := range d.regex {
		if v.MatchString(s) {
			return true
		}
	}
	return false
}
func compile(cfg Config) ([]compiledRule, error) {
	out := make([]compiledRule, 0, len(cfg.Rules))
	for i, r := range cfg.Rules {
		if !validAction(r.Action) {
			return nil, fmt.Errorf("rule %d: invalid action", i)
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" && r.Network != "tcp,udp" {
			return nil, fmt.Errorf("rule %d: network must be tcp or udp", i)
		}
		c := compiledRule{Rule: r, domains: domains{exact: map[string]bool{}, suffix: map[string]bool{}}, prefixes: map[netip.Prefix]bool{}}
		for _, v := range r.Domains {
			values := []string{v}
			if name, ok := strings.CutPrefix(v, "geosite:"); ok {
				set, found := cfg.Sets["geosite-"+name]
				if !found || len(set.Domains) == 0 {
					return nil, fmt.Errorf("rule %d: missing/empty geosite:%s", i, name)
				}
				values = set.Domains
			}
			for _, v := range values {
				if e := c.domains.add(v); e != nil {
					return nil, fmt.Errorf("rule %d: %w", i, e)
				}
			}
		}
		for _, v := range r.IPs {
			values := []string{v}
			if name, ok := strings.CutPrefix(v, "geoip:"); ok {
				set, found := cfg.Sets["geoip-"+name]
				if !found || len(set.IPs) == 0 {
					return nil, fmt.Errorf("rule %d: missing/empty geoip:%s", i, name)
				}
				values = set.IPs
			}
			for _, v := range values {
				p, e := netip.ParsePrefix(v)
				if e != nil {
					a, ae := netip.ParseAddr(v)
					if ae != nil {
						return nil, fmt.Errorf("rule %d: invalid IP/CIDR %q", i, v)
					}
					a = a.Unmap()
					p = netip.PrefixFrom(a, a.BitLen())
				}
				c.prefixes[p.Masked()] = true
			}
		}
		if r.Ports != "" {
			for _, part := range strings.Split(r.Ports, ",") {
				lo, hi, rangePort := strings.Cut(strings.TrimSpace(part), "-")
				if !rangePort {
					hi = lo
				}
				a, e := strconv.ParseUint(lo, 10, 16)
				b, f := strconv.ParseUint(hi, 10, 16)
				if e != nil || f != nil || a == 0 || b < a {
					return nil, fmt.Errorf("rule %d: invalid port range %q", i, part)
				}
				c.ports = append(c.ports, portRange{uint16(a), uint16(b)})
			}
		}
		out = append(out, c)
	}
	return out, nil
}
func (r compiledRule) matchBase(network, domain string, port uint16) bool {
	if r.Network != "" && r.Network != "tcp,udp" && r.Network != network {
		return false
	}
	if len(r.Domains) > 0 && !r.domains.match(domain) {
		return false
	}
	if len(r.ports) > 0 {
		for _, p := range r.ports {
			if port >= p.lo && port <= p.hi {
				return true
			}
		}
		return false
	}
	return true
}
func (r compiledRule) matchIP(a netip.Addr) bool {
	a = a.Unmap()
	for bits := a.BitLen(); bits >= 0; bits-- {
		if r.prefixes[netip.PrefixFrom(a, bits).Masked()] {
			return true
		}
	}
	return false
}
func splitTarget(target string) (string, uint16, error) {
	h, p, e := net.SplitHostPort(target)
	if e != nil {
		return "", 0, e
	}
	n, e := strconv.ParseUint(p, 10, 16)
	if e != nil || n == 0 || h == "" {
		return "", 0, fmt.Errorf("invalid target %q", target)
	}
	return h, uint16(n), nil
}
