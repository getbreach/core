//go:build darwin && !ios

package systemtun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type gatewayRoute struct {
	iface, gateway string
	scoped         bool
}

func parseGatewayRoute(output string) (gatewayRoute, error) {
	var r gatewayRoute
	for _, line := range strings.Split(output, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 {
			continue
		}
		switch f[0] {
		case "interface:":
			r.iface = f[1]
		case "gateway:":
			r.gateway = f[1]
		case "flags:":
			r.scoped = strings.Contains(","+strings.Trim(f[1], "<>")+",", ",IFSCOPE,")
		}
	}
	if _, err := netip.ParseAddr(r.gateway); err != nil || r.iface == "" || strings.HasPrefix(r.iface, "utun") || r.iface == "lo0" {
		return r, errors.New("physical default route must have an IP gateway and a non-tunnel interface")
	}
	return r, nil
}

// A routeLease owns only scoped defaults created by this instance.
type routeLease interface {
	Sync(context.Context, string) (string, error)
	Close() error
	Done() <-chan struct{}
}

type scopedRoute struct {
	family string
	gatewayRoute
}

func (r scopedRoute) key() string { return r.family + "/" + r.iface }
func (r scopedRoute) args(op string) []string {
	return []string{"-n", op, r.family, "default", r.gateway, "-ifscope", r.iface}
}

type routeManager struct {
	run      command
	owned    map[string]scopedRoute
	revision uint64
}

func newRouteManager(run command) *routeManager {
	return &routeManager{run: run, owned: map[string]scopedRoute{}}
}
func (m *routeManager) Done() <-chan struct{} { return nil }

func (m *routeManager) query(ctx context.Context, family, iface string) (gatewayRoute, error) {
	args := []string{"-n", "get", family, "default"}
	if iface != "" {
		args = append(args, "-ifscope", iface)
	}
	out, err := m.run(ctx, "/sbin/route", args...)
	if err != nil {
		return gatewayRoute{}, err
	}
	r, err := parseGatewayRoute(out)
	if err != nil {
		return r, fmt.Errorf("parse %s outbound default route: %w", family, err)
	}
	return r, nil
}

func (m *routeManager) discover(ctx context.Context, iface string) ([]scopedRoute, error) {
	automatic := iface == "" || iface == "auto"
	v4, err := m.query(ctx, "-inet", "")
	if !automatic && (err != nil || v4.iface != iface) {
		v4, err = m.query(ctx, "-inet", iface)
	}
	if err != nil {
		return nil, err
	}
	if !automatic && v4.iface != iface {
		return nil, errors.New("outbound default uses an unexpected interface")
	}
	routes := []scopedRoute{{"-inet", v4}}
	// Socket protection uses the IPv4-selected physical interface for both
	// families. Ignore IPv6 defaults belonging to unrelated system VPNs.
	out, err := m.run(ctx, "/sbin/route", "-n", "get", "-inet6", "default")
	if errors.Is(err, errRouteNotFound) && ctx.Err() == nil {
		return routes, nil
	}
	if err != nil {
		return nil, err
	}
	v6, e := parseGatewayRoute(out)
	if e != nil && !strings.HasPrefix(v6.iface, "utun") {
		return nil, e
	}
	if v6.iface != v4.iface {
		return routes, nil
	}
	if e != nil {
		return nil, e
	}
	return append(routes, scopedRoute{"-inet6", v6}), nil
}

func sameScoped(a gatewayRoute, b scopedRoute) bool {
	return a.scoped && a.iface == b.iface && a.gateway == b.gateway
}

// Never delete a pre-existing route or a route replaced by another owner.
func (m *routeManager) remove(ctx context.Context, r scopedRoute) error {
	current, err := m.query(ctx, r.family, r.iface)
	if errors.Is(err, errRouteNotFound) {
		delete(m.owned, r.key())
		return nil
	}
	if err != nil {
		return err
	}
	if !sameScoped(current, r) {
		delete(m.owned, r.key())
		return nil
	}
	_, err = m.run(ctx, "/sbin/route", r.args("delete")...)
	if errors.Is(err, errRouteNotFound) {
		err = nil
	}
	if err == nil {
		delete(m.owned, r.key())
	}
	return err
}

func (m *routeManager) Sync(ctx context.Context, iface string) (string, error) {
	desired, err := m.discover(ctx, iface)
	if err != nil {
		return "", err
	} // offline: keep ownership, retry after recovery
	want := map[string]scopedRoute{}
	for _, r := range desired {
		want[r.key()] = r
	}
	for _, key := range m.keys() {
		old := m.owned[key]
		next, ok := want[key]
		if !ok || next.gateway != old.gateway {
			if err := m.remove(ctx, old); err != nil {
				return "", err
			}
		}
	}
	var snapshot []string
	for _, r := range desired {
		existing, err := m.query(ctx, r.family, r.iface)
		if err != nil && !errors.Is(err, errRouteNotFound) {
			return "", err
		}
		if err == nil && existing.scoped {
			if !sameScoped(existing, r) {
				delete(m.owned, r.key())
				return "", fmt.Errorf("scoped default on %s differs from physical gateway; leaving another owner's route intact", r.iface)
			}
		} else {
			delete(m.owned, r.key())
			if _, err := m.run(ctx, "/sbin/route", r.args("add")...); err != nil {
				return "", err
			}
			// The guardian owns both mutation and bookkeeping. If the parent dies
			// while waiting for this reply, EOF still cleans up the successful add.
			m.owned[r.key()] = r
			m.revision++
		}
		snapshot = append(snapshot, r.key()+"="+r.gateway)
	}
	return strings.Join(snapshot, "|") + fmt.Sprintf("#%d", m.revision), nil
}
func (m *routeManager) keys() []string {
	keys := make([]string, 0, len(m.owned))
	for key := range m.owned {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
func (m *routeManager) Close() error {
	var err error
	for _, key := range m.keys() {
		err = errors.Join(err, m.remove(context.Background(), m.owned[key]))
	}
	return err
}
func (s *Session) setupBypass(ctx context.Context, iface string) error {
	if s.bypass == nil {
		s.bypass = newRouteManager(s.run)
	}
	snapshot, err := s.bypass.Sync(ctx, iface)
	if err == nil {
		s.snapshot = snapshot
		s.outboundInterface = iface
	}
	return err
}

func (s *Session) addRoute(ctx context.Context, args []string) error {
	if _, err := s.run(ctx, "/sbin/route", args...); err != nil {
		return err
	}
	undo := append([]string(nil), args...)
	undo[1] = "delete"
	s.undo = append(s.undo, undo)
	return nil
}
