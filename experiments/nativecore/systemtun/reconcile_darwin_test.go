//go:build darwin && !ios

package systemtun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

type routeTable struct {
	physical gatewayRoute
	offline  bool
	scoped   map[string]gatewayRoute
	changes  []string
}

func testRouteTable() *routeTable {
	return &routeTable{physical: gatewayRoute{iface: "en1", gateway: "192.0.2.1"}, scoped: map[string]gatewayRoute{}}
}
func (r *routeTable) run(_ context.Context, _ string, args ...string) (string, error) {
	if args[1] == "get" {
		if args[2] == "-inet6" {
			return "", errRouteNotFound
		}
		route := r.physical
		if len(args) == 6 {
			var ok bool
			route, ok = r.scoped[args[5]]
			if !ok {
				if r.offline || args[5] != r.physical.iface {
					return "", errRouteNotFound
				}
				route = r.physical
			}
		} else if r.offline {
			return "", errRouteNotFound
		}
		flags := "UP,GATEWAY"
		if route.scoped {
			flags += ",IFSCOPE"
		}
		return fmt.Sprintf("gateway: %s\ninterface: %s\nflags: <%s>\n", route.gateway, route.iface, flags), nil
	}
	if len(args) != 7 || args[3] != "default" || args[5] != "-ifscope" {
		return "", fmt.Errorf("unexpected mutation %v", args)
	}
	r.changes = append(r.changes, strings.Join(args, " "))
	switch args[1] {
	case "add":
		if _, ok := r.scoped[args[6]]; ok {
			return "", errors.New("route exists")
		}
		r.scoped[args[6]] = gatewayRoute{iface: args[6], gateway: args[4], scoped: true}
	case "delete":
		delete(r.scoped, args[6])
	default:
		return "", errors.New("unexpected route command")
	}
	return "", nil
}

func TestScopedRouteReconciliation(t *testing.T) {
	table := testRouteTable()
	m := newRouteManager(table.run)
	ctx := context.Background()
	sync := func() string {
		t.Helper()
		snapshot, err := m.Sync(ctx, "auto")
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	first := sync()
	if sync() != first || len(table.changes) != 1 {
		t.Fatal("unchanged route was modified")
	}
	table.physical.gateway = "192.0.2.254"
	if sync() == first || table.scoped["en1"].gateway != "192.0.2.254" {
		t.Fatal("same-interface gateway change missed")
	}
	table.physical = gatewayRoute{iface: "en2", gateway: "198.51.100.1"}
	second := sync()
	if _, ok := table.scoped["en1"]; ok {
		t.Fatal("old interface route retained")
	}
	delete(table.scoped, "en2")
	if sync() == second {
		t.Fatal("route repair did not notify transport")
	}
	table.offline = true
	if _, err := m.Sync(ctx, "auto"); !errors.Is(err, errRouteNotFound) {
		t.Fatal(err)
	}
	table.offline = false
	sync()
	if err := m.Close(); err != nil || len(table.scoped) != 0 {
		t.Fatalf("cleanup: %v, %v", table.scoped, err)
	}
}

func TestScopedRouteOwnership(t *testing.T) {
	t.Run("preexisting", func(t *testing.T) {
		table := testRouteTable()
		table.scoped["en1"] = gatewayRoute{iface: "en1", gateway: "192.0.2.1", scoped: true}
		m := newRouteManager(table.run)
		if _, err := m.Sync(context.Background(), "auto"); err != nil {
			t.Fatal(err)
		}
		m.Close()
		if len(table.changes) != 0 || len(table.scoped) != 1 {
			t.Fatal("touched preexisting route")
		}
	})
	t.Run("replaced", func(t *testing.T) {
		table := testRouteTable()
		m := newRouteManager(table.run)
		if _, err := m.Sync(context.Background(), "auto"); err != nil {
			t.Fatal(err)
		}
		table.scoped["en1"] = gatewayRoute{iface: "en1", gateway: "192.0.2.99", scoped: true}
		if err := m.Close(); err != nil {
			t.Fatal(err)
		}
		if table.scoped["en1"].gateway != "192.0.2.99" {
			t.Fatal("deleted another owner's replacement")
		}
	})
}
