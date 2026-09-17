package engine

import (
	"context"
	"net"
	"sort"
	"strings"
	"time"
)

func networkSnapshot() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	var parts []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		as, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, a := range as {
			parts = append(parts, i.Name+":"+a.String())
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "|"), nil
}

// Polling covers interface/address changes without privileged platform APIs.
// A large wall-clock gap also catches suspend/resume. Same-address route-only
// changes are recovered by TURN health checks / QUIC idle timeout.
func watchNetwork(ctx context.Context, changed func()) {
	before, err := networkSnapshot()
	valid := err == nil
	last := time.Now().UnixNano()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		now := time.Now().UnixNano()
		after, err := networkSnapshot()
		if err == nil {
			if valid && (before != after || now-last > int64(10*time.Second)) {
				changed()
			}
			before, valid = after, true
		}
		last = now
	}
}
