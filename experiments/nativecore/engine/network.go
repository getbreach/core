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

// Track interface changes, route repairs, recovery after offline periods and
// wall-clock gaps (sleep). Retry preparation before resetting the transport.
type networkTracker struct {
	snapshot       string
	valid, pending bool
	last           int64
}

func (n *networkTracker) observe(now int64, snapshot string, err error) {
	if n.last != 0 && now-n.last > int64(10*time.Second) {
		n.pending = true
	}
	n.last = now
	if err != nil {
		n.pending = true
		return
	}
	if n.valid && n.snapshot != snapshot {
		n.pending = true
	}
	n.snapshot, n.valid = snapshot, true
}
func (n *networkTracker) prepared(changed bool, err error) bool {
	if err != nil {
		n.pending = true
		return false
	}
	reset := n.pending || changed
	n.pending = false
	return reset
}

func watchNetwork(ctx context.Context, prepare func(context.Context) (bool, error), changed func(), report func(error)) {
	before, err := networkSnapshot()
	state := networkTracker{snapshot: before, valid: err == nil, last: time.Now().UnixNano()}
	lastError := ""
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		after, snapshotErr := networkSnapshot()
		state.observe(time.Now().UnixNano(), after, snapshotErr)
		repaired := false
		var err error
		if prepare != nil {
			repaired, err = prepare(ctx)
		}
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = snapshotErr
		}
		if err != nil {
			if err.Error() != lastError && report != nil {
				report(err)
			}
			lastError = err.Error()
		} else {
			lastError = ""
		}
		if state.prepared(repaired, err) {
			changed()
		}
	}
}
