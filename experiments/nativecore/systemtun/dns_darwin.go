//go:build darwin && !ios

package systemtun

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// scutil owns a temporary dynamic-store value. EOF closes its session and
// configd removes the value, including when the parent is killed with SIGKILL.
// Use a real OS stdin pipe, not os/exec's goroutine-backed reader: the kernel
// must deliver EOF even if no Go cleanup code gets to run.
type dnsProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	done chan struct{}
	once sync.Once
	key  string
}

func startDNS(ctx context.Context, address string) (dnsLease, error) {
	return startDNSDomain(ctx, address, "")
}

// Nonempty domains are used by the privileged tests to avoid changing the
// machine's default resolver while exercising real configd ownership.
func startDNSDomain(ctx context.Context, address, domain string) (dnsLease, error) {
	if strings.ContainsAny(domain, " \t\r\n\"\\") {
		return nil, errors.New("invalid supplemental domain")
	}
	if _, err := netip.ParseAddr(address); err != nil {
		return nil, err
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	d := &dnsProcess{cmd: exec.Command("/usr/sbin/scutil"), done: make(chan struct{}), key: "State:/Network/Service/Breach-" + hex.EncodeToString(id[:]) + "/DNS"}
	d.cmd.Stdout = io.Discard
	d.cmd.Stderr = io.Discard
	var err error
	d.in, err = d.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	if err = d.cmd.Start(); err != nil {
		d.in.Close()
		return nil, err
	}
	go func() { _ = d.cmd.Wait(); close(d.done) }()
	// An empty match domain is a supplemental default resolver. It is ordered
	// before the normal service DNS, without replacing that service's settings.
	script := fmt.Sprintf("d.init\nd.add ServerAddresses * %s\nd.add SupplementalMatchDomains * \"%s\"\nd.add SupplementalMatchOrders * # 1\nd.add SearchOrder # 1\nadd %s temporary\n", address, domain, d.key)
	if _, err = io.WriteString(d.in, script); err != nil {
		d.Close()
		return nil, err
	}
	ready, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		q := exec.CommandContext(ready, "/usr/sbin/scutil")
		q.Stdin = strings.NewReader("show " + d.key + "\nquit\n")
		out, e := q.Output()
		if e == nil && strings.Contains(string(out), address) && strings.Contains(string(out), "SupplementalMatchDomains") {
			return d, nil
		}
		select {
		case <-ready.Done():
			d.Close()
			return nil, fmt.Errorf("temporary DNS record was not installed: %w", ready.Err())
		case <-d.done:
			d.Close()
			return nil, errors.New("scutil stopped before installing temporary DNS")
		case <-ticker.C:
		}
	}
}

func (d *dnsProcess) Done() <-chan struct{} { return d.done }
func (d *dnsProcess) Close() error {
	d.once.Do(func() {
		d.in.Close()
		select {
		case <-d.done:
		case <-time.After(3 * time.Second):
			d.cmd.Process.Kill()
			<-d.done
		}
	})
	return nil
}
