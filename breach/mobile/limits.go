package breachmobile

import (
	"encoding/json"
	"fmt"
	"time"

	"breach/maxproto"
)

type poolSettings struct {
	Mints, Streams int
	Version        uint64
}

// PoolLimits is a JSON-friendly snapshot of requested hot pool settings.
type poolLimits struct {
	Mints   int  `json:"mints"`
	Streams int  `json:"streams"`
	Target  int  `json:"target"`
	Applied bool `json:"applied"`
}

func (c *core) accountCount() int {
	if c.providerName == "wb" {
		return len(c.wbMinters)
	}
	return len(c.cfg.MintAccounts())
}
func (c *core) initLimits() {
	c.requested.Store(&poolSettings{Mints: c.nMints, Streams: c.nStreams, Version: 1})
}
func (c *core) limits() poolLimits {
	v := c.requested.Load()
	if v == nil {
		return poolLimits{}
	}
	return poolLimits{v.Mints, v.Streams, c.accountCount() * v.Mints * v.Streams, c.applied.Load() == v.Version}
}
func (c *core) setLimits(mints, streams int) error {
	if mints < 1 || mints > 16 || streams < 1 || streams > 16 || c.accountCount()*mints*streams > 256 {
		return fmt.Errorf("pool limits: mints/streams must be 1..16 and total allocations <= 256")
	}
	if c.ctx.Err() != nil {
		return fmt.Errorf("transport stopped")
	}
	for {
		old := c.requested.Load()
		if old.Mints == mints && old.Streams == streams {
			return nil
		}
		next := &poolSettings{mints, streams, old.Version + 1}
		if c.requested.CompareAndSwap(old, next) {
			break
		}
	}
	c.log("pool resize requested: mints=%d streams=%d", mints, streams)
	c.wakeReconciler()
	return nil
}

// SetPoolLimits queues a portable, in-process pool resize. The existing pool
// carries traffic while missing allocations are opened. Poll PoolLimits/Stat
// for completion; an accepted request may remain pending on provider failure.
func (t *Tunnel) SetPoolLimits(mints, streams int) error {
	t.mu.Lock()
	c, stopped := t.core, t.stopped
	t.mu.Unlock()
	if stopped || c == nil {
		return fmt.Errorf("transport stopped")
	}
	return c.setLimits(mints, streams)
}

// PoolLimits returns desired settings and whether the pool has reached them.
// String JSON keeps this API compatible with gomobile bindings.
func (t *Tunnel) PoolLimits() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped || t.core == nil {
		return "{}"
	}
	b, _ := json.Marshal(t.core.limits())
	return string(b)
}

// Accessed only under buildMu. Keep unused credentials in memory so lowering
// mints and raising them again doesn't create another call while they are valid.
func (c *core) cachedCreds(dir, key string) []*maxproto.Creds {
	var valid []*maxproto.Creds
	for _, cr := range c.credentialGroups[key] {
		if cr != nil && time.Until(cr.ExpiresAt) >= 30*time.Minute {
			valid = append(valid, cr)
		}
	}
	if len(valid) > 0 {
		return valid
	}
	return maxproto.LoadCachedCreds(dir, key)
}
func (c *core) rememberCreds(dir, key string, usable, cached []*maxproto.Creds) {
	if c.credentialGroups == nil {
		c.credentialGroups = make(map[string][]*maxproto.Creds)
	}
	saved := append([]*maxproto.Creds(nil), usable...)
	if len(cached) > c.nMints {
		saved = append(saved, cached[c.nMints:]...)
	}
	c.credentialGroups[key] = saved
	maxproto.SaveCachedCreds(dir, key, saved)
}
func streamOpen(s *stream) bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}
