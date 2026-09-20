package engine

import (
	"encoding/json"
	"errors"
	"sync"
	"time"

	"breach-nativecore/bridge"
	"breach-nativecore/reconnect"
	"breach-nativecore/transport"
	breachmobile "breach/mobile"
)

// Monitor is optional, read-only telemetry. Status comes from live components,
// never from parsing log text. Snapshot may run concurrently with startup/stop.
type Monitor struct {
	mu                                     sync.Mutex
	started                                time.Time
	phase, device, lastError, networkError string
	ready                                  bool
	r                                      *reconnect.Client
	turn                                   *breachmobile.Tunnel
	b                                      *bridge.Bridge
	wire                                   transport.Meter
}

type Snapshot struct {
	Started                                time.Time
	Phase, Device, LastError, NetworkError string
	Hy2                                    reconnect.Status
	TURN                                   bool
	Allocations, TargetAllocations         int
	Bridge                                 bool
	Flows                                  bridge.Stats
	Wire                                   transport.Traffic
	Pool                                   PoolSettings
}

func (m *Monitor) Snapshot() Snapshot {
	if m == nil {
		return Snapshot{}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Snapshot{Started: m.started, Phase: m.phase, Device: m.device, LastError: m.lastError, NetworkError: m.networkError, Wire: m.wire.Snapshot()}
	if m.r != nil {
		s.Hy2 = m.r.Status()
	}
	if m.turn != nil {
		s.TURN = true
		_ = json.Unmarshal([]byte(m.turn.PoolLimits()), &s.Pool)
		var stat struct {
			Allocations, TargetAllocations int
			LastError                      string
		}
		if json.Unmarshal([]byte(m.turn.Stat()), &stat) == nil {
			s.Allocations, s.TargetAllocations = stat.Allocations, stat.TargetAllocations
			if s.LastError == "" {
				s.LastError = stat.LastError
			}
		}
	}
	if m.b != nil {
		s.Bridge = true
		s.Flows = m.b.Stats()
	}
	if m.ready && m.phase != "stopped" && m.phase != "error" {
		s.Phase = "reconnecting"
		if s.Hy2.Connected {
			s.Phase = "online"
		}
	}
	if s.Hy2.LastError != "" {
		s.LastError = s.Hy2.LastError
	}
	return s
}

func (m *Monitor) update(fn func()) {
	if m != nil {
		m.mu.Lock()
		defer m.mu.Unlock()
		fn()
	}
}

// PoolSettings reflects the portable transport's requested runtime limits.
type PoolSettings struct {
	Mints   int  `json:"mints"`
	Streams int  `json:"streams"`
	Target  int  `json:"target"`
	Applied bool `json:"applied"`
}

func (m *Monitor) SetPoolLimits(mints, streams int) error {
	if m == nil {
		return errors.New("transport not ready")
	}
	m.mu.Lock()
	turn := m.turn
	m.mu.Unlock()
	if turn == nil {
		return errors.New("embedded TURN transport not ready")
	}
	return turn.SetPoolLimits(mints, streams)
}
