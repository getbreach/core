//go:build darwin && !ios

package dashboard

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/shirou/gopsutil/v4/cpu"
	"github.com/shirou/gopsutil/v4/load"
	"github.com/shirou/gopsutil/v4/mem"
	"github.com/shirou/gopsutil/v4/process"
)

type resourceSampler struct {
	process       *process.Process
	lastSystem    *cpu.TimesStat
	lastProcess   float64
	lastProcessAt time.Time
}

func (s *resourceSampler) sample(ctx context.Context) resources {
	r := runtimeResources()
	var errs error
	times, err := cpu.TimesWithContext(ctx, false)
	if err == nil && len(times) > 0 {
		now := times[0]
		if before := s.lastSystem; before != nil {
			total := (now.User + now.System + now.Nice + now.Idle) - (before.User + before.System + before.Nice + before.Idle)
			r.SystemCPU, r.CPUValid = cpuPercent(total-(now.Idle-before.Idle), total)
		}
		s.lastSystem = &now
	} else {
		errs = errors.Join(errs, err)
	}
	if m, err := mem.VirtualMemoryWithContext(ctx); err == nil {
		r.RAMUsed, r.RAMTotal = m.Used, m.Total
	} else {
		errs = errors.Join(errs, err)
	}
	if l, err := load.AvgWithContext(ctx); err == nil {
		r.Load = [3]float64{l.Load1, l.Load5, l.Load15}
		r.LoadValid = true
	} else {
		errs = errors.Join(errs, err)
	}
	if s.process == nil {
		s.process, err = process.NewProcessWithContext(ctx, int32(os.Getpid()))
		errs = errors.Join(errs, err)
	}
	if s.process != nil {
		if p, err := s.process.TimesWithContext(ctx); err == nil {
			now := time.Now()
			used := p.User + p.System
			if !s.lastProcessAt.IsZero() && used >= s.lastProcess {
				r.ProcessCPU = (used - s.lastProcess) / now.Sub(s.lastProcessAt).Seconds() * 100
				r.ProcessCPUValid = true
			}
			s.lastProcess, s.lastProcessAt = used, now
		} else {
			errs = errors.Join(errs, err)
		}
		if m, err := s.process.MemoryInfoWithContext(ctx); err == nil {
			r.RSS = m.RSS
		} else {
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		r.Error = errs.Error()
	}
	return r
}
