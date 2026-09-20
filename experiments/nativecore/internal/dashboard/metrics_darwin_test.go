//go:build darwin && !ios

package dashboard

import (
	"context"
	"testing"
	"time"
)

func TestRealMacOSResourceSamples(t *testing.T) {
	s := resourceSampler{}
	first := s.sample(context.Background())
	if first.Error != "" || first.RAMTotal == 0 || first.RSS == 0 || !first.LoadValid {
		t.Fatalf("resource collection failed: %+v", first)
	}
	// Kernel counters may not advance within one short scheduling interval.
	// Wait for a measurable delta rather than assuming a fixed tick frequency.
	var second resources
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		second = s.sample(context.Background())
		if second.CPUValid && second.ProcessCPUValid {
			break
		}
	}
	if !second.CPUValid || !second.ProcessCPUValid || second.SystemCPU < 0 || second.SystemCPU > 100 {
		t.Fatalf("invalid CPU sample: %+v", second)
	}
}
