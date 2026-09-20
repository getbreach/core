package dashboard

import (
	"runtime"
	"time"
)

type resources struct {
	At                           time.Time
	SystemCPU, ProcessCPU        float64
	CPUValid, ProcessCPUValid    bool
	RAMUsed, RAMTotal, RSS, Heap uint64
	Load                         [3]float64
	LoadValid                    bool
	Goroutines, Cores            int
	Error                        string
}

func runtimeResources() resources {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return resources{At: time.Now(), Heap: m.HeapAlloc, Goroutines: runtime.NumGoroutine(), Cores: runtime.NumCPU()}
}

func cpuPercent(used, total float64) (float64, bool) {
	if total <= 0 || used < 0 {
		return 0, false
	}
	return min(100, max(0, used/total*100)), true
}
