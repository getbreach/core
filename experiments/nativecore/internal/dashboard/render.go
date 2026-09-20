package dashboard

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"breach-nativecore/engine"
)

type view struct {
	config     engine.Config
	status     engine.Snapshot
	resources  resources
	rate       rateMeter
	logs       []string
	warning    string
	uptime     time.Duration
	transition string
	poolEdit   *poolEditor
}

func bytesText(v float64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", v, units[i])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
func percent(v float64, valid bool) string {
	if !valid {
		return "--"
	}
	return fmt.Sprintf("%.1f%%", v)
}
func bar(v float64, valid bool, n int) string {
	if !valid {
		return strings.Repeat("░", n)
	}
	used := int(min(100, max(0, v)) * float64(n) / 100)
	return strings.Repeat("━", used) + strings.Repeat("─", n-used)
}
func history(values []float64, n int) string {
	if len(values) > n {
		values = values[len(values)-n:]
	}
	peak := float64(1)
	for _, v := range values {
		peak = max(peak, v)
	}
	levels := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	b.WriteString(strings.Repeat("·", max(0, n-len(values))))
	for _, v := range values {
		b.WriteRune(levels[int(min(1, max(0, v/peak))*float64(len(levels)-1))])
	}
	return b.String()
}

func render(v view, width, height int, paused, stopping, showLogs bool) []string {
	w, h := max(1, min(width-1, 160)), max(1, min(height, 60))
	c := newCanvas(w, h, os.Getenv("NO_COLOR") == "")
	s, r := v.status, v.resources
	status := strings.ToUpper(safeText(s.Phase))
	if status == "" {
		status = "STARTING"
	}
	statusInk := warn
	if status == "ONLINE" {
		statusInk = good
	}
	if status == "ERROR" {
		statusInk = bad
	}
	if stopping {
		status, statusInk = "STOPPING", warn
	}
	if v.transition != "" && !stopping {
		status, statusInk = "SWITCHING", warn
	}
	footer := "m " + modeName(map[string]string{"tun": "socks", "socks": "tun"}[v.config.Inbound]) + "  ·  t pool  ·  q quit  ·  p pause  ·  l logs"
	if v.transition != "" {
		footer = v.transition + "  ·  q cancel / quit"
	}
	if paused {
		footer = "PAUSED  ·  p resume  ·  m switch mode  ·  q quit"
	}
	if stopping {
		footer = "Restoring routes and DNS · waiting for shutdown…"
	}
	if w < 59 || h < 18 {
		c.text(0, 0, w, "BREACH  ·  "+status, statusInk)
		c.text(0, 1, w, "Resize terminal to at least 60 × 18.", muted)
		c.text(0, h-1, w, footer, muted)
		return c.lines()
	}
	c.text(1, 0, 10, "◈ BREACH", accent)
	c.text(12, 0, w-30, "NETWORK CONSOLE", muted)
	c.text(w-17, 0, 16, "● "+status, statusInk)
	c.text(1, 1, w-2, fmt.Sprintf("%s / %s  ·  %s/%s  ·  uptime %s", strings.ToUpper(safeText(v.config.Inbound)), strings.ToUpper(safeText(v.config.Mode)), runtime.GOOS, runtime.GOARCH, v.uptime.Round(time.Second)), muted)
	c.text(1, h-1, w-2, footer, muted)
	device := safeText(s.Device)
	if device == "" {
		device = "waiting for inbound"
	}
	hy2, hy2Ink := "Connecting", warn
	if s.Hy2.Connected {
		hy2, hy2Ink = "Authenticated · TCP + UDP", good
	}
	turn := "Not used"
	if v.config.Mode == "pipe" {
		turn = "External process"
	}
	if v.config.Mode == "turn" {
		turn = fmt.Sprintf("%d / %d allocations", s.Allocations, s.TargetAllocations)
		if s.Pool.Mints > 0 {
			turn = fmt.Sprintf("%d/%d · M%d × S%d", s.Allocations, s.Pool.Target, s.Pool.Mints, s.Pool.Streams)
			if !s.Pool.Applied {
				turn += " · applying"
			}
		}
	}
	routes := "Manual routes / DNS"
	if v.config.AutoRoute {
		routes = "Auto routes + temporary DNS"
	}
	if v.config.Inbound == "socks" {
		routes = "Local SOCKS5"
	}
	tls, tlsInk := "CA verified", good
	if v.config.TLS.CertSHA256 != "" {
		tls = "Certificate pin"
	}
	if v.config.TLS.Insecure {
		tls, tlsInk = "Verification disabled", warn
	}
	if !s.Hy2.Connected && !v.config.TLS.Insecure {
		tls, tlsInk = "Verification configured", muted
	}
	ram, ramPercent := "--", float64(0)
	if r.RAMTotal > 0 {
		ram = fmt.Sprintf("%s / %s", bytesText(float64(r.RAMUsed)), bytesText(float64(r.RAMTotal)))
		ramPercent = float64(r.RAMUsed) / float64(r.RAMTotal) * 100
	}
	rss, load := "--", "--"
	if r.RSS > 0 {
		rss = bytesText(float64(r.RSS))
	}
	if r.LoadValid {
		load = fmt.Sprintf("%.2f / %.2f / %.2f", r.Load[0], r.Load[1], r.Load[2])
	}
	flows := "Flows  -- (TUN only)"
	if s.Bridge {
		flows = fmt.Sprintf("Flows  %d active · %d rejected", s.Flows.ActiveFlows, s.Flows.RejectedFlows)
	}
	logStart := 0
	if w >= 89 && h >= 26 {
		left := (w - 1) / 2
		rightX, right := left+1, w-left-1
		c.panel(0, 3, left, 9, "TUNNEL")
		c.panel(rightX, 3, right, 9, "SYSTEM")
		put := func(row int, label, value string, color ink) {
			c.text(2, 4+row, 9, label, muted)
			c.text(11, 4+row, left-13, value, color)
		}
		put(0, "Inbound", device, bright)
		put(1, "Hy2", hy2, hy2Ink)
		put(2, "TURN", turn, plain)
		put(3, "Network", routes, plain)
		put(4, "TLS", tls, tlsInk)
		put(5, "Retries", fmt.Sprintf("%d attempts · %d reconnects", s.Hy2.Attempts, s.Hy2.Reconnects), muted)
		put(6, "", flows, muted)
		x, n := rightX+2, right-4
		cpuInk := accent
		if r.SystemCPU >= 85 {
			cpuInk = warn
		}
		c.text(x, 4, n, "CPU  "+percent(r.SystemCPU, r.CPUValid), bright)
		c.text(x, 5, n, bar(r.SystemCPU, r.CPUValid, n), cpuInk)
		c.text(x, 6, n, "RAM  "+ram, bright)
		c.text(x, 7, n, bar(ramPercent, r.RAMTotal > 0, n), violet)
		c.text(x, 9, n, "Load  "+load, muted)
		c.text(x, 10, n, fmt.Sprintf("%d logical CPUs · load 1 / 5 / 15 min", r.Cores), muted)
		c.panel(0, 12, left, 7, "TRAFFIC")
		c.panel(rightX, 12, right, 7, "BREACH PROCESS")
		c.text(2, 13, left-4, fmt.Sprintf("↓ %-16s ↑ %s", bytesText(v.rate.down)+"/s", bytesText(v.rate.up)+"/s"), accent)
		c.text(2, 14, left-4, history(v.rate.history, left-4), accent)
		c.text(2, 15, left-4, fmt.Sprintf("Total ↓ %s  ↑ %s", bytesText(float64(s.Wire.DownBytes)), bytesText(float64(s.Wire.UpBytes))), plain)
		c.text(2, 16, left-4, fmt.Sprintf("Packets ↓ %d  ↑ %d", s.Wire.DownPackets, s.Wire.UpPackets), muted)
		c.text(2, 17, left-4, "Hy2 wire · RX graph, relative scale", muted)
		c.text(x, 13, n, "CPU  "+percent(r.ProcessCPU, r.ProcessCPUValid)+"   RSS  "+rss, bright)
		c.text(x, 14, n, "Heap "+bytesText(float64(r.Heap)), plain)
		c.text(x, 15, n, fmt.Sprintf("%d goroutines · PID %d", r.Goroutines, os.Getpid()), plain)
		c.text(x, 17, n, "Process CPU: 100% = one core", muted)
		logStart = 19
	} else {
		// Compact layout keeps the important readings visible in an 80×24 shell.
		c.panel(0, 3, w, 6, "TUNNEL")
		c.text(2, 4, w-4, device+"  ·  "+hy2, hy2Ink)
		c.text(2, 5, w-4, "TURN "+turn+fmt.Sprintf("  ·  reconnects %d", s.Hy2.Reconnects), plain)
		c.text(2, 6, w-4, routes+"  ·  TLS: "+tls, tlsInk)
		c.text(2, 7, w-4, flows, muted)
		c.panel(0, 9, w, 7, "TRAFFIC / RESOURCES")
		c.text(2, 10, w-4, fmt.Sprintf("↓ %-16s ↑ %-16s RX %s", bytesText(v.rate.down)+"/s", bytesText(v.rate.up)+"/s", history(v.rate.history, max(4, w-48))), accent)
		c.text(2, 11, w-4, fmt.Sprintf("Total ↓ %s  ↑ %s  ·  Hy2 wire", bytesText(float64(s.Wire.DownBytes)), bytesText(float64(s.Wire.UpBytes))), muted)
		c.text(2, 12, w-4, "CPU "+percent(r.SystemCPU, r.CPUValid)+"  "+bar(r.SystemCPU, r.CPUValid, 12)+"  RAM "+ram, plain)
		c.text(2, 13, w-4, "Breach CPU "+percent(r.ProcessCPU, r.ProcessCPUValid)+"  RSS "+rss+"  Heap "+bytesText(float64(r.Heap)), plain)
		c.text(2, 14, w-4, "Load "+load+fmt.Sprintf("  ·  %d goroutines", r.Goroutines), muted)
		logStart = 16
	}
	if v.warning != "" {
		c.text(1, logStart, w-2, "! "+safeText(v.warning), warn)
		logStart++
	}
	available := h - 1 - logStart
	if showLogs && available >= 3 {
		c.panel(0, logStart, w, available, "EVENTS")
		logs := v.logs[max(0, len(v.logs)-(available-2)):]
		if len(logs) == 0 {
			c.text(2, logStart+1, w-4, "Waiting for events…", muted)
		}
		for i, line := range logs {
			color := muted
			lower := strings.ToLower(line)
			if strings.Contains(lower, "error") || strings.Contains(lower, "failed") {
				color = bad
			} else if strings.Contains(lower, "retry") || strings.Contains(lower, "unavailable") {
				color = warn
			} else if strings.Contains(lower, "ready") || strings.Contains(lower, "authenticated") {
				color = good
			}
			c.text(2, logStart+1+i, w-4, safeText(line), color)
		}
	}
	if v.poolEdit != nil {
		c.poolEditor(v.poolEdit)
	}
	return c.lines()
}
