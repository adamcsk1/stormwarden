package app

import (
	"bufio"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type burstLimiter struct {
	mu       sync.Mutex
	inFlight bool
	last     time.Time
	cooldown time.Duration
	now      func() time.Time
}

func newBurstLimiter(cooldown time.Duration) *burstLimiter {
	return &burstLimiter{cooldown: cooldown, now: time.Now}
}

func (b *burstLimiter) try() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.inFlight {
		return false
	}
	if !b.last.IsZero() && now.Sub(b.last) < b.cooldown {
		return false
	}
	b.inFlight = true
	return true
}

func (b *burstLimiter) done() {
	b.mu.Lock()
	b.inFlight = false
	b.last = b.now()
	b.mu.Unlock()
}

type pingFn func(ctx context.Context, addr string, count int, interval, perPacket time.Duration) Sample
type traceFn func(ctx context.Context, addr string, maxHops int) Sample

func (a *App) pingTargets() []struct{ name, addr string } {
	gateway := a.cfg.GatewayAddr
	if gateway == "" {
		gateway = a.netInfo.LANGateway
	}
	isp := a.cfg.ISPHopAddr
	if isp == "" {
		isp = a.ispHop
	}
	targets := []struct{ name, addr string }{
		{"pihole", a.cfg.PingPiholeAddr},
		{"gateway", gateway},
		{"isp_hop", isp},
		{"internet", a.cfg.PingInternetAddr},
	}
	var out []struct{ name, addr string }
	for _, t := range targets {
		if t.addr != "" {
			out = append(out, t)
		}
	}
	return out
}

func isAnomaly(samples []Sample) bool {
	for _, s := range samples {
		switch s.ProbeType {
		case "tcp":
			if s.Severity != Info {
				return true
			}
		case "dns", "doh":
			if !s.Success || s.Severity == Error {
				return true
			}
		case "http", "transfer", "asset":
			if !s.Success || s.Severity == Error || s.connectFailed || s.ConnectMS > 250 {
				return true
			}
		}
	}
	return false
}

func (a *App) maybeBurst(ctx context.Context, samples []Sample) []Sample {
	if !a.cfg.PingEnabled || !isAnomaly(samples) {
		return nil
	}
	if a.burst == nil || !a.burst.try() {
		return nil
	}
	defer a.burst.done()
	burstCtx, cancel := context.WithTimeout(ctx, a.cfg.BurstTimeout)
	defer cancel()
	var nicBefore map[string]int64
	if a.cfg.NICStatsEnabled {
		nicBefore = readNIC(a.netInfo.DefaultIface)
	}
	extra := a.runPingBursts(burstCtx)
	if a.cfg.NICStatsEnabled {
		if delta := nicDeltaSample(a.netInfo.DefaultIface, nicBefore, readNIC(a.netInfo.DefaultIface)); delta != nil {
			extra = append(extra, *delta)
		}
	}
	if a.shouldTrace(samples, extra) {
		extra = append(extra, a.maybeTrace(burstCtx)...)
	}
	return extra
}

func (a *App) runPingBursts(ctx context.Context) []Sample {
	targets := a.pingTargets()
	if len(targets) == 0 {
		return nil
	}
	ping := a.ping
	if ping == nil {
		ping = execPing
	}
	out := make([]Sample, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out[i] = ping(ctx, t.addr, a.cfg.BurstCount, a.cfg.BurstInterval, time.Second)
			out[i].Target = "icmp:" + t.name
		}()
	}
	wg.Wait()
	return out
}

func (a *App) shouldTrace(probes, extra []Sample) bool {
	if !a.cfg.TracerouteEnabled {
		return false
	}
	badTCP := 0
	for _, s := range probes {
		if s.ProbeType == "tcp" && s.Severity != Info {
			badTCP++
		}
	}
	upstream := false
	for _, s := range extra {
		if s.ProbeType == "icmp-burst" && (strings.HasSuffix(s.Target, "internet") || strings.HasSuffix(s.Target, "isp_hop")) && s.Mbps > 0 {
			upstream = true
		}
	}
	return badTCP >= 2 || upstream
}

func (a *App) maybeTrace(ctx context.Context) []Sample {
	if a.traceLimit == nil || !a.traceLimit.try() {
		return nil
	}
	defer a.traceLimit.done()
	trace := a.trace
	if trace == nil {
		trace = execTrace
	}
	addr := a.cfg.PingInternetAddr
	if addr == "" {
		addr = "1.1.1.1"
	}
	sample := trace(ctx, addr, a.cfg.TracerouteMaxHops)
	return []Sample{sample}
}

func execPing(ctx context.Context, addr string, count int, interval, perPacket time.Duration) Sample {
	s := Sample{CreatedAt: time.Now(), ProbeType: "icmp-burst", Target: addr, Severity: Info, Bytes: int64(count)}
	if addr == "" {
		s.Severity, s.Message = Error, "icmp_unavailable: empty address"
		return s
	}
	args := pingArgs(addr, count, interval, perPacket)
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && !strings.Contains(text, "transmitted") {
		s.Severity, s.Message = Error, "icmp_unavailable: "+trimErr(err, text)
		return s
	}
	sent, recv, loss, minMS, avgMS, maxMS, jitter := parsePing(text, count)
	s.Bytes, s.StatusCode = int64(sent), recv
	s.Mbps, s.DNSMS, s.DurationMS, s.ConnectMS, s.TLSMS = loss, minMS, avgMS, maxMS, jitter
	s.Success = recv > 0 && loss < 100
	switch {
	case recv == 0:
		s.Severity, s.Message = Error, fmt.Sprintf("%d sent, 0 recv, 100%% loss", sent)
	case loss > 0:
		s.Severity, s.Message = Warning, fmt.Sprintf("%d sent, %d recv, %.0f%% loss, avg %.0fms", sent, recv, loss, avgMS)
	default:
		s.Message = fmt.Sprintf("%d sent, %d recv, 0%% loss, avg %.0fms", sent, recv, avgMS)
	}
	return s
}

func pingArgs(addr string, count int, interval, perPacket time.Duration) []string {
	timeoutSec := int(perPacket.Seconds())
	if timeoutSec < 1 {
		timeoutSec = 1
	}
	if os.PathSeparator == '\\' {
		return []string{"ping", "-n", strconv.Itoa(count), "-w", strconv.Itoa(timeoutSec * 1000), addr}
	}
	intervalSec := interval.Seconds()
	if intervalSec < 0.05 {
		intervalSec = 0.15
	}
	return []string{"ping", "-n", "-c", strconv.Itoa(count), "-i", strconv.FormatFloat(intervalSec, 'f', 2, 64), "-W", strconv.Itoa(timeoutSec), addr}
}

func parsePing(text string, count int) (sent, recv int, loss, minMS, avgMS, maxMS, jitter float64) {
	sent = count
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "packets transmitted") || strings.Contains(line, "Packets: Sent") {
			sent = firstInt(line, sent)
			if i := strings.Index(line, "received"); i > 0 {
				recv = lastIntBefore(line[:i], recv)
			}
			if i := strings.Index(line, "Received"); i > 0 {
				recv = firstInt(line[i:], recv)
			}
			if strings.Contains(line, "% packet loss") || strings.Contains(line, "% loss") {
				loss = percentBefore(line)
			}
		}
		if strings.Contains(line, "rtt min/avg/max") || strings.Contains(line, "round-trip") {
			minMS, avgMS, maxMS, jitter = parseRTT(line)
		}
		if strings.Contains(line, "Minimum =") {
			minMS = firstFloat(line, minMS)
			avgMS = firstFloat(strings.ToLower(line)[strings.Index(strings.ToLower(line), "average"):], avgMS)
			maxMS = firstFloat(line[strings.Index(line, "Maximum"):], maxMS)
		}
	}
	if sent > 0 && loss == 0 && recv >= 0 {
		loss = float64(sent-recv) * 100 / float64(sent)
	}
	return
}

func parseRTT(line string) (minMS, avgMS, maxMS, jitter float64) {
	parts := strings.Split(line, "=")
	if len(parts) < 2 {
		return
	}
	fields := strings.Split(strings.TrimSpace(strings.Fields(parts[len(parts)-1])[0]), "/")
	if len(fields) >= 3 {
		minMS, _ = strconv.ParseFloat(fields[0], 64)
		avgMS, _ = strconv.ParseFloat(fields[1], 64)
		maxMS, _ = strconv.ParseFloat(fields[2], 64)
	}
	if len(fields) >= 4 {
		jitter, _ = strconv.ParseFloat(fields[3], 64)
	}
	return
}

func execTrace(ctx context.Context, addr string, maxHops int) Sample {
	s := Sample{CreatedAt: time.Now(), ProbeType: "trace", Target: addr, Severity: Info}
	bin := "traceroute"
	args := []string{"-n", "-w", "1", "-q", "1", "-m", strconv.Itoa(maxHops), addr}
	if os.PathSeparator == '\\' {
		bin, args = "tracert", []string{"-d", "-h", strconv.Itoa(maxHops), "-w", "1000", addr}
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	out, err := cmd.CombinedOutput()
	text := string(out)
	if err != nil && len(out) == 0 {
		s.Severity, s.Message = Error, "trace_unavailable: "+trimErr(err, text)
		return s
	}
	hops := parseTrace(text)
	s.Message = formatHops(hops)
	s.StatusCode = len(hops)
	s.Success = reached(hops, addr)
	if !s.Success {
		s.Severity = Warning
	}
	return s
}

type traceHop struct {
	N    int
	Addr string
	RTT  string
}

func parseTrace(text string) []traceHop {
	var hops []traceHop
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		hop := traceHop{N: n, Addr: "*"}
		for _, f := range fields[1:] {
			if net.ParseIP(f) != nil {
				hop.Addr = f
				break
			}
		}
		hops = append(hops, hop)
	}
	return hops
}

func formatHops(hops []traceHop) string {
	if len(hops) == 0 {
		return "no hops recorded"
	}
	parts := make([]string, 0, len(hops))
	for _, h := range hops {
		parts = append(parts, fmt.Sprintf("%d %s", h.N, h.Addr))
	}
	return strings.Join(parts, " | ")
}

func reached(hops []traceHop, dest string) bool {
	for _, h := range hops {
		if h.Addr == dest {
			return true
		}
	}
	return false
}

func pickISPHop(hops []traceHop, gateway string) string {
	after := gateway == ""
	for _, h := range hops {
		if h.Addr == "" || h.Addr == "*" {
			continue
		}
		if gateway != "" && h.Addr == gateway {
			after = true
			continue
		}
		if after {
			return h.Addr
		}
	}
	for _, h := range hops {
		if h.N >= 2 && h.Addr != "" && h.Addr != "*" && h.Addr != gateway {
			return h.Addr
		}
	}
	return ""
}

func discoverGateway() (gw, iface string, err error) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		_ = scanner.Text()
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 8 || fields[1] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), fields[0], nil
	}
	return "", "", scanner.Err()
}

func dockerLike(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	_, d1, _ := net.ParseCIDR("172.16.0.0/12")
	_, d2, _ := net.ParseCIDR("10.0.0.0/8")
	return d1.Contains(parsed) || (d2.Contains(parsed) && strings.HasPrefix(ip, "172."))
}

func localIPs() string {
	addrs, _ := net.InterfaceAddrs()
	var ips []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.To4() == nil {
			continue
		}
		ips = append(ips, n.IP.String())
	}
	return strings.Join(ips, ",")
}

func (a *App) refreshNetInfo() {
	info := NetInfo{ContainerIP: localIPs(), HostNetwork: true}
	gw, iface, err := discoverGateway()
	if err == nil {
		info.DefaultGateway, info.DefaultIface = gw, iface
		if dockerLike(gw) {
			info.DockerGateway = gw
			info.HostNetwork = false
			info.Note = "Default route looks like a Docker bridge. Set GATEWAY_ADDR to the LAN router and prefer host networking."
		}
	} else {
		info.Note = "Gateway auto-discover unavailable: " + err.Error()
		info.HostNetwork = false
	}
	if a.cfg.GatewayAddr != "" {
		info.LANGateway, info.LANGatewaySource = a.cfg.GatewayAddr, "config"
	} else if info.DockerGateway == "" && info.DefaultGateway != "" {
		info.LANGateway, info.LANGatewaySource = info.DefaultGateway, "auto"
	} else if a.cfg.GatewayAddr == "" && info.DockerGateway != "" {
		info.Note = "Docker bridge gateway detected; set GATEWAY_ADDR to the LAN router."
	}
	if a.cfg.ISPHopAddr != "" {
		info.ISPHop = a.cfg.ISPHopAddr
	} else {
		info.ISPHop = a.ispHop
	}
	a.netMu.Lock()
	a.netInfo = info
	a.netMu.Unlock()
}

func readNIC(iface string) map[string]int64 {
	out := map[string]int64{}
	if iface == "" {
		return out
	}
	base := filepath.Join("/sys/class/net", iface, "statistics")
	for _, name := range []string{"rx_packets", "tx_packets", "rx_errors", "tx_errors", "rx_dropped", "tx_dropped"} {
		b, err := os.ReadFile(filepath.Join(base, name))
		if err != nil {
			continue
		}
		n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		out[name] = n
	}
	return out
}

func nicDeltaSample(iface string, before, after map[string]int64) *Sample {
	if len(before) == 0 || len(after) == 0 {
		return nil
	}
	rxE := after["rx_errors"] - before["rx_errors"]
	txE := after["tx_errors"] - before["tx_errors"]
	rxD := after["rx_dropped"] - before["rx_dropped"]
	txD := after["tx_dropped"] - before["tx_dropped"]
	if rxE < 0 {
		rxE = 0
	}
	if txE < 0 {
		txE = 0
	}
	if rxD < 0 {
		rxD = 0
	}
	if txD < 0 {
		txD = 0
	}
	if rxE == 0 && txE == 0 && rxD == 0 && txD == 0 {
		return nil
	}
	msg := fmt.Sprintf("RX errors increased by %d during this incident.", rxE)
	if txE > 0 {
		msg += fmt.Sprintf(" TX errors +%d.", txE)
	}
	if rxD > 0 || txD > 0 {
		msg += fmt.Sprintf(" drops rx+%d tx+%d.", rxD, txD)
	}
	return &Sample{CreatedAt: time.Now(), ProbeType: "nic", Target: iface, Severity: Warning, Bytes: rxE, StatusCode: int(txE), DNSMS: float64(rxD), ConnectMS: float64(txD), Message: msg}
}

func firstInt(s string, fallback int) int {
	n, ok := atoiFirst(s)
	if !ok {
		return fallback
	}
	return n
}

func lastIntBefore(s string, fallback int) int {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' })
	if len(fields) == 0 {
		return fallback
	}
	n, _ := strconv.Atoi(fields[len(fields)-1])
	return n
}

func percentBefore(s string) float64 {
	idx := strings.Index(s, "%")
	if idx <= 0 {
		return 0
	}
	start := idx
	for start > 0 && (s[start-1] == '.' || (s[start-1] >= '0' && s[start-1] <= '9')) {
		start--
	}
	n, _ := strconv.ParseFloat(s[start:idx], 64)
	return n
}

func firstFloat(s string, fallback float64) float64 {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return !((r >= '0' && r <= '9') || r == '.')
	}) {
		if n, err := strconv.ParseFloat(f, 64); err == nil {
			return n
		}
	}
	return fallback
}

func atoiFirst(s string) (int, bool) {
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r < '0' || r > '9' }) {
		if n, err := strconv.Atoi(f); err == nil {
			return n, true
		}
	}
	return 0, false
}

func trimErr(err error, out string) string {
	msg := err.Error()
	if out != "" {
		msg += ": " + strings.TrimSpace(out)
	}
	if len(msg) > 240 {
		msg = msg[:240]
	}
	return msg
}
