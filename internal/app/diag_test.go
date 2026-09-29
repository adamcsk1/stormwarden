package app

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestBurstLimiterCooldown(t *testing.T) {
	now := time.Now()
	b := &burstLimiter{cooldown: 2 * time.Minute, now: func() time.Time { return now }}
	if !b.try() {
		t.Fatal("first burst blocked")
	}
	if b.try() {
		t.Fatal("in-flight burst allowed")
	}
	b.done()
	if b.try() {
		t.Fatal("cooldown ignored")
	}
	now = now.Add(2 * time.Minute)
	if !b.try() {
		t.Fatal("burst after cooldown blocked")
	}
	b.done()
}

func TestForcedBurstKeepsAutomaticCooldown(t *testing.T) {
	now := time.Now()
	b := &burstLimiter{cooldown: time.Minute, now: func() time.Time { return now }}
	if !b.try() {
		t.Fatal("first burst blocked")
	}
	b.done()
	now = now.Add(30 * time.Second)
	if !b.force() {
		t.Fatal("manual burst blocked by cooldown")
	}
	b.release()
	if b.try() {
		t.Fatal("manual burst cleared automatic cooldown")
	}
	now = now.Add(30 * time.Second)
	if !b.try() {
		t.Fatal("manual burst delayed automatic burst")
	}
	b.done()
}

func TestBurstLimiterContextCancelDoesNotMatter(t *testing.T) {
	a := newTestApp(t)
	a.cfg.PingEnabled = true
	a.cfg.BurstCount = 3
	a.cfg.BurstInterval = 10 * time.Millisecond
	a.cfg.BurstTimeout = time.Second
	a.cfg.PingInternetAddr = "192.0.2.1"
	a.cfg.PingPiholeAddr = ""
	a.cfg.GatewayAddr = ""
	a.cfg.ISPHopAddr = ""
	a.cfg.NICStatsEnabled = false
	a.cfg.TracerouteEnabled = false
	a.burst = newBurstLimiter(time.Minute)
	calls := 0
	a.ping = func(ctx context.Context, addr string, count int, interval, perPacket time.Duration) Sample {
		calls++
		return Sample{ProbeType: "icmp-burst", Target: addr, Success: true, Message: "ok"}
	}
	extra := a.maybeBurst(context.Background(), []Sample{tcpSample("cloudflare", Error, 4000, false)})
	if calls != 1 || len(extra) != 1 {
		t.Fatalf("calls=%d extra=%d", calls, len(extra))
	}
	extra2 := a.maybeBurst(context.Background(), []Sample{tcpSample("cloudflare", Error, 4000, false)})
	if extra2 != nil {
		t.Fatal("cooldown failed to suppress second burst")
	}
}

func TestParsePingIncompleteWindowsLine(t *testing.T) {
	sent, recv, loss, minMS, avgMS, maxMS, _ := parsePing("Minimum = 1ms", 10)
	if sent != 10 || recv != 0 || loss != 100 || minMS != 1 || avgMS != 0 || maxMS != 0 {
		t.Fatalf("incomplete line panicked or misparsed sent=%d recv=%d loss=%v min=%v avg=%v max=%v", sent, recv, loss, minMS, avgMS, maxMS)
	}
}

func TestParsePingLinux(t *testing.T) {
	text := `PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
10 packets transmitted, 7 received, 30% packet loss, time 1351ms
rtt min/avg/max/mdev = 1.200/2.400/5.000/0.800 ms`
	sent, recv, loss, minMS, avgMS, maxMS, jitter := parsePing(text, 10)
	if sent != 10 || recv != 7 || loss != 30 || minMS != 1.2 || avgMS != 2.4 || maxMS != 5 || jitter != 0.8 {
		t.Fatalf("parsed %+v", []any{sent, recv, loss, minMS, avgMS, maxMS, jitter})
	}
}

func TestParseTraceAndISPHop(t *testing.T) {
	text := ` 1  192.168.88.1  0.4 ms
 2  10.50.0.1  8 ms
 3  1.1.1.1  12 ms`
	hops := parseTrace(text)
	if len(hops) != 3 || hops[0].Addr != "192.168.88.1" {
		t.Fatalf("hops=%+v", hops)
	}
	if got := pickISPHop(hops, "192.168.88.1"); got != "10.50.0.1" {
		t.Fatalf("isp hop=%s", got)
	}
}

func TestDockerLikeGateway(t *testing.T) {
	if !dockerLike("172.23.0.1") || dockerLike("192.168.88.1") {
		t.Fatal("docker gateway detection")
	}
}

func TestRefreshNetInfoNoteWhenGatewayConfigured(t *testing.T) {
	a := newTestApp(t)
	a.cfg.GatewayAddr = "192.168.88.1"
	a.refreshNetInfo()
	a.netMu.RLock()
	note := a.netInfo.Note
	src := a.netInfo.LANGatewaySource
	a.netMu.RUnlock()
	if src != "config" {
		t.Fatalf("source=%s", src)
	}
	if strings.Contains(note, "Set GATEWAY_ADDR") {
		t.Fatalf("still nags for GATEWAY_ADDR: %s", note)
	}
}

func TestIsAnomaly(t *testing.T) {
	if isAnomaly([]Sample{{ProbeType: "tcp", Severity: Info, Success: true}}) {
		t.Fatal("healthy TCP is anomaly")
	}
	if !isAnomaly([]Sample{{ProbeType: "tcp", Severity: Warning, Success: true, ConnectMS: 1040}}) {
		t.Fatal("slow TCP not anomaly")
	}
}

func TestFormatHopsSkipsClaimingStarIsBroken(t *testing.T) {
	msg := formatHops([]traceHop{{N: 2, Addr: "*"}})
	if strings.Contains(strings.ToLower(msg), "broken") || strings.Contains(strings.ToLower(msg), "fault") {
		t.Fatalf("star hop over-interpreted: %s", msg)
	}
}
