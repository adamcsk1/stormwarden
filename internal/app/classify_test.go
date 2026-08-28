package app

import "testing"

func healthyDNS() []Sample {
	return []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Info, Success: true, DurationMS: 12},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Info, Success: true, DurationMS: 10},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true, DurationMS: 18},
		{ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true, DurationMS: 22},
	}
}

func tcpSample(name string, severity Severity, ms float64, ok bool) Sample {
	return Sample{ProbeType: "tcp", Target: "tcp:" + name, Severity: severity, Success: ok, DurationMS: ms, ConnectMS: ms}
}

func burst(target string, loss float64) Sample {
	sent, recv := 10, 10-int(loss/10)
	if loss == 0 {
		recv = 10
	}
	if loss >= 100 {
		recv = 0
	}
	return Sample{ProbeType: "icmp-burst", Target: "icmp:" + target, Success: loss == 0, Severity: Info, Bytes: int64(sent), StatusCode: recv, Mbps: loss, DurationMS: 2, Message: "burst"}
}

func TestRetransmissionSuspected(t *testing.T) {
	for _, ms := range []float64{1000, 1040, 2086, 3010, 4003} {
		if !retransmissionSuspected(ms) {
			t.Fatalf("expected retransmission tag at %.0fms", ms)
		}
	}
	if retransmissionSuspected(24) || retransmissionSuspected(400) {
		t.Fatal("normal RTT tagged as retransmission")
	}
}

func TestClassifyPiholeOnly(t *testing.T) {
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Error, Message: "fail"},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Error, Message: "fail"},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true, DurationMS: 20},
		{ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true, DurationMS: 25},
		tcpSample("cloudflare", Info, 20, true),
		burst("gateway", 0), burst("pihole", 0), burst("internet", 0),
	}
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "local_dns", "high", Error)
	if !containsAll(d.Evidence, "Pi-hole TCP failed", "external DNS controls succeeded") {
		t.Fatalf("evidence: %+v", d.Evidence)
	}
}

func TestClassifyLANFailure(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Error, 4000, false),
		burst("gateway", 40), burst("pihole", 30), burst("internet", 40),
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "local_network_or_host", "high", Error)
}

func TestClassifyWANPacketLoss(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Warning, 2086, true),
		tcpSample("google", Warning, 2101, true),
		tcpSample("quad9", Error, 4002, false),
		Sample{ProbeType: "http", Target: "http", Severity: Warning, Success: true, ConnectMS: 2090},
		burst("gateway", 0), burst("pihole", 0), burst("internet", 30),
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "wan_or_isp_packet_loss", "high", Error)
	if !containsAll(d.Evidence, "gateway packet loss 0%", "internet/ISP target packet loss 30%", "tcp connect times clustered near retransmission intervals", "dns controls remained healthy") {
		t.Fatalf("evidence: %+v", d.Evidence)
	}
}

func TestClassifyInternetOutageFallsToWANWhenICMPMissing(t *testing.T) {
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Error},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Error},
		{ProbeType: "dns", Target: "public-dns", Severity: Error},
		{ProbeType: "doh", Target: "direct-doh", Severity: Error},
		tcpSample("cloudflare", Error, 4000, false),
		tcpSample("google", Error, 4000, false),
	}
	d := classify(Snapshot{Samples: samples})
	if d.Classification == "local_dns" {
		t.Fatalf("outage classified as local DNS: %+v", d)
	}
}

func TestClassifyOneDestination(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Error, 4000, false),
		tcpSample("google", Info, 18, true),
		tcpSample("quad9", Info, 22, true),
		burst("gateway", 0), burst("internet", 0),
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "destination_or_route_specific", "high", Warning)
}

func TestClassifyDNSOnly(t *testing.T) {
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Error},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Error},
		{ProbeType: "dns", Target: "public-dns", Severity: Error},
		{ProbeType: "doh", Target: "direct-doh", Severity: Error},
		tcpSample("cloudflare", Info, 20, true),
		tcpSample("google", Info, 21, true),
		burst("internet", 0),
	}
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "dns_resolution_failure", "high", Error)
}

func TestClassifyRetransmissionPattern(t *testing.T) {
	samples := append(healthyDNS(), tcpSample("cloudflare", Warning, 1040, true))
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "tcp_connect_establishment", "medium", Warning)
	if !containsAll(d.Evidence, "tcp connect times clustered near retransmission intervals") {
		t.Fatalf("missing retrans evidence: %+v", d)
	}
}

func TestClassifyTLSOnly(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Info, 20, true),
		Sample{ProbeType: "http", Target: "http", Severity: Error, Success: false, ConnectMS: 24, TLSMS: 4000, Message: "tls timeout"},
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "tls_or_remote_service", "high", Warning)
}

func TestClassifyNICAloneDoesNotStealWAN(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Warning, 2086, true),
		tcpSample("google", Warning, 2101, true),
		burst("gateway", 0), burst("pihole", 0), burst("internet", 30),
		Sample{ProbeType: "nic", Target: "eth0", Bytes: 1, Message: "RX errors increased by 1 during this incident."},
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "wan_or_isp_packet_loss", "high", Error)
	if !containsAll(d.Evidence, "RX errors increased by 1 during this incident.") {
		t.Fatalf("NIC evidence dropped: %+v", d.Evidence)
	}
}

func TestClassifyHostNIC(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Error, 4000, false),
		burst("gateway", 20), burst("pihole", 10),
		Sample{ProbeType: "nic", Target: "eth0", Bytes: 14, Message: "RX errors increased by 14 during this incident."},
	)
	d := classify(Snapshot{Samples: samples})
	assertDiagnosis(t, d, "host_or_nic", "high", Error)
}

func TestClassifyContradictoryUnknown(t *testing.T) {
	d := classify(Snapshot{Samples: healthyDNS()})
	if d.Classification != "unknown" || d.Confidence != "low" {
		t.Fatalf("want unknown/low, got %+v", d)
	}
}

func TestClassifyWANKeepsISPHopContradiction(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Warning, 2080, true),
		tcpSample("google", Warning, 2090, true),
		burst("gateway", 0), burst("pihole", 0), burst("isp_hop", 0), burst("internet", 40),
	)
	d := classify(Snapshot{Samples: samples})
	if d.Classification != "wan_or_isp_packet_loss" {
		t.Fatalf("got %s", d.Classification)
	}
	if !containsAll(d.Contradictions, "isp first-hop probe remained healthy") {
		t.Fatalf("contradictions hidden: %+v", d.Contradictions)
	}
}

func TestClassifyDoesNotTreatICMPUnavailableAsDown(t *testing.T) {
	samples := append(healthyDNS(),
		tcpSample("cloudflare", Info, 20, true),
		Sample{ProbeType: "icmp-burst", Target: "icmp:internet", Success: false, Message: "icmp_unavailable: permission denied"},
	)
	d := classify(Snapshot{Samples: samples})
	if d.Classification == "wan_or_isp_packet_loss" || d.Classification == "internet_outage" {
		t.Fatalf("icmp unavailable treated as outage: %+v", d)
	}
}

func assertDiagnosis(t *testing.T, d Diagnosis, class, conf string, sev Severity) {
	t.Helper()
	if d.Classification != class || d.Confidence != conf || d.Severity != sev {
		t.Fatalf("got class=%s conf=%s sev=%s (summary=%s evidence=%v), want %s/%s/%s", d.Classification, d.Confidence, d.Severity, d.Summary, d.Evidence, class, conf, sev)
	}
}

func containsAll(have []string, want ...string) bool {
	for _, w := range want {
		found := false
		for _, h := range have {
			if h == w || (len(w) > 0 && len(h) >= len(w) && (h == w || containsFold(h, w))) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func containsFold(h, w string) bool {
	return len(h) >= len(w) && (h == w || (len(w) > 8 && (stringContains(h, w))))
}

func stringContains(h, w string) bool {
	return len(w) > 0 && (h == w || len(h) > len(w) && search(h, w))
}

func search(h, w string) bool {
	for i := 0; i+len(w) <= len(h); i++ {
		if h[i:i+len(w)] == w {
			return true
		}
	}
	return false
}
