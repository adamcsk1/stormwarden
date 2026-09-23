package app

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	a, err := New(Config{Password: "correct-password", DataPath: filepath.Join(dir, "test.db"), ExportDir: filepath.Join(dir, "exports"), PiHoleAddr: "192.0.2.1:53", PublicDNS: "1.1.1.1:53", HTTPURL: "https://example.test", TransferURL: "https://example.test/file", HTTPExpectedStatus: 204, Timezone: time.UTC}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	return a
}

func TestClassifyLatency(t *testing.T) {
	for _, test := range []struct {
		value float64
		want  Severity
	}{{100, Info}, {251, Warning}, {3001, Error}} {
		got, _ := classifyLatency(test.value, "test")
		if got != test.want {
			t.Fatalf("classifyLatency(%v) = %s, want %s", test.value, got, test.want)
		}
	}
}

func TestTrafficProfiles(t *testing.T) {
	if profileTransferInterval("minimal") != 0 {
		t.Fatal("minimal profile runs transfer probes")
	}
	if profileTransferBytes("low") != 256*1024 {
		t.Fatal("wrong low transfer size")
	}
	if profileTransferBytes("detailed") != 5*1024*1024 {
		t.Fatal("wrong detailed transfer size")
	}
	if got := transferURL("https://example.test/file?bytes=1", 99); got != "https://example.test/file?bytes=99" {
		t.Fatalf("transfer URL = %q", got)
	}
}

func TestDNSResponseValidation(t *testing.T) {
	query := dnsQuery(42, "example.com")
	if err := validateDNSResponse(query, query, 42); err == nil {
		t.Fatal("query echo accepted as response")
	}
	empty := append([]byte(nil), query...)
	empty[2], empty[3] = 0x81, 0x80
	if err := validateDNSResponse(empty, query, 42); err == nil {
		t.Fatal("zero-answer response accepted")
	}
	nxdomain := negativeDNSResponse(t, query, dnsmessage.RCodeNameError)
	if err := validateDNSResponse(nxdomain, query, 42); err != nil {
		t.Fatalf("valid NXDOMAIN rejected: %v", err)
	}
	var request dnsmessage.Message
	_ = request.Unpack(query)
	referral := dnsmessage.Message{Header: dnsmessage.Header{ID: 42, Response: true, RecursionAvailable: true}, Questions: request.Questions, Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{1, 2, 3, 4}}}}}
	referralBytes, _ := referral.Pack()
	if err := validateDNSResponse(referralBytes, query, 42); err == nil {
		t.Fatal("referral accepted as negative answer")
	}
	valid := append(empty, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)
	binary.BigEndian.PutUint16(valid[6:8], 1)
	if err := validateDNSResponse(valid, query, 42); err != nil {
		t.Fatalf("valid response rejected: %v", err)
	}
}

func negativeDNSResponse(t *testing.T, query []byte, rcode dnsmessage.RCode) []byte {
	t.Helper()
	var request dnsmessage.Message
	if err := request.Unpack(query); err != nil {
		t.Fatal(err)
	}
	ns, _ := dnsmessage.NewName("ns.example.com.")
	mailbox, _ := dnsmessage.NewName("hostmaster.example.com.")
	response := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: request.Header.ID, Response: true, RecursionAvailable: true, RCode: rcode},
		Questions:   request.Questions,
		Authorities: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: request.Questions[0].Name, Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.SOAResource{NS: ns, MBox: mailbox, Serial: 1, Refresh: 60, Retry: 60, Expire: 60, MinTTL: 60}}},
	}
	packed, err := response.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return packed
}

func TestDNSQueriesBypassCache(t *testing.T) {
	_, firstName, first, err := newDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	_, secondName, second, err := newDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[12:], second[12:]) {
		t.Fatal("DNS probe names were reused")
	}
	if firstName == secondName || firstName == "" {
		t.Fatal("DNS probe names were not returned uniquely")
	}
	if !bytes.Contains(first, []byte("example")) {
		t.Fatal("DNS probe does not use expected domain")
	}
}

func TestDoHProbeAcceptsNXDOMAIN(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		response := negativeDNSResponse(t, query, dnsmessage.RCodeNameError)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	sample := probeDoH(context.Background(), "direct-doh", server.URL)
	if !sample.Success || sample.ProbeType != "doh" || !strings.Contains(sample.Message, "NXDOMAIN") || sample.NetworkResult != networkSuccess || sample.ProbeControl != probeCompleted {
		t.Fatalf("DoH result: %+v", sample)
	}
}

func TestDoHProbeValidatesHTTPResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	sample := probeDoH(context.Background(), "direct-doh", server.URL)
	if sample.Success || sample.StatusCode != http.StatusBadGateway || sample.NetworkResult != networkHTTPStatusError {
		t.Fatalf("invalid DoH HTTP result: %+v", sample)
	}
}

func TestURLRedaction(t *testing.T) {
	got := redactURL("https://user:password@example.test/path?token=secret#fragment")
	if got != "https://example.test/path" {
		t.Fatalf("redacted URL = %q", got)
	}
}

func TestHTTPErrorRedaction(t *testing.T) {
	raw := "https://user:password@example.test/path?token=secret"
	err := &url.Error{Op: "Get", URL: raw, Err: errors.New("dial failed")}
	message := redactHTTPError(err, raw)
	if strings.Contains(message, "secret") || strings.Contains(message, "password") {
		t.Fatalf("HTTP error leaked URL: %s", message)
	}
}

func TestProbesRunConcurrently(t *testing.T) {
	probe := func(context.Context) Sample { time.Sleep(100 * time.Millisecond); return Sample{} }
	started := time.Now()
	result := runConcurrentProbes(context.Background(), time.Second, []probeFunc{{Run: probe}, {Run: probe}, {Run: probe}})
	if len(result) != 3 {
		t.Fatalf("got %d results", len(result))
	}
	if elapsed := time.Since(started); elapsed > 220*time.Millisecond {
		t.Fatalf("probes ran sequentially: %v", elapsed)
	}
}

func TestProbeCycleEnforcesDeadline(t *testing.T) {
	stuck := func(context.Context) Sample { time.Sleep(300 * time.Millisecond); return Sample{Success: true} }
	started := time.Now()
	result := runConcurrentProbes(context.Background(), 40*time.Millisecond, []probeFunc{{ProbeType: "dns", Target: "pihole", Run: stuck}})
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("deadline not enforced: %v", elapsed)
	}
	if len(result) != 1 || result[0].Target != "pihole" || result[0].ProbeType != "dns" || result[0].ProbeControl != probeCancellationTimeout {
		t.Fatalf("missing timeout result: %+v", result)
	}
	if confirmedNetworkFailure(result[0]) {
		t.Fatalf("lifecycle timeout counted as network failure: %+v", result[0])
	}
}

func TestHTTPStatusAndTransferValidation(t *testing.T) {
	forbidden := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer forbidden.Close()
	if sample := probeHTTPStatus(context.Background(), "http", forbidden.URL, 1024, http.StatusNoContent); sample.Success || sample.Severity != Error {
		t.Fatalf("unexpected status accepted: %+v", sample)
	}

	short := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(bytes.Repeat([]byte("x"), 100)) }))
	defer short.Close()
	if sample := probeHTTPStatus(context.Background(), "transfer", short.URL, 1000, http.StatusOK); sample.Success || !strings.Contains(sample.Message, "short transfer") {
		t.Fatalf("short transfer accepted: %+v", sample)
	}
}

func TestTransferSpeedExcludesConnectionDelay(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 256*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer server.Close()
	sample := probeHTTPStatus(context.Background(), "transfer", server.URL, int64(len(payload)), http.StatusOK)
	if !sample.Success || sample.Severity != Info {
		t.Fatalf("connection delay polluted transfer speed: %+v", sample)
	}
	if sample.TTFBMS < 250 {
		t.Fatalf("TTFB did not capture delay: %.1f", sample.TTFBMS)
	}
}

func TestSlowTransferRemainsSuccessful(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), 100*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload[:1])
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(250 * time.Millisecond)
		_, _ = w.Write(payload[1:])
	}))
	defer server.Close()
	sample := probeHTTPStatus(context.Background(), "transfer", server.URL, int64(len(payload)), http.StatusOK)
	if !sample.Success || sample.Severity != Warning {
		t.Fatalf("slow complete transfer result: %+v", sample)
	}
}

func TestAggregateCriticalAfterConsecutiveFailures(t *testing.T) {
	a := newTestApp(t)
	failure := func(target string) Sample {
		return Sample{ProbeType: "tcp", Target: target, Severity: Error, Message: "failed"}
	}
	samples := []Sample{failure("pihole"), failure("pihole-udp"), failure("public-dns"), failure("direct-doh"), failure("internet-tcp")}
	if got := a.aggregateSample(samples); got.Severity != Error {
		t.Fatalf("first cycle = %s", got.Severity)
	}
	if got := a.aggregateSample(samples); got.Severity != Critical || got.Success {
		t.Fatalf("second cycle = %+v", got)
	}
}

func TestDiagnosisIdentifiesUDPInstability(t *testing.T) {
	a := newTestApp(t)
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Error, Message: "failed"},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Error, Message: "failed"},
		{ProbeType: "dns", Target: "public-dns", Severity: Error, Message: "failed"},
		{ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true, Message: "healthy"},
		{ProbeType: "tcp", Target: "internet-tcp", Severity: Info, Success: true, Message: "healthy"},
	}
	_, issues, _ := a.diagnoseSamples(samples)
	found := false
	for _, issue := range issues {
		if issue.Target == "direct_udp_path" && issue.Severity == Error {
			found = true
		}
	}
	if !found {
		t.Fatalf("UDP instability not diagnosed: %+v", issues)
	}
}

func TestDiagnosisReportsSlowSuccessfulDNSPath(t *testing.T) {
	a := newTestApp(t)
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Info, Success: true},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Warning, Success: true, Message: "DNS response above 250 ms"},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true},
		{ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true},
		{ProbeType: "tcp", Target: "internet-tcp", Severity: Info, Success: true},
	}
	aggregate, issues, _ := a.diagnoseSamples(samples)
	if !aggregate.Success || aggregate.Severity != Warning {
		t.Fatalf("aggregate result: %+v", aggregate)
	}
	found := false
	for _, issue := range issues {
		if issue.Target == "pihole_udp_path" && issue.Severity == Warning {
			found = true
		}
	}
	if !found {
		t.Fatalf("slow successful path omitted: %+v", issues)
	}
}

func TestDiagnosisCorrelatesTCPControls(t *testing.T) {
	a := newTestApp(t)
	base := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Info, Success: true, DurationMS: 10},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Info, Success: true, DurationMS: 10},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true, DurationMS: 15},
		{ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true, DurationMS: 40},
		{ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Warning, Success: true, ConnectMS: 1050, DurationMS: 1050, Message: "TCP connection above 250 ms to 1.1.1.1:443"},
		{ProbeType: "tcp", Target: "tcp:google", Severity: Info, Success: true, ConnectMS: 20, DurationMS: 20},
		{ProbeType: "http", Target: "http", Severity: Info, Success: true, ConnectMS: 30, DurationMS: 80},
	}
	_, issues, _ := a.diagnoseSamples(base)
	if issueMessage(issues, "destination_or_route_specific") == "" {
		t.Fatalf("single-target TCP not classified destination-specific: %+v", issues)
	}

	base[4] = Sample{ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Warning, Success: true, ConnectMS: 2080, DurationMS: 2080}
	base[5] = Sample{ProbeType: "tcp", Target: "tcp:google", Severity: Warning, Success: true, ConnectMS: 2090, DurationMS: 2090}
	base = append(base, Sample{ProbeType: "icmp-burst", Target: "icmp:gateway", Success: true, Mbps: 0, Message: "burst"})
	base = append(base, Sample{ProbeType: "icmp-burst", Target: "icmp:pihole", Success: true, Mbps: 0, Message: "burst"})
	base = append(base, Sample{ProbeType: "icmp-burst", Target: "icmp:internet", Success: true, Mbps: 30, Message: "burst"})
	_, issues, _ = a.diagnoseSamples(base)
	if issueMessage(issues, "wan_or_isp_packet_loss") == "" {
		t.Fatalf("multi-target TCP + upstream loss not WAN/ISP: %+v", issues)
	}
}

func TestAnnotate(t *testing.T) {
	a := newTestApp(t)
	if err := a.Annotate("Disabled Omada IDS/IPS"); err != nil {
		t.Fatal(err)
	}
	notes, err := recentAnnotations(context.Background(), a.db, 5)
	if err != nil || len(notes) != 1 || notes[0].Note != "Disabled Omada IDS/IPS" {
		t.Fatalf("annotations=%+v err=%v", notes, err)
	}
}

func issueMessage(issues []Sample, target string) string {
	for _, issue := range issues {
		if issue.Target == target {
			return issue.Message
		}
	}
	return ""
}

func TestIncidentHysteresisAndCauseUpdate(t *testing.T) {
	a := newTestApp(t)
	bad := Sample{ProbeType: "aggregate", Target: "local_dns", Severity: Error, Message: "Pi-hole failed"}
	a.updateIncident(context.Background(), bad)
	if active, _ := activeIncident(context.Background(), a.db); active != nil {
		t.Fatal("incident opened after one cycle")
	}
	a.updateIncident(context.Background(), bad)
	active, _ := activeIncident(context.Background(), a.db)
	if active == nil || active.Category != "local_dns" {
		t.Fatalf("incident not opened correctly: %+v", active)
	}
	changed := Sample{ProbeType: "aggregate", Target: "slow_ttfb", Severity: Warning, Message: "slow response"}
	a.updateIncident(context.Background(), changed)
	a.updateIncident(context.Background(), changed)
	activeList, _ := activeIncidents(context.Background(), a.db)
	if len(activeList) != 2 {
		t.Fatalf("concurrent incidents = %d", len(activeList))
	}
	foundSlow := false
	for _, incident := range activeList {
		if incident.Category == "slow_ttfb" && strings.Contains(incident.Summary, "slow response") {
			foundSlow = true
		}
	}
	if !foundSlow {
		t.Fatalf("slow incident missing: %+v", activeList)
	}
	healthy := Sample{ProbeType: "aggregate", Severity: Info}
	a.updateIncident(context.Background(), healthy)
	a.updateIncident(context.Background(), healthy)
	if active, _ = activeIncident(context.Background(), a.db); active == nil {
		t.Fatal("incident recovered too early")
	}
	a.updateIncident(context.Background(), healthy)
	if active, _ = activeIncident(context.Background(), a.db); active != nil {
		t.Fatal("incident did not recover after three cycles")
	}
}

func TestIncidentKeepsPeakAndRecordsEventSeverity(t *testing.T) {
	a := newTestApp(t)
	failed := Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Error, Message: "TCP 1.1.1.1:443 timed out"}
	a.updateIncident(context.Background(), failed)
	a.updateIncident(context.Background(), failed)
	warning := Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Warning, Message: "TCP 1.1.1.1:443 recovered slowly"}
	a.updateIncident(context.Background(), warning)
	incident, err := activeIncident(context.Background(), a.db)
	if err != nil || incident == nil {
		t.Fatalf("active incident: %+v, err=%v", incident, err)
	}
	if incident.Severity != Error || incident.Summary != warning.Message || !strings.Contains(incident.Evidence, "event_severity=warning") {
		t.Fatalf("peak and event severity conflated: %+v", incident)
	}
}

func TestIncidentKeepsPeakBeforeOpening(t *testing.T) {
	a := newTestApp(t)
	a.updateIncident(context.Background(), Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Error, Message: "timed out"})
	a.updateIncident(context.Background(), Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Warning, Message: "slow"})
	incident, err := activeIncident(context.Background(), a.db)
	if err != nil || incident == nil || incident.Severity != Error || incident.Summary != "slow" || !strings.Contains(incident.Evidence, "event_severity=error") || !strings.Contains(incident.Evidence, "event_severity=warning") {
		t.Fatalf("pre-open peak lost: incident=%+v err=%v", incident, err)
	}
}

func TestIncidentEvidenceRetainsPeakWhenTruncated(t *testing.T) {
	a := newTestApp(t)
	warning := Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Warning, Message: "initial warning"}
	a.updateIncident(context.Background(), warning)
	a.updateIncident(context.Background(), warning)
	a.updateIncident(context.Background(), Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Error, Message: "peak timeout evidence"})
	for range 80 {
		a.updateIncident(context.Background(), Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Warning, Message: strings.Repeat("later warning ", 20)})
	}
	incident, err := activeIncident(context.Background(), a.db)
	if err != nil || incident == nil || !strings.Contains(incident.Evidence, "peak timeout evidence") || !strings.Contains(incident.Evidence, "older events truncated") {
		t.Fatalf("peak evidence lost: incident=%+v err=%v", incident, err)
	}
}

func TestConnectionTracePrefersSuccessfulAttempt(t *testing.T) {
	trace := newConnectionTrace()
	trace.start("tcp6", "[2001:db8::1]:443")
	trace.start("tcp4", "192.0.2.1:443")
	trace.done("tcp4", "192.0.2.1:443", nil)
	successDuration := trace.duration()
	time.Sleep(time.Millisecond)
	trace.done("tcp6", "[2001:db8::1]:443", errors.New("canceled loser"))
	if trace.duration() != successDuration {
		t.Fatalf("failed parallel attempt replaced successful duration: before=%v after=%v", successDuration, trace.duration())
	}
}

func TestTCPProbeMessageIncludesDestination(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	sample := probeTCP(ctx, "internet-tcp", "192.0.2.1:443")
	if !strings.Contains(sample.Message, "192.0.2.1:443") {
		t.Fatalf("TCP destination missing: %+v", sample)
	}
}

func TestTransferIncidentOnlyRecoversWhenObserved(t *testing.T) {
	a := newTestApp(t)
	slow := Sample{ProbeType: "aggregate", Target: "slow_transfer", Severity: Warning, Message: "slow"}
	a.updateIncident(context.Background(), slow)
	a.updateIncident(context.Background(), slow)
	for range 3 {
		a.updateIncidents(context.Background(), nil, map[string]bool{"local_dns": true})
	}
	active, _ := activeIncidents(context.Background(), a.db)
	if len(active) != 1 {
		t.Fatalf("unobserved transfer incident closed: %d", len(active))
	}
	for range 3 {
		a.updateIncidents(context.Background(), nil, map[string]bool{"slow_transfer": true})
	}
	active, _ = activeIncidents(context.Background(), a.db)
	if len(active) != 0 {
		t.Fatalf("observed healthy transfer did not close incident: %d", len(active))
	}
}

func TestTransferTimeoutMeasuresBelowOneMbps(t *testing.T) {
	if timeout := transferProbeTimeout(5 * 1024 * 1024); timeout < 80*time.Second {
		t.Fatalf("detailed timeout too short: %v", timeout)
	}
	if timeout := transferProbeTimeout(256 * 1024); timeout != 30*time.Second {
		t.Fatalf("low timeout = %v", timeout)
	}
}

func TestAvailabilityUsesAggregateCyclesOnly(t *testing.T) {
	a := newTestApp(t)
	for range 10 {
		_ = insertSample(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "dns", Target: "public-dns", Severity: Error})
	}
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true})
	summary, err := a.dashboardSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Availability24 != 100 {
		t.Fatalf("availability = %.2f", summary.Availability24)
	}
}

func TestSummaryCountsIncidentsNotAggregateBlips(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "aggregate", Target: "internet", Severity: Error, Success: false})
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "aggregate", Target: "internet", Severity: Warning, Success: true})
	summary, err := a.dashboardSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Warnings24 != 0 || summary.Errors24 != 0 {
		t.Fatalf("1-cycle blips counted as incidents: %+v", summary)
	}

	bad := Sample{ProbeType: "aggregate", Target: "local_dns", Severity: Error, Message: "Pi-hole failed"}
	a.updateIncident(context.Background(), bad)
	a.updateIncident(context.Background(), bad)
	warn := Sample{ProbeType: "aggregate", Target: "slow_ttfb", Severity: Warning, Message: "slow"}
	a.updateIncident(context.Background(), warn)
	a.updateIncident(context.Background(), warn)
	summary, err = a.dashboardSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Warnings24 != 1 || summary.Errors24 != 1 {
		t.Fatalf("incident counts: warnings=%d errors=%d", summary.Warnings24, summary.Errors24)
	}

	old := dbTime(now.Add(-48 * time.Hour))
	_, err = a.db.Exec(`INSERT INTO incidents(started_at, ended_at, severity, category, summary) VALUES (?, ?, 'error', 'tcp_connect', 'old')`, old, old)
	if err != nil {
		t.Fatal(err)
	}
	summary, err = a.dashboardSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Warnings24 != 1 || summary.Errors24 != 1 {
		t.Fatalf("closed 48h incident counted: warnings=%d errors=%d", summary.Warnings24, summary.Errors24)
	}
}

func TestRecentDegradedSamplesSkipsHealthyAndOld(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "dns", Target: "pihole", Severity: Info, Success: true, Message: "healthy"})
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now.Add(-10 * time.Minute), ProbeType: "doh", Target: "direct-doh", Severity: Warning, Success: true, Message: "slow"})
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now.Add(-23 * time.Hour), ProbeType: "aggregate", Target: "internet", Severity: Error, Success: false, Message: "failed"})
	_ = insertSample(context.Background(), a.db, Sample{CreatedAt: now.Add(-48 * time.Hour), ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Error, Success: false, Message: "too old"})
	samples, err := recentDegradedSamples(context.Background(), a.db, now.Add(-24*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("got %d samples: %+v", len(samples), samples)
	}
	if samples[0].Severity != Warning || samples[1].Severity != Error {
		t.Fatalf("order/severity: %+v", samples)
	}
}

func TestCleanupRollsUpRawData(t *testing.T) {
	a := newTestApp(t)
	old := Sample{CreatedAt: time.Now().Add(-31 * 24 * time.Hour), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true, DurationMS: 10}
	if err := insertSample(context.Background(), a.db, old); err != nil {
		t.Fatal(err)
	}
	if err := cleanup(context.Background(), a.db, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var raw, quarter, daily int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&raw)
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM quarter_hour_rollups_v2 WHERE probe_type='aggregate' AND target='internet'`).Scan(&quarter)
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM daily_rollups_v2 WHERE probe_type='aggregate' AND target='internet'`).Scan(&daily)
	if raw != 0 || quarter != 1 || daily != 1 {
		t.Fatalf("raw=%d quarter=%d daily=%d", raw, quarter, daily)
	}
}

func TestPendingExportMarkedFailedAfterRestart(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Password: "test", DataPath: filepath.Join(dir, "test.db"), ExportDir: filepath.Join(dir, "exports"), Timezone: time.UTC}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('pending', ?, 'day', '', 0, 'pending')`, dbTime(time.Now()))
	_ = a.Close()
	a, err = New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var status string
	_ = a.db.QueryRow(`SELECT status FROM exports WHERE id='pending'`).Scan(&status)
	if status != "failed" {
		t.Fatalf("pending export status = %s", status)
	}
}

func TestPrivacyV2ScrubsExistingIncidents(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Password: "test", DataPath: filepath.Join(dir, "test.db"), ExportDir: filepath.Join(dir, "exports"), Timezone: time.UTC}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec(`DELETE FROM settings WHERE key='privacy_scrub_v2'`)
	_, _ = a.db.Exec(`INSERT INTO incidents(started_at, severity, category, summary, evidence) VALUES (?, 'error', 'slow_ttfb', 'token=secret', 'url?token=secret')`, dbTime(time.Now()))
	_ = a.Close()
	a, err = New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var summary, evidence string
	if err := a.db.QueryRow(`SELECT summary, evidence FROM incidents LIMIT 1`).Scan(&summary, &evidence); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(summary+evidence, "secret") {
		t.Fatalf("incident was not scrubbed: %s %s", summary, evidence)
	}
}

func TestLegacyHourlyRollupsMigrated(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Password: "test", DataPath: filepath.Join(dir, "test.db"), ExportDir: filepath.Join(dir, "exports"), Timezone: time.UTC}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.db.Exec(`INSERT INTO hourly_rollups(bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps) VALUES ('2025-01-01T10:00:00Z', 'aggregate', 4, 3, 0, 1, 0, 10, 5, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.db.Exec(`INSERT INTO daily_rollups(bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps) VALUES ('2024-01-01T00:00:00Z', 'aggregate', 96, 90, 2, 4, 0, 10, 5, 0)`)
	if err != nil {
		t.Fatal(err)
	}
	_ = a.Close()
	a, err = New(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	var samples int
	_ = a.db.QueryRow(`SELECT samples FROM quarter_hour_rollups WHERE bucket='2025-01-01T10:00:00Z' AND probe_type='aggregate'`).Scan(&samples)
	if samples != 4 {
		t.Fatalf("migrated samples = %d", samples)
	}
	_ = a.db.QueryRow(`SELECT samples FROM quarter_hour_rollups WHERE bucket='2024-01-01T00:00:00Z' AND probe_type='aggregate'`).Scan(&samples)
	if samples != 96 {
		t.Fatalf("migrated daily samples = %d", samples)
	}
}

func TestExpiredExportCleanupDoesNotDeadlock(t *testing.T) {
	a := newTestApp(t)
	path := filepath.Join(a.cfg.ExportDir, "expired.zip")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('old', ?, 'day', ?, 4, 'complete')`, dbTime(time.Now().Add(-8*24*time.Hour)), path)
	done := make(chan struct{})
	go func() { a.cleanupExports(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cleanup deadlocked")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("expired file remains")
	}
}

func TestDeleteExportRemovesFileAndRow(t *testing.T) {
	a := newTestApp(t)
	path := filepath.Join(a.cfg.ExportDir, "keep.zip")
	if err := os.WriteFile(path, []byte("zip"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('del-me', ?, 'day', ?, 3, 'complete')`, dbTime(time.Now()), path)
	cookie := login(t, a)
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		t.Fatal("session missing")
	}
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/exports/del-me/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", result.Code, result.Body.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("export file remains")
	}
	var n int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM exports WHERE id='del-me'`).Scan(&n)
	if n != 0 {
		t.Fatal("export row remains")
	}
	if strings.Contains(result.Body.String(), "del-me") {
		t.Fatalf("deleted export still listed: %s", result.Body.String())
	}
}

func TestDeleteExportRejectsPathEscapeAndBadCSRF(t *testing.T) {
	a := newTestApp(t)
	outside := filepath.Join(t.TempDir(), "secret.zip")
	if err := os.WriteFile(outside, []byte("no"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('evil', ?, 'day', ?, 2, 'complete')`, dbTime(time.Now()), outside)
	cookie := login(t, a)
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		t.Fatal("session missing")
	}
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/exports/evil/delete", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusForbidden {
		t.Fatalf("escaped path status = %d", result.Code)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatal("outside file was removed")
	}

	bad := httptest.NewRequest(http.MethodPost, "/ui/exports/evil/delete", strings.NewReader("csrf=wrong"))
	bad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	bad.AddCookie(cookie)
	denied := httptest.NewRecorder()
	a.Handler().ServeHTTP(denied, bad)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF status = %d", denied.Code)
	}
}

func TestExportContainsBoundedAIData(t *testing.T) {
	a := newTestApp(t)
	inside := Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true, Message: "inside"}
	outside := inside
	outside.CreatedAt = time.Now().Add(-48 * time.Hour)
	outside.Message = "outside"
	_ = insertSample(context.Background(), a.db, inside)
	_ = insertSample(context.Background(), a.db, outside)
	rsrp := -96.0
	_ = insertModemSample(context.Background(), a.db, ModemSample{CreatedAt: time.Now(), RSRP: &rsrp, Operator: "Yettel"})
	_ = insertModemSample(context.Background(), a.db, ModemSample{CreatedAt: time.Now().Add(-48 * time.Hour), RSRP: &rsrp, Operator: "Old Carrier"})
	_, _ = a.db.Exec(`INSERT INTO incidents(started_at, severity, category, summary, evidence) VALUES (?, 'error', 'outage', 'overlapping', '')`, dbTime(time.Now().Add(-48*time.Hour)))
	job := exportJob{ID: "test-export", RangeName: "day", From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Minute)}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES (?, ?, 'day', '', 0, 'pending')`, job.ID, dbTime(time.Now()))
	if err := a.processExport(context.Background(), job); err != nil {
		t.Fatal(err)
	}
	var path string
	if err := a.db.QueryRow(`SELECT path FROM exports WHERE id=?`, job.ID).Scan(&path); err != nil {
		t.Fatal(err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	wanted := map[string]bool{"summary.md": false, "measurements.jsonl": false, "incidents.jsonl": false, "modem-samples.jsonl": false, "dns-path-summary.json": false, "quarter-hour-rollups.jsonl": false, "settings-redacted.json": false}
	for _, file := range reader.File {
		if _, ok := wanted[file.Name]; ok {
			wanted[file.Name] = true
		}
		if file.Name == "measurements.jsonl" {
			stream, _ := file.Open()
			data, _ := io.ReadAll(stream)
			_ = stream.Close()
			if strings.Contains(string(data), "outside") {
				t.Fatal("export ignored upper/lower date bounds")
			}
		}
		if file.Name == "incidents.jsonl" {
			stream, _ := file.Open()
			data, _ := io.ReadAll(stream)
			_ = stream.Close()
			if !strings.Contains(string(data), "overlapping") {
				t.Fatal("overlapping incident omitted")
			}
		}
		if file.Name == "modem-samples.jsonl" {
			stream, _ := file.Open()
			data, _ := io.ReadAll(stream)
			_ = stream.Close()
			if strings.Contains(string(data), "Old Carrier") {
				t.Fatal("modem export ignored time bounds")
			}
			var sample map[string]any
			if err := json.Unmarshal(data, &sample); err != nil || sample["operator"] != "Yettel" || sample["created_at"] == nil || sample["rsrp"] == nil {
				t.Fatalf("modem export=%s err=%v", data, err)
			}
		}
	}
	for name, found := range wanted {
		if !found {
			t.Errorf("export missing %s", name)
		}
	}
}

func TestDNSPathSummaryIncludesRetainedRollups(t *testing.T) {
	a := newTestApp(t)
	bucket := dbTime(time.Now().Add(-40 * 24 * time.Hour).Truncate(15 * time.Minute))
	_, err := a.db.Exec(`INSERT INTO quarter_hour_rollups_v2(bucket, probe_type, target, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms, avg_mbps) VALUES (?, 'dns', 'pihole', 10, 8, 1, 1, 0, 20, 20, 0, 0, 0, 0)`, bucket)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := a.db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	summaries, err := loadDNSPathSummaries(context.Background(), tx, dbTime(time.Now().Add(-50*24*time.Hour)), dbTime(time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Samples != 10 || summaries[0].Successes != 8 || summaries[0].AvgDurationMS != 20 {
		t.Fatalf("rollup summary: %+v", summaries)
	}
}

func login(t *testing.T, a *App) *http.Cookie {
	t.Helper()
	form := url.Values{"password": {"correct-password"}}
	request := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusSeeOther || len(result.Result().Cookies()) == 0 {
		t.Fatalf("login failed: %d", result.Code)
	}
	return result.Result().Cookies()[0]
}

func TestLoginDashboardAndCSRF(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	dashboard := httptest.NewRequest(http.MethodGet, "/", nil)
	dashboard.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, dashboard)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), `hx-get="/ui/summary"`) {
		t.Fatalf("dashboard failed: %d", result.Code)
	}
	settings := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader("profile=minimal"))
	settings.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	settings.AddCookie(cookie)
	settingsResult := httptest.NewRecorder()
	a.Handler().ServeHTTP(settingsResult, settings)
	if settingsResult.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF accepted: %d", settingsResult.Code)
	}
}

func TestHealthDetectsStalePersistence(t *testing.T) {
	a := newTestApp(t)
	a.startedAt, a.lastPersist = time.Now().Add(-2*time.Minute), time.Now().Add(-2*time.Minute)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	result := httptest.NewRecorder()
	a.health(result, request)
	if result.Code != http.StatusServiceUnavailable {
		t.Fatalf("stale health status = %d", result.Code)
	}
	a.lastPersist = time.Now()
	result = httptest.NewRecorder()
	a.health(result, request)
	if result.Code != http.StatusOK {
		t.Fatalf("fresh health status = %d", result.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	limiter := newLoginLimiter()
	for range 5 {
		if !limiter.allow("192.0.2.1") {
			t.Fatal("blocked before fifth failure")
		}
		limiter.failure("192.0.2.1")
	}
	if limiter.allow("192.0.2.1") {
		t.Fatal("fifth failure was not throttled")
	}
	limiter.success("192.0.2.1")
	if !limiter.allow("192.0.2.1") {
		t.Fatal("successful login did not reset limiter")
	}
}

func TestLoginLimiterStorageIsBounded(t *testing.T) {
	limiter := newLoginLimiter()
	for i := range 5000 {
		limiter.failure(string(rune(i + 1)))
	}
	if size := len(limiter.attempts); size > 1000 {
		t.Fatalf("limiter contains %d entries", size)
	}
	if !limiter.allow("new-client") {
		t.Fatal("LRU limiter globally blocked unrelated client")
	}
}

func TestIncidentPagination(t *testing.T) {
	a := newTestApp(t)
	for i := range 51 {
		started := dbTime(time.Now().Add(time.Duration(i) * time.Second))
		_, _ = a.db.Exec(`INSERT INTO incidents(started_at, ended_at, severity, category, summary, evidence) VALUES (?, ?, 'warning', 'test', ?, '')`, started, started, "test")
	}
	first, more, err := incidentPage(context.Background(), a.db, 50, 0)
	if err != nil || len(first) != 50 || !more {
		t.Fatalf("first page len=%d more=%v err=%v", len(first), more, err)
	}
	second, more, err := incidentPage(context.Background(), a.db, 50, 50)
	if err != nil || len(second) != 1 || more {
		t.Fatalf("second page len=%d more=%v err=%v", len(second), more, err)
	}
}

func TestIncidentPaginationShowsOnlyDirectionalControls(t *testing.T) {
	a := newTestApp(t)
	result := httptest.NewRecorder()
	a.render(result, "incidents.html", map[string]any{
		"Incidents": []incidentView{{Incident: Incident{StartedAt: time.Now(), Severity: Warning, Category: "tcp_connect", Summary: "slow"}}},
		"Next":      true,
		"NextPage":  1,
	})
	body := result.Body.String()
	if !strings.Contains(body, ">Older<") || strings.Contains(body, "Page ") {
		t.Fatalf("unexpected pagination: %s", body)
	}
	result = httptest.NewRecorder()
	a.render(result, "incidents.html", map[string]any{"Incidents": []incidentView{{Incident: Incident{StartedAt: time.Now(), Severity: Warning, Category: "tcp_connect", Summary: "slow"}}}})
	if strings.Contains(result.Body.String(), `<nav class="pagination">`) {
		t.Fatalf("empty pagination rendered: %s", result.Body.String())
	}
}

func TestDNSPathFragmentShowsAllControls(t *testing.T) {
	a := newTestApp(t)
	for _, target := range []string{"pihole", "pihole-udp", "public-dns", "direct-doh"} {
		if err := insertSample(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "dns", Target: target, Severity: Info, Success: true, DurationMS: 12, Message: "healthy"}); err != nil {
			t.Fatal(err)
		}
	}
	result := httptest.NewRecorder()
	a.dnsPathsFragment(result, httptest.NewRequest(http.MethodGet, "/ui/dns-paths", nil))
	body := result.Body.String()
	for _, label := range []string{"Pi-hole TCP", "Pi-hole UDP", "Direct UDP", "Direct DoH"} {
		if !strings.Contains(body, label) {
			t.Fatalf("DNS path fragment missing %s: %s", label, body)
		}
	}
}

func TestDNSPathFragmentMarksStaleSamples(t *testing.T) {
	a := newTestApp(t)
	result := httptest.NewRecorder()
	a.render(result, "dns-paths.html", map[string]any{"Paths": []dnsPathView{{Label: "Direct DoH", Sample: &Sample{CreatedAt: time.Now().Add(-time.Minute), Severity: Info}, Stale: true}}})
	if !strings.Contains(result.Body.String(), ">stale<") {
		t.Fatalf("stale state missing: %s", result.Body.String())
	}
}

func TestWidePanelScrollDoesNotCollapseOnMobile(t *testing.T) {
	css, err := webFiles.ReadFile("web/static/incidents.css")
	if err != nil {
		t.Fatal(err)
	}
	text := string(css)
	if !strings.Contains(text, "@media (min-width: 851px)") || !strings.Contains(text, "height: 0") {
		t.Fatal("wide panel stretch is not desktop-only")
	}
	if !strings.Contains(text, "@media (max-width: 850px)") || !strings.Contains(text, "max-height: min(70vh, 720px)") {
		t.Fatal("mobile panel-body lacks a scroll cap")
	}
}

func TestDNSPathBadgeDoesNotStretch(t *testing.T) {
	css, err := webFiles.ReadFile("web/static/dns-paths.css")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(css), ".dns-path .badge") || !strings.Contains(string(css), "justify-self: start") {
		t.Fatal("DNS path badge lacks compact grid alignment")
	}
}

func TestParseAssetTargets(t *testing.T) {
	targets, err := parseAssetTargets("Video|https://example.test/video.jpg\nNews|cache-bust|https://example.test/news.png;Map|http://example.test/map.webp")
	if err != nil || len(targets) != 3 || targets[2].Name != "Map" || !targets[1].CacheBust {
		t.Fatalf("parsed targets = %+v, err = %v", targets, err)
	}
	pipeURL, err := parseAssetTargets("Legacy|https://example.test/path|segment")
	if err != nil || pipeURL[0].URL != "https://example.test/path|segment" {
		t.Fatalf("legacy URL containing pipe rejected: %+v, err = %v", pipeURL, err)
	}
	if _, err := parseAssetTargets("File|ftp://example.test/file"); err == nil {
		t.Fatal("non-HTTP asset URL accepted")
	}
	if _, err := parseAssetTargets(strings.Repeat("Image|https://example.test/image.jpg\n", maxAssetTargets+1)); err == nil {
		t.Fatal("too many asset targets accepted")
	}
	if assetSampleTarget(targets[0]) == assetSampleTarget(AssetTarget{Name: targets[0].Name, URL: targets[0].URL, CacheBust: true}) {
		t.Fatal("fixed and cache-busted sample identities collide")
	}
}

func TestCacheBustedAssetURLPreservesQuery(t *testing.T) {
	got := cacheBustedAssetURL("https://example.test/file?bytes=32768", "unique")
	parsed, err := url.Parse(got)
	if err != nil || parsed.Query().Get("bytes") != "32768" || parsed.Query().Get("stormwarden") != "unique" {
		t.Fatalf("cache-busted URL = %q, err = %v", got, err)
	}
}

func TestAssetProbeSchedulesCacheBustEveryFiveMinutes(t *testing.T) {
	var fixed, cacheBusted atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("stormwarden") == "" {
			fixed.Add(1)
		} else {
			cacheBusted.Add(1)
		}
		_, _ = w.Write([]byte("asset"))
	}))
	defer server.Close()
	a := newTestApp(t)
	configured := "Fixed|" + server.URL + "/fixed\nBusted|cache-bust|" + server.URL + "/busted?bytes=32768"
	if err := setSetting(context.Background(), a.db, "asset_targets", configured); err != nil {
		t.Fatal(err)
	}
	a.nextCacheBustProbe = time.Now().Add(time.Minute)
	a.runAssetProbeCycle(context.Background())
	if fixed.Load() != 1 || cacheBusted.Load() != 0 {
		t.Fatalf("early cycle counts: fixed=%d cache-busted=%d", fixed.Load(), cacheBusted.Load())
	}
	a.nextCacheBustProbe = time.Now()
	a.runAssetProbeCycle(context.Background())
	if fixed.Load() != 2 || cacheBusted.Load() != 1 {
		t.Fatalf("due cycle counts: fixed=%d cache-busted=%d", fixed.Load(), cacheBusted.Load())
	}
}

func TestAssetDefaultMigrationRunsOnce(t *testing.T) {
	a := newTestApp(t)
	_, _ = a.db.Exec(`DELETE FROM settings WHERE key='asset_defaults_v2'`)
	if err := setSetting(context.Background(), a.db, "asset_targets", legacyDefaultAssetTargets); err != nil {
		t.Fatal(err)
	}
	configured, err := initializeAssetSettings(context.Background(), a.db, defaultAssetTargets)
	if err != nil || configured != defaultAssetTargets {
		t.Fatalf("migrated defaults = %q, err = %v", configured, err)
	}
	if err := setSetting(context.Background(), a.db, "asset_targets", legacyDefaultAssetTargets); err != nil {
		t.Fatal(err)
	}
	configured, err = initializeAssetSettings(context.Background(), a.db, defaultAssetTargets)
	if err != nil || configured != legacyDefaultAssetTargets {
		t.Fatalf("removed default was re-added: %q, err = %v", configured, err)
	}
}

func TestFreshLegacyAssetOverrideIsNotMigrated(t *testing.T) {
	a := newTestApp(t)
	_, _ = a.db.Exec(`DELETE FROM settings WHERE key IN ('asset_targets', 'asset_defaults_v2')`)
	configured, err := initializeAssetSettings(context.Background(), a.db, legacyDefaultAssetTargets)
	if err != nil || configured != legacyDefaultAssetTargets {
		t.Fatalf("explicit legacy override changed: %q, err = %v", configured, err)
	}
}

func TestCacheBustedIncidentRecoversAfterNextObservation(t *testing.T) {
	a := newTestApp(t)
	category := assetIncidentCategory(AssetTarget{Name: "Busted", CacheBust: true})
	failure := Sample{ProbeType: "aggregate", Target: category, Severity: Error, Message: "failed"}
	a.updateIncident(context.Background(), failure)
	a.updateIncident(context.Background(), failure)
	a.updateIncidents(context.Background(), nil, map[string]bool{category: true})
	incident, err := activeIncident(context.Background(), a.db)
	if err != nil || incident != nil {
		t.Fatalf("cache-busted incident did not recover: %+v, err = %v", incident, err)
	}
}

func TestAssetProbeBoundsDownloadAndRecordsSpeed(t *testing.T) {
	payload := bytes.Repeat([]byte("x"), assetDownloadLimit*2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(payload) }))
	defer server.Close()

	sample := probeAsset(context.Background(), AssetTarget{Name: "Representative image", URL: server.URL}, "")
	if !sample.Success || sample.Target != "asset:Representative image|"+server.URL || sample.Bytes != assetDownloadLimit || sample.Mbps <= 0 || sample.DurationMS <= 0 {
		t.Fatalf("asset result: %+v", sample)
	}
}

func TestAssetProbeCyclePersistsConfiguredTarget(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("image")) }))
	defer server.Close()
	a := newTestApp(t)
	configured := "Image|" + server.URL + "/asset.jpg?token=secret"
	if err := setSetting(context.Background(), a.db, "asset_targets", configured); err != nil {
		t.Fatal(err)
	}
	a.runAssetProbeCycle(context.Background())
	sample, err := latestSampleByTarget(context.Background(), a.db, "asset:Image|"+server.URL+"/asset.jpg")
	if err != nil || sample == nil || !sample.Success || strings.Contains(sample.Target, "secret") {
		t.Fatalf("persisted asset sample = %+v, err = %v", sample, err)
	}
}

func TestAssetFragmentShowsPhaseMetrics(t *testing.T) {
	a := newTestApp(t)
	if err := setSetting(context.Background(), a.db, "asset_targets", "Video|https://example.test/video.jpg"); err != nil {
		t.Fatal(err)
	}
	if err := insertSample(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "asset", Target: "asset:Video|https://example.test/video.jpg", Severity: Info, Success: true, DNSMS: 1, ConnectMS: 2, TLSMS: 3, TTFBMS: 4, DurationMS: 5, Bytes: 1024, Mbps: 6, Message: "healthy"}); err != nil {
		t.Fatal(err)
	}

	result := httptest.NewRecorder()
	a.assetsFragment(result, httptest.NewRequest(http.MethodGet, "/ui/assets", nil))
	body := result.Body.String()
	for _, value := range []string{"Video", "DNS", "TCP", "TLS", "TTFB", "Total", "Size", "Speed", "6.0 Mbps"} {
		if !strings.Contains(body, value) {
			t.Fatalf("asset fragment missing %q: %s", value, body)
		}
	}
}

func TestSettingsSaveAssetTargets(t *testing.T) {
	a := newTestApp(t)
	a.incidentStates["asset_path:Old"] = &incidentState{badCycles: 1}
	if err := openIncident(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "asset_path:Old", Severity: Error, Message: "failed"}); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, a)
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		t.Fatal("login session missing")
	}
	form := url.Values{"profile": {"minimal"}, "asset_targets": {"News|https://example.test/news.jpg"}, "csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	configured, err := setting(context.Background(), a.db, "asset_targets")
	if result.Code != http.StatusOK || err != nil || configured != form.Get("asset_targets") {
		t.Fatalf("saved asset targets = %q, status = %d, err = %v", configured, result.Code, err)
	}
	incidents, err := activeIncidents(context.Background(), a.db)
	if err != nil || len(incidents) != 0 || a.incidentStates["asset_path:Old"] != nil {
		t.Fatalf("removed asset incident remains active: incidents=%+v state=%+v err=%v", incidents, a.incidentStates["asset_path:Old"], err)
	}
}

func TestClearRecordedDataKeepsSettings(t *testing.T) {
	a := newTestApp(t)
	if err := insertSample(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Warning, DurationMS: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := openIncident(context.Background(), a.db, Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "tcp_connect", Severity: Warning, Message: "slow"}); err != nil {
		t.Fatal(err)
	}
	if err := setSetting(context.Background(), a.db, "profile", "detailed"); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, a)
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		t.Fatal("login session missing")
	}
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/clear-data", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", result.Code, result.Body.String())
	}
	var samples, incidents int
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM samples`).Scan(&samples)
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM incidents`).Scan(&incidents)
	profile, _ := setting(context.Background(), a.db, "profile")
	if samples != 0 || incidents != 0 || profile != "detailed" {
		t.Fatalf("samples=%d incidents=%d profile=%s", samples, incidents, profile)
	}
}
