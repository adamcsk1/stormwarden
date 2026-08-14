package app

import (
	"archive/zip"
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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
	_, first, err := newDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := newDNSQuery()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first[12:], second[12:]) {
		t.Fatal("DNS probe names were reused")
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
	if !sample.Success || sample.ProbeType != "doh" || !strings.Contains(sample.Message, "NXDOMAIN") {
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
	if sample.Success || sample.DurationMS <= 0 || sample.StatusCode != http.StatusBadGateway {
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
	if len(result) != 1 || result[0].Target != "pihole" || result[0].ProbeType != "dns" || result[0].Severity != Error {
		t.Fatalf("missing timeout result: %+v", result)
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

func TestExportContainsBoundedAIData(t *testing.T) {
	a := newTestApp(t)
	inside := Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true, Message: "inside"}
	outside := inside
	outside.CreatedAt = time.Now().Add(-48 * time.Hour)
	outside.Message = "outside"
	_ = insertSample(context.Background(), a.db, inside)
	_ = insertSample(context.Background(), a.db, outside)
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
	wanted := map[string]bool{"summary.md": false, "measurements.jsonl": false, "incidents.jsonl": false, "dns-path-summary.json": false, "quarter-hour-rollups.jsonl": false, "settings-redacted.json": false}
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

func TestIncidentPaginationDisplaysOneBasedPage(t *testing.T) {
	a := newTestApp(t)
	result := httptest.NewRecorder()
	a.render(result, "incidents.html", map[string]any{
		"Incidents":   []Incident{{StartedAt: time.Now(), Severity: Warning, Category: "tcp_connect", Summary: "slow"}},
		"DisplayPage": 1,
	})
	body := result.Body.String()
	if !strings.Contains(body, "Page 1") || strings.Contains(body, "Page 0") {
		t.Fatalf("unexpected pagination: %s", body)
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
