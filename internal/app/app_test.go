package app

import (
	"archive/zip"
	"bytes"
	"context"
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
	samples := []Sample{failure("pihole"), failure("internet-tcp"), failure("http")}
	if got := a.aggregateSample(samples); got.Severity != Error {
		t.Fatalf("first cycle = %s", got.Severity)
	}
	if got := a.aggregateSample(samples); got.Severity != Critical || got.Success {
		t.Fatalf("second cycle = %+v", got)
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
	active, _ = activeIncident(context.Background(), a.db)
	if active.Category != "slow_ttfb" || active.Severity != Error || !strings.Contains(active.Evidence, "slow response") {
		t.Fatalf("cause/evidence not updated: %+v", active)
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
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM quarter_hour_rollups WHERE probe_type='aggregate'`).Scan(&quarter)
	_ = a.db.QueryRow(`SELECT COUNT(*) FROM daily_rollups WHERE probe_type='aggregate'`).Scan(&daily)
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
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('pending', ?, 'day', '', 0, 'pending')`, time.Now().UTC().Format(time.RFC3339Nano))
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
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES ('old', ?, 'day', ?, 4, 'complete')`, time.Now().Add(-8*24*time.Hour).UTC().Format(time.RFC3339Nano), path)
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
	_, _ = a.db.Exec(`INSERT INTO incidents(started_at, severity, category, summary, evidence) VALUES (?, 'error', 'outage', 'overlapping', '')`, time.Now().Add(-48*time.Hour).UTC().Format(time.RFC3339Nano))
	job := exportJob{ID: "test-export", RangeName: "day", From: time.Now().Add(-24 * time.Hour), To: time.Now().Add(time.Minute)}
	_, _ = a.db.Exec(`INSERT INTO exports(id, created_at, range_name, path, size, status) VALUES (?, ?, 'day', '', 0, 'pending')`, job.ID, time.Now().UTC().Format(time.RFC3339Nano))
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
	wanted := map[string]bool{"summary.md": false, "measurements.jsonl": false, "incidents.jsonl": false, "quarter-hour-rollups.jsonl": false, "settings-redacted.json": false}
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
	if size := len(limiter.attempts); size > 1001 {
		t.Fatalf("limiter contains %d entries", size)
	}
}

func TestIncidentPagination(t *testing.T) {
	a := newTestApp(t)
	for i := range 51 {
		_, _ = a.db.Exec(`INSERT INTO incidents(started_at, severity, category, summary, evidence) VALUES (?, 'warning', 'test', ?, '')`, time.Now().Add(time.Duration(i)*time.Second).UTC().Format(time.RFC3339Nano), "test")
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
