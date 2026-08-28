package app

import (
	"archive/zip"
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type exportRecord struct {
	ID        string
	CreatedAt time.Time
	RangeName string
	Path      string
	Size      string
	Status    string
	Error     string
}

type exportJob struct {
	ID, RangeName string
	From, To      time.Time
}

func (a *App) exportWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-a.exportJobs:
			if err := a.processExport(ctx, job); err != nil {
				a.logger.Error("export failed", "id", job.ID, "error", err)
				_, _ = a.db.ExecContext(context.Background(), `UPDATE exports SET status='failed', error=? WHERE id=?`, err.Error(), job.ID)
			}
		}
	}
}

func (a *App) exportsFragment(w http.ResponseWriter, r *http.Request) {
	a.renderExports(w, r, "exports.html")
}

func (a *App) renderExports(w http.ResponseWriter, r *http.Request, templateName string) {
	records, err := a.listExports(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, templateName, map[string]any{"Exports": records, "CSRF": s.CSRF})
}

func (a *App) listExports(ctx context.Context) ([]exportRecord, error) {
	rows, err := a.db.QueryContext(ctx, `SELECT id, created_at, range_name, path, size, status, error FROM exports ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []exportRecord
	for rows.Next() {
		var record exportRecord
		var created string
		var size int64
		if err := rows.Scan(&record.ID, &created, &record.RangeName, &record.Path, &size, &record.Status, &record.Error); err != nil {
			return nil, err
		}
		record.CreatedAt, _ = parseDBTime(created)
		record.Size = humanBytes(size)
		records = append(records, record)
	}
	return records, rows.Err()
}

func (a *App) createExport(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	rangeName := r.FormValue("range")
	now := time.Now()
	job := exportJob{RangeName: rangeName, To: now}
	switch rangeName {
	case "day":
		job.From = now.Add(-24 * time.Hour)
	case "week":
		job.From = now.Add(-7 * 24 * time.Hour)
	case "month":
		job.From = now.Add(-30 * 24 * time.Hour)
	case "all":
		job.From = time.Unix(0, 0)
	case "custom":
		from, fromErr := time.ParseInLocation("2006-01-02", r.FormValue("from"), a.cfg.Timezone)
		to, toErr := time.ParseInLocation("2006-01-02", r.FormValue("to"), a.cfg.Timezone)
		if fromErr != nil || toErr != nil || to.Before(from) {
			http.Error(w, "invalid date range", http.StatusBadRequest)
			return
		}
		job.From, job.To = from, to.AddDate(0, 0, 1)
	default:
		http.Error(w, "invalid range", http.StatusBadRequest)
		return
	}
	id, err := randomToken()
	if err != nil {
		http.Error(w, "secure token generation failed", http.StatusInternalServerError)
		return
	}
	job.ID = id[:20]
	_, err = a.db.ExecContext(r.Context(), `INSERT INTO exports(id, created_at, range_name, path, size, status, error) VALUES (?, ?, ?, '', 0, 'pending', '')`, job.ID, dbTime(now), rangeName)
	if err != nil {
		http.Error(w, "export creation failed", http.StatusInternalServerError)
		return
	}
	select {
	case a.exportJobs <- job:
	default:
		_, _ = a.db.ExecContext(r.Context(), `UPDATE exports SET status='failed', error='export queue is full' WHERE id=?`, job.ID)
	}
	a.renderExports(w, r, "export-list")
}

func (a *App) processExport(ctx context.Context, job exportJob) error {
	temp, err := os.CreateTemp(a.cfg.ExportDir, ".export-*.zip")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	zw := zip.NewWriter(temp)
	if err := a.writeExport(ctx, zw, job.From, job.To); err != nil {
		_ = zw.Close()
		_ = temp.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	finalPath := filepath.Join(a.cfg.ExportDir, fmt.Sprintf("stormwarden-%s-%s.zip", job.RangeName, job.ID))
	if err := os.Rename(tempPath, finalPath); err != nil {
		return err
	}
	stat, err := os.Stat(finalPath)
	if err != nil {
		return err
	}
	result, err := a.db.ExecContext(ctx, `UPDATE exports SET path=?, size=?, status='complete', error='' WHERE id=?`, finalPath, stat.Size(), job.ID)
	if err != nil {
		_ = os.Remove(finalPath)
		return err
	}
	rows, _ := result.RowsAffected()
	if rows != 1 {
		_ = os.Remove(finalPath)
		return errors.New("export record disappeared")
	}
	return nil
}

func (a *App) writeExport(ctx context.Context, zw *zip.Writer, from, to time.Time) error {
	a.dataMu.RLock()
	defer a.dataMu.RUnlock()
	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	fromText, toText := dbTime(from), dbTime(to)
	var total, successful, warnings, errorCount, criticals int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(success),0), COALESCE(SUM(severity='warning'),0), COALESCE(SUM(severity='error'),0), COALESCE(SUM(severity='critical'),0) FROM samples WHERE probe_type='aggregate' AND created_at>=? AND created_at<?`, fromText, toText).Scan(&total, &successful, &warnings, &errorCount, &criticals)
	if err != nil {
		return err
	}
	var rolledTotal, rolledSuccessful, rolledWarnings, rolledErrors, rolledCriticals int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(samples),0), COALESCE(SUM(successes),0), COALESCE(SUM(warnings),0), COALESCE(SUM(errors),0), COALESCE(SUM(criticals),0) FROM quarter_hour_rollups_v2 WHERE probe_type='aggregate' AND bucket>=? AND bucket<?`, fromText, toText).Scan(&rolledTotal, &rolledSuccessful, &rolledWarnings, &rolledErrors, &rolledCriticals); err != nil {
		return err
	}
	total, successful = total+rolledTotal, successful+rolledSuccessful
	warnings, errorCount, criticals = warnings+rolledWarnings, errorCount+rolledErrors, criticals+rolledCriticals
	var incidentCount int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE started_at<? AND (ended_at IS NULL OR ended_at>?)`, toText, fromText).Scan(&incidentCount); err != nil {
		return err
	}
	var profile string
	_ = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='profile'`).Scan(&profile)
	var assetTargetSetting string
	_ = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='asset_targets'`).Scan(&assetTargetSetting)
	assetTargets, _ := parseAssetTargets(assetTargetSetting)
	redactedAssetTargets := make([]map[string]string, 0, len(assetTargets))
	for _, target := range assetTargets {
		mode := "fixed"
		if target.CacheBust {
			mode = "cache-bust"
		}
		redactedAssetTargets = append(redactedAssetTargets, map[string]string{"name": target.Name, "url": redactURL(target.URL), "mode": mode})
	}
	availability := 100.0
	if total > 0 {
		availability = float64(successful) * 100 / float64(total)
	}
	cover := computeCoverage(ctx, a.db, from, to, a.startedAt)
	daily := dailyAnomalyCounts(ctx, a.db, from, to, a.cfg.Timezone)
	prevFrom := from.Add(-to.Sub(from))
	left, right := periodStats(ctx, a.db, from, to), periodStats(ctx, a.db, prevFrom, from)
	notes, _ := listAnnotations(ctx, a.db, from, to, 50)
	summary := buildExportSummary(a.cfg.Timezone, from, to, profile, len(assetTargets), total, availability, warnings, errorCount, criticals, incidentCount, cover, daily, left, right, notes)
	if err := zipText(zw, "README.md", "Use summary.md for an overview and the JSONL files for detailed analysis. JSONL contains one JSON object per line. Raw data retains 30 days; rollups preserve older trends.\n"); err != nil {
		return err
	}
	if err := zipText(zw, "summary.md", summary); err != nil {
		return err
	}
	if err := a.zipSamples(ctx, tx, zw, fromText, toText); err != nil {
		return err
	}
	if err := a.zipIncidents(ctx, tx, zw, fromText, toText); err != nil {
		return err
	}
	dnsPaths, err := loadDNSPathSummaries(ctx, tx, fromText, toText)
	if err != nil {
		return err
	}
	if err := zipJSON(zw, "dns-path-summary.json", dnsPaths); err != nil {
		return err
	}
	if err := a.zipRollups(ctx, tx, zw, "quarter_hour_rollups_v2", "quarter-hour-rollups.jsonl", fromText, toText); err != nil {
		return err
	}
	if notes == nil {
		notes = []Annotation{}
	}
	if err := zipJSON(zw, "annotations.json", notes); err != nil {
		return err
	}
	settings := map[string]any{"profile": profile, "asset_targets": redactedAssetTargets, "pihole_dns_target": a.cfg.PiHoleAddr, "public_dns_target": a.cfg.PublicDNS, "doh_probe_url": redactURL(a.cfg.DoHURL), "http_dns_target": a.cfg.HTTPDNSAddr, "http_probe_url": redactURL(a.cfg.HTTPURL), "http_expected_status": a.cfg.HTTPExpectedStatus, "transfer_probe_url": redactURL(a.cfg.TransferURL), "tcp_controls": a.cfg.tcpControls(), "gateway_addr": a.cfg.GatewayAddr, "ping_enabled": a.cfg.PingEnabled, "raw_retention_days": 30, "rollup_retention": "indefinite", "export_retention_days": 7}
	if err := zipJSON(zw, "settings-redacted.json", settings); err != nil {
		return err
	}
	a.netMu.RLock()
	netInfo := a.netInfo
	a.netMu.RUnlock()
	if err := zipJSON(zw, "system-info.json", map[string]any{"go_version": runtime.Version(), "os": runtime.GOOS, "architecture": runtime.GOARCH, "app_uptime": time.Since(a.startedAt).String(), "network": netInfo}); err != nil {
		return err
	}
	return tx.Commit()
}

func (a *App) zipSamples(ctx context.Context, tx *sql.Tx, zw *zip.Writer, from, to string) error {
	w, err := zw.Create("measurements.jsonl")
	if err != nil {
		return err
	}
	buffer, encoder := bufio.NewWriter(w), json.NewEncoder(w)
	encoder = json.NewEncoder(buffer)
	lastID := int64(0)
	for {
		rows, err := tx.QueryContext(ctx, `SELECT `+sampleColumns+` FROM samples WHERE id>? AND created_at>=? AND created_at<? ORDER BY id LIMIT 5000`, lastID, from, to)
		if err != nil {
			return err
		}
		batch := make([]Sample, 0, 5000)
		for rows.Next() {
			sample, scanErr := scanSample(rows)
			if scanErr != nil {
				rows.Close()
				return scanErr
			}
			batch = append(batch, sample)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, sample := range batch {
			if err := encoder.Encode(sample); err != nil {
				return err
			}
			lastID = sample.ID
		}
		if len(batch) < 5000 {
			break
		}
	}
	return buffer.Flush()
}

func (a *App) zipIncidents(ctx context.Context, tx *sql.Tx, zw *zip.Writer, from, to string) error {
	w, err := zw.Create("incidents.jsonl")
	if err != nil {
		return err
	}
	buffer, encoder := bufio.NewWriter(w), json.NewEncoder(w)
	encoder = json.NewEncoder(buffer)
	lastID := int64(0)
	for {
		rows, err := tx.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id>? AND started_at<? AND (ended_at IS NULL OR ended_at>?) ORDER BY id LIMIT 1000`, lastID, to, from)
		if err != nil {
			return err
		}
		batch := make([]Incident, 0, 1000)
		for rows.Next() {
			incident, scanErr := scanIncident(rows)
			if scanErr != nil {
				rows.Close()
				return scanErr
			}
			batch = append(batch, incident)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, incident := range batch {
			if err := encoder.Encode(incident); err != nil {
				return err
			}
			lastID = incident.ID
		}
		if len(batch) < 1000 {
			break
		}
	}
	return buffer.Flush()
}

type rollup struct {
	Bucket        string  `json:"bucket"`
	ProbeType     string  `json:"probe_type"`
	Target        string  `json:"target"`
	Samples       int     `json:"samples"`
	Successes     int     `json:"successes"`
	Warnings      int     `json:"warnings"`
	Errors        int     `json:"errors"`
	Criticals     int     `json:"criticals"`
	AvgDurationMS float64 `json:"avg_duration_ms"`
	AvgDNSMS      float64 `json:"avg_dns_ms"`
	AvgConnectMS  float64 `json:"avg_connect_ms"`
	AvgTLSMS      float64 `json:"avg_tls_ms"`
	AvgTTFBMS     float64 `json:"avg_ttfb_ms"`
	AvgMbps       float64 `json:"avg_mbps"`
}

type dnsPathSummary struct {
	Target        string  `json:"target"`
	Samples       int     `json:"samples"`
	Successes     int     `json:"successes"`
	AvgDurationMS float64 `json:"avg_duration_ms"`
}

func loadDNSPathSummaries(ctx context.Context, tx *sql.Tx, from, to string) ([]dnsPathSummary, error) {
	type accumulator struct {
		samples, successes int
		totalDuration      float64
	}
	values := make(map[string]accumulator)
	queries := []string{
		`SELECT target, COUNT(*), SUM(success), SUM(duration_ms) FROM samples WHERE target IN ('pihole','pihole-udp','public-dns','direct-doh') AND created_at>=? AND created_at<? GROUP BY target`,
		`SELECT target, SUM(samples), SUM(successes), SUM(avg_duration_ms*samples) FROM quarter_hour_rollups_v2 WHERE target IN ('pihole','pihole-udp','public-dns','direct-doh') AND bucket>=? AND bucket<? GROUP BY target`,
	}
	for _, query := range queries {
		rows, err := tx.QueryContext(ctx, query, from, to)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var target string
			var samples, successes int
			var totalDuration float64
			if err := rows.Scan(&target, &samples, &successes, &totalDuration); err != nil {
				rows.Close()
				return nil, err
			}
			value := values[target]
			value.samples, value.successes, value.totalDuration = value.samples+samples, value.successes+successes, value.totalDuration+totalDuration
			values[target] = value
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	keys := make([]string, 0, len(values))
	for target := range values {
		keys = append(keys, target)
	}
	sort.Strings(keys)
	result := make([]dnsPathSummary, 0, len(keys))
	for _, target := range keys {
		value := values[target]
		average := 0.0
		if value.samples > 0 {
			average = value.totalDuration / float64(value.samples)
		}
		result = append(result, dnsPathSummary{Target: target, Samples: value.samples, Successes: value.successes, AvgDurationMS: average})
	}
	return result, nil
}

func (a *App) zipRollups(ctx context.Context, tx *sql.Tx, zw *zip.Writer, table, name, from, to string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT bucket, probe_type, target, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms, avg_mbps FROM `+table+` WHERE bucket>=? AND bucket<? ORDER BY bucket`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	encoder := json.NewEncoder(w)
	for rows.Next() {
		var value rollup
		if err := rows.Scan(&value.Bucket, &value.ProbeType, &value.Target, &value.Samples, &value.Successes, &value.Warnings, &value.Errors, &value.Criticals, &value.AvgDurationMS, &value.AvgDNSMS, &value.AvgConnectMS, &value.AvgTLSMS, &value.AvgTTFBMS, &value.AvgMbps); err != nil {
			return err
		}
		if err := encoder.Encode(value); err != nil {
			return err
		}
	}
	return rows.Err()
}

func buildExportSummary(loc *time.Location, from, to time.Time, profile string, assetCount, total int, availability float64, warnings, errorCount, criticals, incidentCount int, cover coverageInfo, daily []dayCount, current, previous compareStats, notes []Annotation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Stormwarden Diagnostic Report\n\n")
	fmt.Fprintf(&b, "Requested period: %s to %s\n", from.In(loc).Format(time.RFC3339), to.In(loc).Format(time.RFC3339))
	fmt.Fprintf(&b, "Available data: %s to %s\n", formatMaybe(cover.FirstSample, loc), formatMaybe(cover.LastSample, loc))
	fmt.Fprintf(&b, "Generated: %s\n", time.Now().In(loc).Format(time.RFC3339))
	fmt.Fprintf(&b, "Application uptime: %s\n", cover.Uptime)
	fmt.Fprintf(&b, "Data coverage: %.1f%% (%d/%d expected 15s cycles)\n", cover.Percent, cover.Actual, cover.Expected)
	fmt.Fprintf(&b, "Traffic profile: %s\nAsset probes: %d\n\n## Summary\n\n", profile, assetCount)
	fmt.Fprintf(&b, "- Health cycles: %d\n- Availability: %.2f%%\n- Warning cycles: %d\n- Error cycles: %d\n- Critical cycles: %d\n- Incidents: %d\n", total, availability, warnings, errorCount, criticals, incidentCount)
	if len(cover.Gaps) > 0 {
		b.WriteString("\n## Monitoring gaps\n\n")
		for _, gap := range cover.Gaps {
			fmt.Fprintf(&b, "- %s\n", gap)
		}
	}
	if len(daily) > 0 {
		b.WriteString("\n## TCP connectivity anomalies by day\n\n")
		var rates []float64
		for _, day := range daily {
			fmt.Fprintf(&b, "- %s: %d\n", day.Day, day.Count)
			rates = append(rates, float64(day.Count))
		}
		mid := len(rates) / 2
		if mid > 0 {
			if note := rateShift(rates[mid:], rates[:mid]); note != "" {
				fmt.Fprintf(&b, "\n%s\n", note)
			}
		}
	}
	b.WriteString("\n## A/B vs previous equal window\n\n")
	fmt.Fprintf(&b, "- Incidents: %d vs %d\n- TCP median: %.0f ms vs %.0f ms\n- TCP P95: %.0f ms vs %.0f ms\n- DNS fail: %.2f%% vs %.2f%%\n- HTTP connect fail: %.2f%% vs %.2f%%\n", current.Anomalies, previous.Anomalies, current.TCPMedian, previous.TCPMedian, current.TCPP95, previous.TCPP95, current.DNSFailPct, previous.DNSFailPct, current.HTTPConnectFailPct, previous.HTTPConnectFailPct)
	if len(current.ClassCounts) > 0 {
		b.WriteString("\n## Incident classifications\n\n")
		for cat, n := range current.ClassCounts {
			fmt.Fprintf(&b, "- %s: %d\n", cat, n)
		}
	}
	if len(notes) > 0 {
		b.WriteString("\n## Configuration-change annotations\n\n")
		for _, note := range notes {
			fmt.Fprintf(&b, "- %s %s\n", note.CreatedAt.In(loc).Format(time.RFC3339), note.Note)
		}
	}
	b.WriteString("\n## Interpretation\n\nClassification estimates the lowest healthy layer, then where failure begins. ICMP silence, traceroute non-replies, and ~1s TCP delays are evidence, not proof of packet loss. Path differences are evidence, not proof of a specific transport cause.\n\n## Privacy\n\nAuthentication secrets, sessions, cookies, headers, and DNS answers are excluded. Configured targets remain because diagnosis requires them; URL credentials, queries, and fragments are removed.\n")
	return b.String()
}

func formatMaybe(t time.Time, loc *time.Location) string {
	if t.IsZero() {
		return "none"
	}
	return t.In(loc).Format(time.RFC3339)
}

func zipText(zw *zip.Writer, name, value string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, value)
	return err
}
func zipJSON(zw *zip.Writer, name string, value any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func (a *App) downloadExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var path, rangeName, status string
	if err := a.db.QueryRowContext(r.Context(), `SELECT path, range_name, status FROM exports WHERE id=?`, id).Scan(&path, &rangeName, &status); err != nil || status != "complete" {
		http.NotFound(w, r)
		return
	}
	cleanDir, dirErr := filepath.Abs(a.cfg.ExportDir)
	cleanPath, pathErr := filepath.Abs(path)
	if dirErr != nil || pathErr != nil || !strings.HasPrefix(cleanPath, cleanDir+string(os.PathSeparator)) {
		http.Error(w, "invalid export path", http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="stormwarden-%s-%s.zip"`, rangeName, time.Now().Format("20060102")))
	w.Header().Set("Content-Type", "application/zip")
	http.ServeFile(w, r, cleanPath)
}

func humanBytes(size int64) string {
	if size >= 1024*1024 {
		return fmt.Sprintf("%.1f MB", float64(size)/(1024*1024))
	}
	if size >= 1024 {
		return fmt.Sprintf("%.1f KB", float64(size)/1024)
	}
	return fmt.Sprintf("%d B", size)
}
