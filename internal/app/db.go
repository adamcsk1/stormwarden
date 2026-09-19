package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const dbTimeLayout = "2006-01-02T15:04:05.000000000Z"

func dbTime(value time.Time) string { return value.UTC().Format(dbTimeLayout) }

func parseDBTime(value string) (time.Time, error) {
	if parsed, err := time.Parse(dbTimeLayout, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339Nano, value)
}

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout%3d5000&_pragma=foreign_keys%3don&_pragma=journal_mode%3dWAL"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  probe_type TEXT NOT NULL,
  target TEXT NOT NULL,
  severity TEXT NOT NULL,
  success INTEGER NOT NULL,
  duration_ms REAL NOT NULL DEFAULT 0,
  dns_ms REAL NOT NULL DEFAULT 0,
  connect_ms REAL NOT NULL DEFAULT 0,
  tls_ms REAL NOT NULL DEFAULT 0,
  ttfb_ms REAL NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0,
  mbps REAL NOT NULL DEFAULT 0,
  status_code INTEGER NOT NULL DEFAULT 0,
  message TEXT NOT NULL DEFAULT '',
  network_result TEXT NOT NULL DEFAULT '',
  probe_control TEXT NOT NULL DEFAULT '',
  probe_stage TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_samples_created ON samples(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_samples_severity ON samples(severity, created_at DESC);
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  started_at TEXT NOT NULL,
  ended_at TEXT,
  severity TEXT NOT NULL,
  category TEXT NOT NULL,
  summary TEXT NOT NULL,
  evidence TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_incidents_started ON incidents(started_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_incidents_active_category ON incidents(category) WHERE ended_at IS NULL;
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
INSERT OR IGNORE INTO settings(key, value) VALUES ('profile', 'low');
CREATE TABLE IF NOT EXISTS exports (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  range_name TEXT NOT NULL,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'complete',
  error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS hourly_rollups (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL,
  PRIMARY KEY(bucket, probe_type)
);
CREATE TABLE IF NOT EXISTS quarter_hour_rollups (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL,
  PRIMARY KEY(bucket, probe_type)
);
CREATE TABLE IF NOT EXISTS daily_rollups (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL,
  PRIMARY KEY(bucket, probe_type)
);
CREATE TABLE IF NOT EXISTS quarter_hour_rollups_v2 (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, target TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_dns_ms REAL NOT NULL, avg_connect_ms REAL NOT NULL, avg_tls_ms REAL NOT NULL,
  avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL, PRIMARY KEY(bucket, probe_type, target)
);
CREATE TABLE IF NOT EXISTS hourly_rollups_v2 (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, target TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_dns_ms REAL NOT NULL, avg_connect_ms REAL NOT NULL, avg_tls_ms REAL NOT NULL,
  avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL, PRIMARY KEY(bucket, probe_type, target)
);
CREATE TABLE IF NOT EXISTS daily_rollups_v2 (
  bucket TEXT NOT NULL, probe_type TEXT NOT NULL, target TEXT NOT NULL, samples INTEGER NOT NULL, successes INTEGER NOT NULL,
  warnings INTEGER NOT NULL, errors INTEGER NOT NULL, criticals INTEGER NOT NULL,
  avg_duration_ms REAL NOT NULL, avg_dns_ms REAL NOT NULL, avg_connect_ms REAL NOT NULL, avg_tls_ms REAL NOT NULL,
  avg_ttfb_ms REAL NOT NULL, avg_mbps REAL NOT NULL, PRIMARY KEY(bucket, probe_type, target)
);`)
	if err != nil {
		return err
	}
	if err := ensureColumn(db, "exports", "status", "TEXT NOT NULL DEFAULT 'complete'"); err != nil {
		return err
	}
	if err := ensureColumn(db, "exports", "error", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "incidents", "confidence", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "incidents", "contradictions", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "samples", "network_result", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "samples", "probe_control", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureColumn(db, "samples", "probe_stage", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS annotations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  note TEXT NOT NULL
)`); err != nil {
		return err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS modem_samples (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at TEXT NOT NULL,
  rssi REAL,
  rsrp REAL,
  rsrq REAL,
  sinr REAL,
  rscp REAL,
  ecio REAL,
  ca_count INTEGER NOT NULL DEFAULT 0,
  band TEXT NOT NULL DEFAULT '',
  ca_bands TEXT NOT NULL DEFAULT '',
  operator TEXT NOT NULL DEFAULT '',
  network_type TEXT NOT NULL DEFAULT '',
  cell_id TEXT NOT NULL DEFAULT '',
  message TEXT NOT NULL DEFAULT ''
); CREATE INDEX IF NOT EXISTS idx_modem_samples_created ON modem_samples(created_at DESC)`); err != nil {
		return err
	}
	if value, _ := setting(context.Background(), db, "fixed_timestamps_v1"); value != "done" {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, statement := range []string{
			`UPDATE samples SET created_at=strftime('%Y-%m-%dT%H:%M:%f',created_at)||'000000Z' WHERE length(created_at)<>30`,
			`UPDATE incidents SET started_at=strftime('%Y-%m-%dT%H:%M:%f',started_at)||'000000Z' WHERE length(started_at)<>30`,
			`UPDATE incidents SET ended_at=strftime('%Y-%m-%dT%H:%M:%f',ended_at)||'000000Z' WHERE ended_at IS NOT NULL AND length(ended_at)<>30`,
			`UPDATE exports SET created_at=strftime('%Y-%m-%dT%H:%M:%f',created_at)||'000000Z' WHERE length(created_at)<>30`,
			`INSERT INTO settings(key,value) VALUES ('fixed_timestamps_v1','done') ON CONFLICT(key) DO UPDATE SET value='done'`,
		} {
			if _, err := tx.Exec(statement); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO quarter_hour_rollups(bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps)
SELECT bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps FROM hourly_rollups`)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT OR IGNORE INTO quarter_hour_rollups(bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps)
SELECT d.bucket, d.probe_type, d.samples, d.successes, d.warnings, d.errors, d.criticals, d.avg_duration_ms, d.avg_ttfb_ms, d.avg_mbps
FROM daily_rollups d WHERE NOT EXISTS (
  SELECT 1 FROM quarter_hour_rollups q WHERE q.probe_type=d.probe_type AND substr(q.bucket,1,10)=substr(d.bucket,1,10)
)`)
	if err != nil {
		return err
	}
	for oldTable, newTable := range map[string]string{"quarter_hour_rollups": "quarter_hour_rollups_v2", "hourly_rollups": "hourly_rollups_v2", "daily_rollups": "daily_rollups_v2"} {
		query := fmt.Sprintf(`INSERT OR IGNORE INTO %s(bucket, probe_type, target, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms, avg_mbps)
SELECT CASE WHEN instr(bucket,'.')=0 THEN replace(bucket,'Z','.000000000Z') ELSE bucket END, probe_type, 'unknown', samples, successes, warnings, errors, criticals, avg_duration_ms, 0, 0, 0, avg_ttfb_ms, avg_mbps FROM %s`, newTable, oldTable)
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func ensureColumn(db *sql.DB, table, column, definition string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid int
		var name, dataType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return err
		}
		if name == column {
			found = true
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func applyPrivacyMigration(db *sql.DB, exportDir string) error {
	if value, err := setting(context.Background(), db, "privacy_scrub_v2"); err == nil && value == "done" {
		return nil
	}
	rows, err := db.Query(`SELECT id, target FROM samples WHERE probe_type IN ('http','transfer')`)
	if err != nil {
		return err
	}
	type targetRow struct {
		id     int64
		target string
	}
	var targets []targetRow
	for rows.Next() {
		var row targetRow
		if err := rows.Scan(&row.id, &row.target); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, row)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, row := range targets {
		redactedTarget := redactURL(row.target)
		redactedMessage := "Historical HTTP probe result (details redacted)"
		if _, err := db.Exec(`UPDATE samples SET target=?, message=? WHERE id=?`, redactedTarget, redactedMessage, row.id); err != nil {
			return err
		}
	}
	if _, err := db.Exec(`UPDATE incidents SET summary='Historical HTTP incident (details redacted)', evidence='' WHERE category IN ('slow_ttfb','tls_handshake','internet_connectivity','slow_transfer')`); err != nil {
		return err
	}
	exportRows, err := db.Query(`SELECT path FROM exports`)
	if err != nil {
		return err
	}
	var paths []string
	for exportRows.Next() {
		var path string
		if err := exportRows.Scan(&path); err != nil {
			exportRows.Close()
			return err
		}
		paths = append(paths, path)
	}
	if err := exportRows.Close(); err != nil {
		return err
	}
	cleanDir, err := filepath.Abs(exportDir)
	if err != nil {
		return err
	}
	for _, path := range paths {
		cleanPath, pathErr := filepath.Abs(path)
		if pathErr != nil || !strings.HasPrefix(cleanPath, cleanDir+string(os.PathSeparator)) {
			continue
		}
		if err := os.Remove(cleanPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if _, err := db.Exec(`DELETE FROM exports`); err != nil {
		return err
	}
	if err := setSetting(context.Background(), db, "privacy_scrub_v1", "done"); err != nil {
		return err
	}
	return setSetting(context.Background(), db, "privacy_scrub_v2", "done")
}

func insertSample(ctx context.Context, db *sql.DB, s Sample) error {
	_, err := db.ExecContext(ctx, `INSERT INTO samples
(created_at, probe_type, target, severity, success, duration_ms, dns_ms, connect_ms, tls_ms, ttfb_ms, bytes, mbps, status_code, message, network_result, probe_control, probe_stage)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, dbTime(s.CreatedAt), s.ProbeType,
		s.Target, s.Severity, s.Success, s.DurationMS, s.DNSMS, s.ConnectMS, s.TLSMS, s.TTFBMS, s.Bytes, s.Mbps, s.StatusCode, s.Message, s.NetworkResult, s.ProbeControl, s.ProbeStage)
	return err
}

func scanSample(rows interface{ Scan(...any) error }) (Sample, error) {
	var s Sample
	var created string
	err := rows.Scan(&s.ID, &created, &s.ProbeType, &s.Target, &s.Severity, &s.Success, &s.DurationMS,
		&s.DNSMS, &s.ConnectMS, &s.TLSMS, &s.TTFBMS, &s.Bytes, &s.Mbps, &s.StatusCode, &s.Message, &s.NetworkResult, &s.ProbeControl, &s.ProbeStage)
	if err != nil {
		return s, err
	}
	s.CreatedAt, err = parseDBTime(created)
	return s, err
}

const sampleColumns = `id, created_at, probe_type, target, severity, success, duration_ms, dns_ms, connect_ms, tls_ms, ttfb_ms, bytes, mbps, status_code, message, network_result, probe_control, probe_stage`

func recentDegradedSamples(ctx context.Context, db *sql.DB, since time.Time, limit int) ([]Sample, error) {
	return listSamples(ctx, db, `SELECT `+sampleColumns+` FROM samples WHERE created_at >= ? AND severity != 'info' ORDER BY created_at DESC LIMIT ?`, dbTime(since), limit)
}

func listSamples(ctx context.Context, db *sql.DB, query string, args ...any) ([]Sample, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Sample
	for rows.Next() {
		s, err := scanSample(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func latestSampleTime(ctx context.Context, db *sql.DB, probeType string) (time.Time, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT created_at FROM samples WHERE probe_type=? ORDER BY created_at DESC LIMIT 1`, probeType).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	return parseDBTime(value)
}

func latestSampleByTarget(ctx context.Context, db *sql.DB, target string) (*Sample, error) {
	sample, err := scanSample(db.QueryRowContext(ctx, `SELECT `+sampleColumns+` FROM samples WHERE target=? ORDER BY id DESC LIMIT 1`, target))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &sample, nil
}

func setting(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func setSetting(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

const incidentColumns = `id, started_at, ended_at, severity, category, summary, evidence, confidence, contradictions`

func activeIncident(ctx context.Context, db *sql.DB) (*Incident, error) {
	row := db.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE ended_at IS NULL ORDER BY CASE severity WHEN 'critical' THEN 3 WHEN 'error' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END DESC, id DESC LIMIT 1`)
	incident, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &incident, err
}

func activeIncidents(ctx context.Context, db *sql.DB) ([]Incident, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE ended_at IS NULL ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, incident)
	}
	return result, rows.Err()
}

func scanIncident(row interface{ Scan(...any) error }) (Incident, error) {
	var i Incident
	var started string
	var ended sql.NullString
	err := row.Scan(&i.ID, &started, &ended, &i.Severity, &i.Category, &i.Summary, &i.Evidence, &i.Confidence, &i.Contradictions)
	if err != nil {
		return i, err
	}
	i.StartedAt, err = parseDBTime(started)
	if err == nil && ended.Valid {
		t, parseErr := parseDBTime(ended.String)
		if parseErr != nil {
			return i, parseErr
		}
		i.EndedAt = &t
	}
	return i, err
}

func recentIncidents(ctx context.Context, db *sql.DB, since time.Time, limit int) ([]Incident, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE started_at >= ? ORDER BY started_at DESC LIMIT ?`, dbTime(since), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Incident
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, i)
	}
	return result, rows.Err()
}

func incidentPage(ctx context.Context, db *sql.DB, limit, offset int) ([]Incident, bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+incidentColumns+` FROM incidents ORDER BY started_at DESC LIMIT ? OFFSET ?`, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var result []Incident
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, false, err
		}
		result = append(result, i)
	}
	hasMore := len(result) > limit
	if hasMore {
		result = result[:limit]
	}
	return result, hasMore, rows.Err()
}

func openIncident(ctx context.Context, db *sql.DB, s Sample) error {
	return openIncidentWithPeak(ctx, db, s, s)
}

func openIncidentWithPeak(ctx context.Context, db *sql.DB, current, peak Sample) error {
	doc := evidenceFromSample(peak)
	if current.Severity != peak.Severity || current.Message != peak.Message || current.DurationMS != peak.DurationMS {
		doc.Events = append(doc.Events, incidentEvidence(current))
	}
	if current.diagnosis != nil {
		doc = mergeDiagnosis(doc, current.diagnosis)
	}
	evidence, _ := json.Marshal(doc)
	confidence, contradictions := "", ""
	if current.diagnosis != nil {
		confidence = current.diagnosis.Confidence
		contradictions = strings.Join(current.diagnosis.Contradictions, "\n")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO incidents(started_at, severity, category, summary, evidence, confidence, contradictions) VALUES (?, ?, ?, ?, ?, ?, ?)`, dbTime(time.Now()), peak.Severity, categoryFor(current), current.Message, string(evidence), confidence, contradictions)
	return err
}

func closeIncident(ctx context.Context, db *sql.DB, id int64) error {
	_, err := db.ExecContext(ctx, `UPDATE incidents SET ended_at=? WHERE id=? AND ended_at IS NULL`, dbTime(time.Now()), id)
	return err
}

func updateIncident(ctx context.Context, db *sql.DB, id int64, s Sample, peakSeverity Severity, promotePeak bool) error {
	var existing string
	if err := db.QueryRowContext(ctx, `SELECT evidence FROM incidents WHERE id=? AND ended_at IS NULL`, id).Scan(&existing); err != nil {
		return err
	}
	evidence := mergeIncidentEvidenceJSON(existing, s, promotePeak)
	confidence, contradictions := "", ""
	if s.diagnosis != nil {
		confidence = s.diagnosis.Confidence
		contradictions = strings.Join(s.diagnosis.Contradictions, "\n")
	}
	_, err := db.ExecContext(ctx, `UPDATE incidents SET severity=?, category=?, summary=?, evidence=?, confidence=?, contradictions=? WHERE id=? AND ended_at IS NULL`, peakSeverity, s.Target, s.Message, evidence, confidence, contradictions, id)
	return err
}

func mergeIncidentEvidence(existing, current string, promotePeak bool) string {
	combined := existing + "\n" + current
	if promotePeak {
		combined = current + "\n" + existing
	}
	runes := []rune(combined)
	if len(runes) <= 12000 {
		return combined
	}
	peak, history, _ := strings.Cut(combined, "\n")
	historyRunes := []rune(history)
	if len(historyRunes) > 10000 {
		historyRunes = historyRunes[len(historyRunes)-10000:]
	}
	return peak + "\n... older events truncated ...\n" + string(historyRunes)
}

func evidenceFromSample(s Sample) incidentEvidenceDoc {
	doc := incidentEvidenceDoc{Events: []string{incidentEvidence(s)}}
	return mergeDiagnosis(doc, s.diagnosis)
}

func mergeDiagnosis(doc incidentEvidenceDoc, d *Diagnosis) incidentEvidenceDoc {
	if d == nil {
		return doc
	}
	doc.Classification, doc.Confidence, doc.Evidence, doc.Contradictions = d.Classification, d.Confidence, d.Evidence, d.Contradictions
	return doc
}

func mergeIncidentEvidenceJSON(existing string, s Sample, promotePeak bool) string {
	doc := parseEvidenceDoc(existing)
	line := incidentEvidence(s)
	if promotePeak {
		doc.Events = append([]string{line}, doc.Events...)
	} else {
		doc.Events = append(doc.Events, line)
	}
	doc = mergeDiagnosis(doc, s.diagnosis)
	encoded, err := json.Marshal(truncateEvidenceDoc(doc))
	if err != nil {
		return mergeIncidentEvidence(existing, line, promotePeak)
	}
	return string(encoded)
}

func parseEvidenceDoc(raw string) incidentEvidenceDoc {
	var doc incidentEvidenceDoc
	if json.Unmarshal([]byte(raw), &doc) == nil && (len(doc.Events) > 0 || len(doc.Evidence) > 0 || doc.Classification != "") {
		return doc
	}
	if strings.TrimSpace(raw) == "" {
		return incidentEvidenceDoc{}
	}
	return incidentEvidenceDoc{Events: []string{raw}}
}

func truncateEvidenceDoc(doc incidentEvidenceDoc) incidentEvidenceDoc {
	encoded, _ := json.Marshal(doc)
	if len(encoded) <= 12000 {
		return doc
	}
	if len(doc.Events) > 8 {
		peak := doc.Events[0]
		doc.Events = append([]string{peak, "... older events truncated ..."}, doc.Events[len(doc.Events)-4:]...)
	}
	return doc
}

func incidentEvidence(s Sample) string {
	at := s.CreatedAt
	if at.IsZero() {
		at = time.Now()
	}
	evidence := fmt.Sprintf("%s event_severity=%s target=%s duration=%.0fms dns=%.0fms connect=%.0fms tls=%.0fms ttfb=%.0fms throughput=%.2fMbps message=%s", at.UTC().Format(time.RFC3339), s.Severity, s.Target, s.DurationMS, s.DNSMS, s.ConnectMS, s.TLSMS, s.TTFBMS, s.Mbps, s.Message)
	if s.incidentContext != "" {
		evidence += "\n" + s.incidentContext
	}
	return evidence
}

func samplesBetween(ctx context.Context, db *sql.DB, from, to time.Time, limit int) ([]Sample, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+sampleColumns+` FROM samples WHERE created_at>=? AND created_at<? ORDER BY created_at LIMIT ?`, dbTime(from), dbTime(to), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Sample
	for rows.Next() {
		s, err := scanSample(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, s)
	}
	return result, rows.Err()
}

func incidentByID(ctx context.Context, db *sql.DB, id int64) (*Incident, error) {
	incident, err := scanIncident(db.QueryRowContext(ctx, `SELECT `+incidentColumns+` FROM incidents WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &incident, nil
}

func insertAnnotation(ctx context.Context, db *sql.DB, note string) error {
	note = strings.TrimSpace(note)
	if note == "" {
		return errors.New("annotation note is required")
	}
	if len([]rune(note)) > 500 {
		return errors.New("annotation note is too long")
	}
	_, err := db.ExecContext(ctx, `INSERT INTO annotations(created_at, note) VALUES (?, ?)`, dbTime(time.Now()), note)
	return err
}

func listAnnotations(ctx context.Context, db *sql.DB, from, to time.Time, limit int) ([]Annotation, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, created_at, note FROM annotations WHERE created_at>=? AND created_at<? ORDER BY created_at DESC LIMIT ?`, dbTime(from), dbTime(to), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []Annotation
	for rows.Next() {
		var item Annotation
		var created string
		if err := rows.Scan(&item.ID, &created, &item.Note); err != nil {
			return nil, err
		}
		item.CreatedAt, _ = parseDBTime(created)
		result = append(result, item)
	}
	return result, rows.Err()
}

func recentAnnotations(ctx context.Context, db *sql.DB, limit int) ([]Annotation, error) {
	return listAnnotations(ctx, db, time.Unix(0, 0), time.Now().Add(time.Minute), limit)
}

func nullFloat(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

func scanNullFloat(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func insertModemSample(ctx context.Context, db *sql.DB, s ModemSample) error {
	_, err := db.ExecContext(ctx, `INSERT INTO modem_samples(created_at, rssi, rsrp, rsrq, sinr, rscp, ecio, ca_count, band, ca_bands, operator, network_type, cell_id, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		dbTime(s.CreatedAt), nullFloat(s.RSSI), nullFloat(s.RSRP), nullFloat(s.RSRQ), nullFloat(s.SINR), nullFloat(s.RSCP), nullFloat(s.EcIo),
		s.CACount, s.Band, s.CABands, s.Operator, s.NetworkType, s.CellID, s.Message)
	return err
}

func latestModemSample(ctx context.Context, db *sql.DB) (*ModemSample, error) {
	row := db.QueryRowContext(ctx, `SELECT id, created_at, rssi, rsrp, rsrq, sinr, rscp, ecio, ca_count, band, ca_bands, operator, network_type, cell_id, message FROM modem_samples ORDER BY id DESC LIMIT 1`)
	s, err := scanModemSample(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

type modemDayStats struct {
	Samples                                                                int
	MinRSRP, MaxRSRP, MinRSRQ, MaxRSRQ, MinSINR, MaxSINR, MinRSSI, MaxRSSI sql.NullFloat64
}

func modemStatsSince(ctx context.Context, db *sql.DB, since time.Time) (modemDayStats, error) {
	var s modemDayStats
	err := db.QueryRowContext(ctx, `SELECT COUNT(*), MIN(rsrp), MAX(rsrp), MIN(rsrq), MAX(rsrq), MIN(sinr), MAX(sinr), MIN(rssi), MAX(rssi)
FROM modem_samples WHERE created_at>=?`, dbTime(since)).Scan(&s.Samples, &s.MinRSRP, &s.MaxRSRP, &s.MinRSRQ, &s.MaxRSRQ, &s.MinSINR, &s.MaxSINR, &s.MinRSSI, &s.MaxRSSI)
	return s, err
}

type modemRow interface {
	Scan(dest ...any) error
}

func scanModemSample(row modemRow) (ModemSample, error) {
	var s ModemSample
	var created string
	var rssi, rsrp, rsrq, sinr, rscp, ecio sql.NullFloat64
	err := row.Scan(&s.ID, &created, &rssi, &rsrp, &rsrq, &sinr, &rscp, &ecio, &s.CACount, &s.Band, &s.CABands, &s.Operator, &s.NetworkType, &s.CellID, &s.Message)
	if err != nil {
		return ModemSample{}, err
	}
	s.CreatedAt, _ = parseDBTime(created)
	s.RSSI, s.RSRP, s.RSRQ, s.SINR, s.RSCP, s.EcIo = scanNullFloat(rssi), scanNullFloat(rsrp), scanNullFloat(rsrq), scanNullFloat(sinr), scanNullFloat(rscp), scanNullFloat(ecio)
	return s, nil
}

func clearRecordedData(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, table := range []string{
		"samples", "incidents", "modem_samples",
		"quarter_hour_rollups", "hourly_rollups", "daily_rollups",
		"quarter_hour_rollups_v2", "hourly_rollups_v2", "daily_rollups_v2",
	} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+table); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func cleanup(ctx context.Context, db *sql.DB, rawRetention time.Duration) error {
	cutoff := dbTime(time.Now().UTC().Truncate(15 * time.Minute).Add(-rawRetention))
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for table, bucket := range map[string]string{
		"quarter_hour_rollups_v2": "substr(created_at,1,14) || printf('%02d', (CAST(substr(created_at,15,2) AS INTEGER)/15)*15) || ':00.000000000Z'",
		"hourly_rollups_v2":       "substr(created_at,1,13) || ':00:00.000000000Z'",
		"daily_rollups_v2":        "substr(created_at,1,10) || 'T00:00:00.000000000Z'",
	} {
		query := fmt.Sprintf(`INSERT INTO %s(bucket, probe_type, target, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_dns_ms, avg_connect_ms, avg_tls_ms, avg_ttfb_ms, avg_mbps)
SELECT %s, probe_type, target, COUNT(*), SUM(success), SUM(severity='warning'), SUM(severity='error'), SUM(severity='critical'), AVG(duration_ms), AVG(dns_ms), AVG(connect_ms), AVG(tls_ms), AVG(ttfb_ms), AVG(mbps)
FROM samples WHERE created_at < ? AND probe_control NOT IN ('cancellation_timeout','internal_error') GROUP BY 1, 2, 3
ON CONFLICT(bucket, probe_type, target) DO UPDATE SET
samples=samples+excluded.samples, successes=successes+excluded.successes, warnings=warnings+excluded.warnings,
errors=errors+excluded.errors, criticals=criticals+excluded.criticals,
avg_duration_ms=((avg_duration_ms*samples)+(excluded.avg_duration_ms*excluded.samples))/(samples+excluded.samples),
avg_dns_ms=((avg_dns_ms*samples)+(excluded.avg_dns_ms*excluded.samples))/(samples+excluded.samples),
avg_connect_ms=((avg_connect_ms*samples)+(excluded.avg_connect_ms*excluded.samples))/(samples+excluded.samples),
avg_tls_ms=((avg_tls_ms*samples)+(excluded.avg_tls_ms*excluded.samples))/(samples+excluded.samples),
avg_ttfb_ms=((avg_ttfb_ms*samples)+(excluded.avg_ttfb_ms*excluded.samples))/(samples+excluded.samples),
avg_mbps=((avg_mbps*samples)+(excluded.avg_mbps*excluded.samples))/(samples+excluded.samples)`, table, bucket)
		if _, err := tx.ExecContext(ctx, query, cutoff); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM samples WHERE created_at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM modem_samples WHERE created_at < ?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}
