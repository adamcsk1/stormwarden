package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
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
  message TEXT NOT NULL DEFAULT ''
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
	return err
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

func insertSample(ctx context.Context, db *sql.DB, s Sample) error {
	_, err := db.ExecContext(ctx, `INSERT INTO samples
(created_at, probe_type, target, severity, success, duration_ms, dns_ms, connect_ms, tls_ms, ttfb_ms, bytes, mbps, status_code, message)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, s.CreatedAt.UTC().Format(time.RFC3339Nano), s.ProbeType,
		s.Target, s.Severity, s.Success, s.DurationMS, s.DNSMS, s.ConnectMS, s.TLSMS, s.TTFBMS, s.Bytes, s.Mbps, s.StatusCode, s.Message)
	return err
}

func scanSample(rows interface{ Scan(...any) error }) (Sample, error) {
	var s Sample
	var created string
	err := rows.Scan(&s.ID, &created, &s.ProbeType, &s.Target, &s.Severity, &s.Success, &s.DurationMS,
		&s.DNSMS, &s.ConnectMS, &s.TLSMS, &s.TTFBMS, &s.Bytes, &s.Mbps, &s.StatusCode, &s.Message)
	if err != nil {
		return s, err
	}
	s.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	return s, err
}

const sampleColumns = `id, created_at, probe_type, target, severity, success, duration_ms, dns_ms, connect_ms, tls_ms, ttfb_ms, bytes, mbps, status_code, message`

func recentSamples(ctx context.Context, db *sql.DB, since time.Time, limit int) ([]Sample, error) {
	rows, err := db.QueryContext(ctx, `SELECT `+sampleColumns+` FROM samples WHERE created_at >= ? ORDER BY created_at DESC LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
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

func setting(ctx context.Context, db *sql.DB, key string) (string, error) {
	var value string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&value)
	return value, err
}

func setSetting(ctx context.Context, db *sql.DB, key, value string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func activeIncident(ctx context.Context, db *sql.DB) (*Incident, error) {
	row := db.QueryRowContext(ctx, `SELECT id, started_at, ended_at, severity, category, summary, evidence FROM incidents WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1`)
	incident, err := scanIncident(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &incident, err
}

func scanIncident(row interface{ Scan(...any) error }) (Incident, error) {
	var i Incident
	var started string
	var ended sql.NullString
	err := row.Scan(&i.ID, &started, &ended, &i.Severity, &i.Category, &i.Summary, &i.Evidence)
	if err != nil {
		return i, err
	}
	i.StartedAt, err = time.Parse(time.RFC3339Nano, started)
	if err == nil && ended.Valid {
		t, parseErr := time.Parse(time.RFC3339Nano, ended.String)
		if parseErr != nil {
			return i, parseErr
		}
		i.EndedAt = &t
	}
	return i, err
}

func recentIncidents(ctx context.Context, db *sql.DB, since time.Time, limit int) ([]Incident, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, started_at, ended_at, severity, category, summary, evidence FROM incidents WHERE started_at >= ? ORDER BY started_at DESC LIMIT ?`, since.UTC().Format(time.RFC3339Nano), limit)
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
	rows, err := db.QueryContext(ctx, `SELECT id, started_at, ended_at, severity, category, summary, evidence FROM incidents ORDER BY started_at DESC LIMIT ? OFFSET ?`, limit+1, offset)
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
	category := categoryFor(s)
	summary := fmt.Sprintf("%s probe degraded: %s", s.ProbeType, s.Message)
	evidence := fmt.Sprintf("target=%s duration=%.0fms ttfb=%.0fms throughput=%.2fMbps", s.Target, s.DurationMS, s.TTFBMS, s.Mbps)
	_, err := db.ExecContext(ctx, `INSERT INTO incidents(started_at, severity, category, summary, evidence) VALUES (?, ?, ?, ?, ?)`, time.Now().UTC().Format(time.RFC3339Nano), s.Severity, category, summary, evidence)
	return err
}

func closeIncident(ctx context.Context, db *sql.DB, id int64) error {
	_, err := db.ExecContext(ctx, `UPDATE incidents SET ended_at=? WHERE id=? AND ended_at IS NULL`, time.Now().UTC().Format(time.RFC3339Nano), id)
	return err
}

func updateIncident(ctx context.Context, db *sql.DB, id int64, s Sample) error {
	evidence := fmt.Sprintf("\n%s target=%s severity=%s message=%s", time.Now().UTC().Format(time.RFC3339), s.Target, s.Severity, s.Message)
	_, err := db.ExecContext(ctx, `UPDATE incidents SET severity=?, category=?, summary=?, evidence=substr(evidence || ?, -12000) WHERE id=? AND ended_at IS NULL`, s.Severity, s.Target, s.Message, evidence, id)
	return err
}

func cleanup(ctx context.Context, db *sql.DB, rawRetention time.Duration) error {
	cutoff := time.Now().UTC().Truncate(15 * time.Minute).Add(-rawRetention).Format(time.RFC3339Nano)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for table, bucket := range map[string]string{
		"quarter_hour_rollups": "substr(created_at,1,14) || printf('%02d', (CAST(substr(created_at,15,2) AS INTEGER)/15)*15) || ':00Z'",
		"hourly_rollups":       "substr(created_at,1,13) || ':00:00Z'",
		"daily_rollups":        "substr(created_at,1,10) || 'T00:00:00Z'",
	} {
		query := fmt.Sprintf(`INSERT INTO %s(bucket, probe_type, samples, successes, warnings, errors, criticals, avg_duration_ms, avg_ttfb_ms, avg_mbps)
SELECT %s, probe_type, COUNT(*), SUM(success), SUM(severity='warning'), SUM(severity='error'), SUM(severity='critical'), AVG(duration_ms), AVG(ttfb_ms), AVG(mbps)
FROM samples WHERE created_at < ? GROUP BY 1, 2
ON CONFLICT(bucket, probe_type) DO UPDATE SET
samples=samples+excluded.samples, successes=successes+excluded.successes, warnings=warnings+excluded.warnings,
errors=errors+excluded.errors, criticals=criticals+excluded.criticals,
avg_duration_ms=((avg_duration_ms*samples)+(excluded.avg_duration_ms*excluded.samples))/(samples+excluded.samples),
avg_ttfb_ms=((avg_ttfb_ms*samples)+(excluded.avg_ttfb_ms*excluded.samples))/(samples+excluded.samples),
avg_mbps=((avg_mbps*samples)+(excluded.avg_mbps*excluded.samples))/(samples+excluded.samples)`, table, bucket)
		if _, err := tx.ExecContext(ctx, query, cutoff); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM samples WHERE created_at < ?`, cutoff); err != nil {
		return err
	}
	return tx.Commit()
}
