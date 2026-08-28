package app

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"sort"
	"time"
)

type Baseline struct {
	TCPMedian, TCPP95     float64
	DNSMedian             float64
	GatewayRTT            float64
	PiholeRTT             float64
	PublicRTT             float64
	TLSMedian, TTFBMedian float64
	ComputedAt            time.Time
}

func (b *Baseline) note(e extracted) string {
	if b == nil || b.TCPMedian <= 0 {
		return ""
	}
	worst := 0.0
	for _, t := range e.tcp {
		if t.ConnectMS > worst {
			worst = t.ConnectMS
		}
	}
	if worst <= 0 {
		return ""
	}
	return fmt.Sprintf("TCP connect = %.0f ms, normal median = %.0f ms.", worst, b.TCPMedian)
}

func (a *App) currentBaseline(ctx context.Context) *Baseline {
	a.baseMu.Lock()
	defer a.baseMu.Unlock()
	if a.baseline != nil && time.Since(a.baseline.ComputedAt) < 15*time.Minute {
		return a.baseline
	}
	b, err := loadBaseline(ctx, a.db)
	if err != nil {
		return a.baseline
	}
	a.baseline = b
	return b
}

func loadBaseline(ctx context.Context, db *sql.DB) (*Baseline, error) {
	since := dbTime(time.Now().Add(-24 * time.Hour))
	b := &Baseline{ComputedAt: time.Now()}
	tcp, err := columnValues(ctx, db, `SELECT connect_ms FROM samples WHERE probe_type='tcp' AND success=1 AND severity='info' AND created_at>=? AND connect_ms>0`, since)
	if err != nil {
		return nil, err
	}
	b.TCPMedian, b.TCPP95 = median(tcp), percentile(tcp, 95)
	dns, err := columnValues(ctx, db, `SELECT duration_ms FROM samples WHERE probe_type IN ('dns','doh') AND success=1 AND severity='info' AND created_at>=? AND duration_ms>0`, since)
	if err != nil {
		return nil, err
	}
	b.DNSMedian = median(dns)
	return b, nil
}

func columnValues(ctx context.Context, db *sql.DB, query string, args ...any) ([]float64, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var values []float64
	for rows.Next() {
		var v float64
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		values = append(values, v)
	}
	return values, rows.Err()
}

func median(values []float64) float64 { return percentile(values, 50) }

func percentile(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	if p <= 0 {
		return sorted[0]
	}
	if p >= 100 {
		return sorted[len(sorted)-1]
	}
	idx := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func mad(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	m := median(values)
	dev := make([]float64, len(values))
	for i, v := range values {
		dev[i] = math.Abs(v - m)
	}
	return median(dev)
}

type coverageInfo struct {
	RequestedFrom, RequestedTo time.Time
	FirstSample, LastSample    time.Time
	Expected, Actual           int
	Percent                    float64
	Gaps                       []string
	Uptime                     string
}

func computeCoverage(ctx context.Context, db *sql.DB, from, to, started time.Time) coverageInfo {
	info := coverageInfo{RequestedFrom: from, RequestedTo: to, Uptime: time.Since(started).Round(time.Second).String()}
	var first, last string
	_ = db.QueryRowContext(ctx, `SELECT MIN(created_at), MAX(created_at), COUNT(*) FROM samples WHERE probe_type='aggregate' AND created_at>=? AND created_at<?`, dbTime(from), dbTime(to)).Scan(&first, &last, &info.Actual)
	info.FirstSample, _ = parseDBTime(first)
	info.LastSample, _ = parseDBTime(last)
	availableFrom, availableTo := from, to
	if !info.FirstSample.IsZero() && info.FirstSample.After(availableFrom) {
		availableFrom = info.FirstSample
	}
	if !info.LastSample.IsZero() && info.LastSample.Before(availableTo) {
		availableTo = info.LastSample
	}
	span := availableTo.Sub(availableFrom)
	if span < 0 {
		span = 0
	}
	info.Expected = int(span / (15 * time.Second))
	if info.Expected > 0 {
		info.Percent = float64(info.Actual) * 100 / float64(info.Expected)
		if info.Percent > 100 {
			info.Percent = 100
		}
	}
	info.Gaps = monitoringGaps(ctx, db, availableFrom, availableTo)
	return info
}

func monitoringGaps(ctx context.Context, db *sql.DB, from, to time.Time) []string {
	rows, err := db.QueryContext(ctx, `SELECT created_at FROM samples WHERE probe_type='aggregate' AND created_at>=? AND created_at<? ORDER BY created_at`, dbTime(from), dbTime(to))
	if err != nil {
		return nil
	}
	defer rows.Close()
	var prev time.Time
	var gaps []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return gaps
		}
		at, err := parseDBTime(raw)
		if err != nil {
			continue
		}
		if !prev.IsZero() && at.Sub(prev) > 2*time.Minute {
			gaps = append(gaps, fmt.Sprintf("%s to %s (%.0f min)", prev.UTC().Format(time.RFC3339), at.UTC().Format(time.RFC3339), at.Sub(prev).Minutes()))
			if len(gaps) >= 12 {
				break
			}
		}
		prev = at
	}
	return gaps
}

type dayCount struct {
	Day   string
	Count int
}

func dailyAnomalyCounts(ctx context.Context, db *sql.DB, from, to time.Time, loc *time.Location) []dayCount {
	rows, err := db.QueryContext(ctx, `SELECT started_at FROM incidents WHERE started_at>=? AND started_at<? AND category IN ('tcp_connect','tcp_connect_establishment','wan_or_isp_packet_loss','destination_or_route_specific','internet_outage')`, dbTime(from), dbTime(to))
	if err != nil {
		return nil
	}
	defer rows.Close()
	counts := map[string]int{}
	var days []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil
		}
		at, err := parseDBTime(raw)
		if err != nil {
			continue
		}
		day := at.In(loc).Format("2006-01-02")
		if counts[day] == 0 {
			days = append(days, day)
		}
		counts[day]++
	}
	sort.Strings(days)
	out := make([]dayCount, 0, len(days))
	for _, day := range days {
		out = append(out, dayCount{Day: day, Count: counts[day]})
	}
	return out
}

func rateShift(current, previous []float64) string {
	if len(current) == 0 || len(previous) == 0 {
		return ""
	}
	c, p := median(current), median(previous)
	if p <= 0 {
		return ""
	}
	spread := mad(previous)
	if spread < 1 {
		spread = 1
	}
	if math.Abs(c-p) < 3*spread {
		return ""
	}
	return fmt.Sprintf("TCP connectivity anomaly rate changed from %.0f/day to %.0f/day versus the previous period.", p, c)
}

type compareStats struct {
	Label                     string
	Anomalies                 int
	TCPMedian, TCPP95, TCPP99 float64
	DNSFailPct                float64
	HTTPConnectFailPct        float64
	ClassCounts               map[string]int
}

func periodStats(ctx context.Context, db *sql.DB, from, to time.Time) compareStats {
	s := compareStats{ClassCounts: map[string]int{}}
	tcp, _ := columnValues(ctx, db, `SELECT connect_ms FROM samples WHERE probe_type='tcp' AND created_at>=? AND created_at<? AND connect_ms>0`, dbTime(from), dbTime(to))
	s.TCPMedian, s.TCPP95, s.TCPP99 = median(tcp), percentile(tcp, 95), percentile(tcp, 99)
	var dnsN, dnsFail, httpN, httpFail int
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(success=0),0) FROM samples WHERE probe_type='dns' AND created_at>=? AND created_at<?`, dbTime(from), dbTime(to)).Scan(&dnsN, &dnsFail)
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(success=0 OR connect_ms>250),0) FROM samples WHERE probe_type='http' AND created_at>=? AND created_at<?`, dbTime(from), dbTime(to)).Scan(&httpN, &httpFail)
	if dnsN > 0 {
		s.DNSFailPct = float64(dnsFail) * 100 / float64(dnsN)
	}
	if httpN > 0 {
		s.HTTPConnectFailPct = float64(httpFail) * 100 / float64(httpN)
	}
	_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE started_at>=? AND started_at<?`, dbTime(from), dbTime(to)).Scan(&s.Anomalies)
	rows, err := db.QueryContext(ctx, `SELECT category, COUNT(*) FROM incidents WHERE started_at>=? AND started_at<? GROUP BY category`, dbTime(from), dbTime(to))
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var cat string
			var n int
			if err := rows.Scan(&cat, &n); err == nil {
				s.ClassCounts[cat] = n
			}
		}
	}
	return s
}
