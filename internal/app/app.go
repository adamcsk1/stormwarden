package app

import (
	"context"
	"database/sql"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type App struct {
	cfg            Config
	db             *sql.DB
	logger         *slog.Logger
	startedAt      time.Time
	sessions       *sessionStore
	probeMu        sync.Mutex
	dataMu         sync.RWMutex
	lastTransfer   time.Time
	badCycles      int
	healthyCycles  int
	criticalCycles int
	exportJobs     chan exportJob
	loginLimiter   *loginLimiter
}

type probeFunc struct {
	ProbeType string
	Target    string
	Run       func(context.Context) Sample
}

type probeResult struct {
	index  int
	sample Sample
}

func runConcurrentProbes(ctx context.Context, timeout time.Duration, probes []probeFunc) []Sample {
	sampleChannel := make(chan probeResult, len(probes))
	for index, probe := range probes {
		go func() {
			probeCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			sampleChannel <- probeResult{index: index, sample: probe.Run(probeCtx)}
		}()
	}
	samples := make([]Sample, len(probes))
	received := make([]bool, len(probes))
	count := 0
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for count < len(probes) {
		select {
		case result := <-sampleChannel:
			if !received[result.index] {
				samples[result.index], received[result.index], count = result.sample, true, count+1
			}
		case <-ctx.Done():
			return nil
		case <-timer.C:
		drain:
			for {
				select {
				case result := <-sampleChannel:
					if !received[result.index] {
						samples[result.index], received[result.index], count = result.sample, true, count+1
					}
				default:
					break drain
				}
			}
			for index, probe := range probes {
				if !received[index] {
					samples[index] = Sample{CreatedAt: time.Now(), ProbeType: probe.ProbeType, Target: probe.Target, Severity: Error, Message: "probe did not stop before deadline"}
				}
			}
			return samples
		}
	}
	return samples
}

func New(cfg Config, logger *slog.Logger) (*App, error) {
	db, err := openDB(cfg.DataPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.ExportDir, 0o750); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`UPDATE exports SET status='failed', error='interrupted by application restart' WHERE status='pending'`); err != nil {
		db.Close()
		return nil, err
	}
	return &App{
		cfg: cfg, db: db, logger: logger, startedAt: time.Now(), sessions: newSessionStore(), exportJobs: make(chan exportJob, 16), loginLimiter: newLoginLimiter(),
	}, nil
}

func (a *App) Close() error { return a.db.Close() }

func (a *App) Start(ctx context.Context) {
	go a.scheduler(ctx)
	go a.maintenance(ctx)
	go a.exportWorker(ctx)
}

func (a *App) scheduler(ctx context.Context) {
	a.runProbeCycle(ctx)
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runProbeCycle(ctx)
		}
	}
}

func (a *App) maintenance(ctx context.Context) {
	a.runMaintenance(ctx)
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.runMaintenance(ctx)
		}
	}
}

func (a *App) runMaintenance(ctx context.Context) {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	if err := cleanup(ctx, a.db, 30*24*time.Hour); err != nil {
		a.logger.Error("retention cleanup failed", "error", err)
	}
	a.cleanupExports()
	a.sessions.cleanup()
}

func (a *App) cleanupExports() {
	cutoff := time.Now().Add(-7 * 24 * time.Hour)
	rows, err := a.db.Query(`SELECT id, path FROM exports WHERE created_at < ?`, cutoff.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return
	}
	type expiredExport struct{ id, path string }
	var expired []expiredExport
	for rows.Next() {
		var id, path string
		if rows.Scan(&id, &path) == nil {
			expired = append(expired, expiredExport{id, path})
		}
	}
	_ = rows.Close()
	for _, item := range expired {
		if filepath.Clean(item.path) != filepath.Clean(a.cfg.ExportDir) {
			_ = os.Remove(item.path)
		}
		_, _ = a.db.Exec(`DELETE FROM exports WHERE id=?`, item.id)
	}
}

func (a *App) runProbeCycle(ctx context.Context) {
	if !a.probeMu.TryLock() {
		return
	}
	defer a.probeMu.Unlock()

	probes := []probeFunc{
		{ProbeType: "dns", Target: "pihole", Run: func(probeCtx context.Context) Sample { return probeDNS(probeCtx, "pihole", a.cfg.PiHoleAddr) }},
		{ProbeType: "dns", Target: "public-dns", Run: func(probeCtx context.Context) Sample { return probeDNS(probeCtx, "public-dns", a.cfg.PublicDNS) }},
		{ProbeType: "tcp", Target: "internet-tcp", Run: func(probeCtx context.Context) Sample { return probeTCP(probeCtx, "internet-tcp", "1.1.1.1:443") }},
		{ProbeType: "http", Target: "http", Run: func(probeCtx context.Context) Sample {
			return probeHTTPStatus(probeCtx, "http", a.cfg.HTTPURL, 64*1024, a.cfg.HTTPExpectedStatus)
		}},
	}
	samples := runConcurrentProbes(ctx, 10*time.Second, probes)

	profile, err := setting(ctx, a.db, "profile")
	if err != nil {
		profile = "low"
	}
	interval := profileTransferInterval(profile)
	if interval > 0 && time.Since(a.lastTransfer) >= interval {
		limit := profileTransferBytes(profile)
		transferCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		samples = append(samples, probeHTTPStatus(transferCtx, "transfer", transferURL(a.cfg.TransferURL, limit), limit, http.StatusOK))
		cancel()
		a.lastTransfer = time.Now()
	}

	for _, sample := range samples {
		if err := insertSample(ctx, a.db, sample); err != nil {
			a.logger.Error("sample persistence failed", "error", err)
		}
	}
	aggregate := a.aggregateSample(samples)
	if err := insertSample(ctx, a.db, aggregate); err != nil {
		a.logger.Error("aggregate persistence failed", "error", err)
	}
	a.updateIncident(ctx, aggregate)
}

func (a *App) aggregateSample(samples []Sample) Sample {
	aggregate := Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true, Message: "healthy"}
	var worst Sample
	relevantFailures, relevantDegraded, independentFailures := 0, 0, 0
	for _, sample := range samples {
		if sample.ProbeType == "transfer" {
			continue
		}
		if !sample.Success {
			independentFailures++
		}
		relevant := sample.Target != "public-dns"
		if relevant && !sample.Success {
			relevantFailures++
		}
		if relevant && sample.Severity != Info {
			relevantDegraded++
		}
		if relevant && severityRank(sample.Severity) > severityRank(worst.Severity) {
			worst = sample
		}
	}
	if independentFailures >= 3 {
		a.criticalCycles++
	} else {
		a.criticalCycles = 0
	}
	if relevantDegraded == 0 {
		return aggregate
	}
	aggregate.Success = relevantFailures == 0
	aggregate.Severity, aggregate.Message, aggregate.Target = worst.Severity, worst.Message, categoryFor(worst)
	if a.criticalCycles >= 2 {
		aggregate.Severity, aggregate.Target, aggregate.Message = Critical, "internet_outage", "multiple independent probes failed for consecutive cycles"
	}
	return aggregate
}

func (a *App) updateIncident(ctx context.Context, worst Sample) {
	active, err := activeIncident(ctx, a.db)
	if err != nil {
		a.logger.Error("incident lookup failed", "error", err)
		return
	}
	if worst.Severity == Info {
		a.badCycles = 0
		a.healthyCycles++
		if active != nil {
			if a.healthyCycles >= 3 {
				_ = closeIncident(ctx, a.db, active.ID)
			}
		}
		return
	}
	a.healthyCycles = 0
	a.badCycles++
	if active == nil {
		if a.badCycles < 2 {
			return
		}
		if err := openIncident(ctx, a.db, worst); err != nil {
			a.logger.Error("incident creation failed", "error", err)
		}
		return
	}
	if severityRank(active.Severity) > severityRank(worst.Severity) {
		worst.Severity = active.Severity
	}
	_ = updateIncident(ctx, a.db, active.ID, worst)
}

func severityRank(s Severity) int {
	switch s {
	case Warning:
		return 1
	case Error:
		return 2
	case Critical:
		return 3
	default:
		return 0
	}
}

func profileTransferInterval(profile string) time.Duration {
	switch profile {
	case "low", "detailed":
		return 15 * time.Minute
	default:
		return 0
	}
}

func profileTransferBytes(profile string) int64 {
	if profile == "detailed" {
		return 5 * 1024 * 1024
	}
	return 256 * 1024
}

func categoryFor(s Sample) string {
	if s.ProbeType == "aggregate" && s.Target != "" {
		return s.Target
	}
	if s.ProbeType == "dns" && s.Target == "pihole" {
		return "local_dns"
	}
	if s.ProbeType == "dns" {
		return "external_dns"
	}
	if s.ProbeType == "tcp" {
		return "tcp_connect"
	}
	if s.TLSMS > 1500 {
		return "tls_handshake"
	}
	if s.TTFBMS > 1000 {
		return "slow_ttfb"
	}
	if s.ProbeType == "transfer" {
		return "slow_transfer"
	}
	return "internet_connectivity"
}

func (a *App) Handler() http.Handler { return a.routes() }
