package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type App struct {
	cfg                Config
	db                 *sql.DB
	logger             *slog.Logger
	startedAt          time.Time
	sessions           *sessionStore
	probeMu            sync.Mutex
	assetMu            sync.Mutex
	incidentMu         sync.Mutex
	dataMu             sync.RWMutex
	healthMu           sync.RWMutex
	lastPersist        time.Time
	lastPersistErr     error
	lastTransfer       time.Time
	lastAssetProbe     time.Time
	nextCacheBustProbe time.Time
	criticalCycles     int
	incidentStates     map[string]*incidentState
	exportJobs         chan exportJob
	loginLimiter       *loginLimiter
	piholeAPI          *piHoleAPIClient
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
	if err := applyPrivacyMigration(db, cfg.ExportDir); err != nil {
		db.Close()
		return nil, err
	}
	lastTransfer, _ := latestSampleTime(context.Background(), db, "transfer")
	if lastTransfer.IsZero() {
		lastTransfer = time.Now()
	}
	lastPersist, _ := latestSampleTime(context.Background(), db, "aggregate")
	assetTargets, err := initializeAssetSettings(context.Background(), db, cfg.AssetTargets)
	if err != nil {
		db.Close()
		return nil, err
	}
	lastAssetProbe, _ := latestSampleTime(context.Background(), db, "asset")
	if lastAssetProbe.IsZero() {
		lastAssetProbe = time.Now().Add(-fixedAssetInterval)
	}
	lastCacheBustProbe := time.Time{}
	parsedTargets, _ := parseAssetTargets(assetTargets)
	for _, target := range parsedTargets {
		if !target.CacheBust {
			continue
		}
		if sample, sampleErr := latestSampleByTarget(context.Background(), db, assetSampleTarget(target)); sampleErr == nil && sample != nil && sample.CreatedAt.After(lastCacheBustProbe) {
			lastCacheBustProbe = sample.CreatedAt
		}
	}
	if lastCacheBustProbe.IsZero() {
		lastCacheBustProbe = time.Now().Add(-cacheBustInterval)
	}
	a := &App{
		cfg: cfg, db: db, logger: logger, startedAt: time.Now(), sessions: newSessionStore(), exportJobs: make(chan exportJob, 16), loginLimiter: newLoginLimiter(), lastTransfer: lastTransfer, lastAssetProbe: lastAssetProbe, nextCacheBustProbe: lastCacheBustProbe.Add(cacheBustInterval), lastPersist: lastPersist, incidentStates: make(map[string]*incidentState),
	}
	if cfg.PiHoleAPIURL != "" {
		a.piholeAPI = newPiHoleAPIClient(cfg.PiHoleAPIURL, cfg.PiHoleAPIPassword)
	}
	return a, nil
}

func initializeAssetSettings(ctx context.Context, db *sql.DB, configuredDefault string) (string, error) {
	value, err := setting(ctx, db, "asset_targets")
	existed := err == nil
	if errors.Is(err, sql.ErrNoRows) {
		value = configuredDefault
		if err := setSetting(ctx, db, "asset_targets", value); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	if _, err := setting(ctx, db, "asset_defaults_v2"); errors.Is(err, sql.ErrNoRows) {
		if existed && value == legacyDefaultAssetTargets {
			value = defaultAssetTargets
			if err := setSetting(ctx, db, "asset_targets", value); err != nil {
				return "", err
			}
		}
		if err := setSetting(ctx, db, "asset_defaults_v2", "1"); err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}
	return value, nil
}

func (a *App) Close() error { return a.db.Close() }

func (a *App) Start(ctx context.Context) {
	go a.scheduler(ctx)
	go a.assetScheduler(ctx)
	go a.maintenance(ctx)
	go a.exportWorker(ctx)
}

func (a *App) assetScheduler(ctx context.Context) {
	wait := time.Until(a.lastAssetProbe.Add(fixedAssetInterval))
	if wait < 0 {
		wait = 0
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	firstCycleAt := time.Now()
	ticker := time.NewTicker(fixedAssetInterval)
	defer ticker.Stop()
	a.runAssetProbeCycleAt(ctx, firstCycleAt)
	for {
		select {
		case <-ctx.Done():
			return
		case cycleAt := <-ticker.C:
			a.runAssetProbeCycleAt(ctx, cycleAt)
		}
	}
}

func (a *App) runAssetProbeCycle(ctx context.Context) {
	a.runAssetProbeCycleAt(ctx, time.Now())
}

func (a *App) runAssetProbeCycleAt(ctx context.Context, cycleAt time.Time) {
	a.assetMu.Lock()
	defer a.assetMu.Unlock()
	configured, err := setting(ctx, a.db, "asset_targets")
	if err != nil {
		a.logger.Error("asset probe configuration unavailable", "error", err)
		return
	}
	targets, err := parseAssetTargets(configured)
	if err != nil {
		a.logger.Error("asset probe configuration invalid", "error", err)
		return
	}
	cacheBustDue := !cycleAt.Before(a.nextCacheBustProbe)
	probes := make([]probeFunc, 0, len(targets))
	categories := make(map[string]string, len(targets))
	cacheBustIncluded := false
	for _, target := range targets {
		if target.CacheBust && !cacheBustDue {
			continue
		}
		target := target
		cacheBustIncluded = cacheBustIncluded || target.CacheBust
		categories[target.Name] = assetIncidentCategory(target)
		probes = append(probes, probeFunc{ProbeType: "asset", Target: assetSampleTarget(target), Run: func(probeCtx context.Context) Sample { return probeAsset(probeCtx, target, a.cfg.HTTPDNSAddr) }})
	}
	if cacheBustIncluded {
		a.nextCacheBustProbe = a.nextCacheBustProbe.Add(cacheBustInterval)
		if !a.nextCacheBustProbe.After(cycleAt) {
			a.nextCacheBustProbe = cycleAt.Add(cacheBustInterval)
		}
	}
	samples := runConcurrentProbes(ctx, assetProbeTimeout(), probes)
	if ctx.Err() != nil {
		return
	}
	issues := make([]Sample, 0, len(samples))
	observed := make(map[string]bool, len(samples))
	for _, sample := range samples {
		if err := insertSample(ctx, a.db, sample); err != nil {
			a.logger.Error("asset sample persistence failed", "error", err)
		}
		name := assetSampleName(sample.Target)
		category := categories[name]
		observed[category] = true
		if sample.Severity != Info {
			issue := incidentSample(sample, category)
			issue.Message = name + " asset path degraded: " + sample.Message
			issues = append(issues, issue)
		}
	}
	a.updateIncidents(ctx, issues, observed)
	a.lastAssetProbe = time.Now()
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
	rows, err := a.db.Query(`SELECT id, path FROM exports WHERE created_at < ?`, dbTime(cutoff))
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
	cleanDir, err := filepath.Abs(a.cfg.ExportDir)
	if err != nil {
		a.logger.Error("export cleanup path failed", "error", err)
		return
	}
	for _, item := range expired {
		cleanPath, pathErr := filepath.Abs(item.path)
		if pathErr != nil || !strings.HasPrefix(cleanPath, cleanDir+string(os.PathSeparator)) {
			a.logger.Error("export cleanup rejected path", "path", item.path)
			continue
		}
		if removeErr := os.Remove(cleanPath); removeErr != nil && !os.IsNotExist(removeErr) {
			a.logger.Error("export cleanup file failed", "path", cleanPath, "error", removeErr)
			continue
		}
		if _, deleteErr := a.db.Exec(`DELETE FROM exports WHERE id=?`, item.id); deleteErr != nil {
			a.logger.Error("export cleanup record failed", "id", item.id, "error", deleteErr)
		}
	}
}

type incidentState struct {
	badCycles, healthyCycles int
	peakIssue                Sample
}

func (a *App) runProbeCycle(ctx context.Context) {
	if !a.probeMu.TryLock() {
		return
	}
	defer a.probeMu.Unlock()

	probes := []probeFunc{
		{ProbeType: "dns", Target: "pihole", Run: func(probeCtx context.Context) Sample { return probeDNSTCP(probeCtx, "pihole", a.cfg.PiHoleAddr) }},
		{ProbeType: "dns", Target: "pihole-udp", Run: func(probeCtx context.Context) Sample { return probeDNS(probeCtx, "pihole-udp", a.cfg.PiHoleAddr) }},
		{ProbeType: "dns", Target: "public-dns", Run: func(probeCtx context.Context) Sample { return probeDNS(probeCtx, "public-dns", a.cfg.PublicDNS) }},
		{ProbeType: "doh", Target: "direct-doh", Run: func(probeCtx context.Context) Sample { return probeDoH(probeCtx, "direct-doh", a.cfg.DoHURL) }},
		{ProbeType: "tcp", Target: "internet-tcp", Run: func(probeCtx context.Context) Sample { return probeTCP(probeCtx, "internet-tcp", "1.1.1.1:443") }},
		{ProbeType: "http", Target: "http", Run: func(probeCtx context.Context) Sample {
			return probeHTTPStatusResolver(probeCtx, "http", a.cfg.HTTPURL, 512, a.cfg.HTTPExpectedStatus, a.cfg.HTTPDNSAddr)
		}},
	}
	samples := runConcurrentProbes(ctx, 10*time.Second, probes)
	if ctx.Err() != nil {
		return
	}
	profile, err := setting(ctx, a.db, "profile")
	if err != nil {
		profile = "low"
	}
	interval := profileTransferInterval(profile)
	if interval > 0 && time.Since(a.lastTransfer) >= interval {
		limit := profileTransferBytes(profile)
		transferCtx, cancel := context.WithTimeout(ctx, transferProbeTimeout(limit))
		samples = append(samples, probeHTTPStatusResolver(transferCtx, "transfer", transferURL(a.cfg.TransferURL, limit), limit, http.StatusOK, a.cfg.HTTPDNSAddr))
		cancel()
		a.lastTransfer = time.Now()
	}

	for _, sample := range samples {
		if err := insertSample(ctx, a.db, sample); err != nil {
			a.logger.Error("sample persistence failed", "error", err)
		}
	}
	aggregate, issues, observed := a.diagnoseSamples(samples)
	a.correlatePiHoleIncident(ctx, issues)
	if err := insertSample(ctx, a.db, aggregate); err != nil {
		a.logger.Error("aggregate persistence failed", "error", err)
		a.healthMu.Lock()
		a.lastPersistErr = err
		a.healthMu.Unlock()
	} else {
		a.healthMu.Lock()
		a.lastPersist, a.lastPersistErr = time.Now(), nil
		a.healthMu.Unlock()
	}
	a.updateIncidents(ctx, issues, observed)
}

func (a *App) correlatePiHoleIncident(ctx context.Context, issues []Sample) {
	if a.piholeAPI == nil {
		return
	}
	for index := range issues {
		if issues[index].Target != "local_dns" && issues[index].Target != "pihole_udp_path" && issues[index].Target != "pihole_tcp_path" {
			continue
		}
		probeTime := issues[index].dnsQueryAt
		if probeTime.IsZero() {
			probeTime = issues[index].CreatedAt
		}
		contextText, err := a.piholeAPI.correlate(ctx, probeTime, issues[index].dnsQueryName)
		if err != nil {
			a.logger.Warn("Pi-hole API correlation failed", "error", err)
		}
		issues[index].incidentContext = contextText
		return
	}
}

func (a *App) aggregateSample(samples []Sample) Sample {
	aggregate, _, _ := a.diagnoseSamples(samples)
	return aggregate
}

func (a *App) diagnoseSamples(samples []Sample) (Sample, []Sample, map[string]bool) {
	aggregate := Sample{CreatedAt: time.Now(), ProbeType: "aggregate", Target: "internet", Severity: Info, Success: true, Message: "healthy"}
	byTarget := make(map[string]Sample)
	var httpSample, transfer Sample
	hasHTTP, hasTransfer := false, false
	for _, sample := range samples {
		byTarget[sample.Target] = sample
		if sample.ProbeType == "http" {
			httpSample, hasHTTP = sample, true
		}
		if sample.ProbeType == "transfer" {
			transfer, hasTransfer = sample, true
		}
	}
	pihole, hasPiHole := byTarget["pihole"]
	piholeUDP, hasPiHoleUDP := byTarget["pihole-udp"]
	publicDNS, hasPublic := byTarget["public-dns"]
	doh, hasDoH := byTarget["direct-doh"]
	tcp, hasTCP := byTarget["internet-tcp"]
	var issues []Sample
	observed := map[string]bool{
		"local_dns": hasPiHole && hasPiHoleUDP, "external_dns": hasPiHole && hasPiHoleUDP && hasPublic && hasDoH,
		"pihole_udp_path": hasPiHoleUDP, "pihole_tcp_path": hasPiHole,
		"direct_udp_path": hasPublic && hasDoH, "direct_doh_path": hasPublic && hasDoH,
		"tcp_connect": hasTCP, "internet_outage": hasPiHole && hasPiHoleUDP && hasPublic && hasDoH && hasTCP,
		"slow_ttfb": hasHTTP, "tls_handshake": hasHTTP, "internet_connectivity": hasHTTP,
		"slow_transfer": hasTransfer,
	}
	if hasPiHole && hasPiHoleUDP && !pihole.Success && !piholeUDP.Success {
		category := "local_dns"
		if hasPublic && hasDoH && !publicDNS.Success && !doh.Success {
			category = "external_dns"
		}
		issues = append(issues, incidentSample(pihole, category))
	} else if hasPiHoleUDP && piholeUDP.Severity != Info {
		issue := incidentSample(piholeUDP, "pihole_udp_path")
		issue.Message = "Pi-hole UDP path degraded: " + piholeUDP.Message
		issues = append(issues, issue)
	}
	if hasPiHole && pihole.Severity != Info && !(hasPiHoleUDP && !pihole.Success && !piholeUDP.Success) {
		issue := incidentSample(pihole, "pihole_tcp_path")
		issue.Message = "Pi-hole TCP path degraded: " + pihole.Message
		issues = append(issues, issue)
	}
	if hasPublic && publicDNS.Severity != Info {
		issue := incidentSample(publicDNS, "direct_udp_path")
		issue.Message = "Direct UDP DNS path degraded: " + publicDNS.Message
		issues = append(issues, issue)
	}
	if hasDoH && doh.Severity != Info {
		issue := incidentSample(doh, "direct_doh_path")
		issue.Message = "Direct DoH path degraded: " + doh.Message
		issues = append(issues, issue)
	}
	if hasTCP && tcp.Severity != Info {
		issue := incidentSample(tcp, "tcp_connect")
		issue.Message += tcpControlContext(publicDNS, hasPublic, doh, hasDoH, httpSample, hasHTTP)
		issues = append(issues, issue)
	}
	if hasHTTP && httpSample.Severity != Info && (!hasPiHole || pihole.Success) && (!hasTCP || tcp.Success) {
		issues = append(issues, incidentSample(httpSample, categoryFor(httpSample)))
	}
	if hasTransfer && transfer.Severity != Info {
		issues = append(issues, incidentSample(transfer, "slow_transfer"))
	}
	outageEvidence := hasPiHole && hasPiHoleUDP && hasPublic && hasDoH && hasTCP && !pihole.Success && !piholeUDP.Success && !publicDNS.Success && !doh.Success && !tcp.Success
	if outageEvidence {
		a.criticalCycles++
	} else {
		a.criticalCycles = 0
	}
	if a.criticalCycles >= 2 {
		critical := incidentSample(tcp, "internet_outage")
		critical.Severity, critical.Message = Critical, "Pi-hole DNS, direct UDP DNS, DNS-over-HTTPS, and direct TCP failed for consecutive cycles"
		issues = append(issues, critical)
	}
	dnsAvailable := (!hasPiHoleUDP && (!hasPiHole || pihole.Success)) || (hasPiHoleUDP && piholeUDP.Success)
	available := dnsAvailable && (!hasTCP || tcp.Success) && (!hasHTTP || httpSample.Success)
	for _, issue := range issues {
		if severityRank(issue.Severity) > severityRank(aggregate.Severity) {
			aggregate = issue
		}
	}
	aggregate.CreatedAt, aggregate.ProbeType, aggregate.Success = time.Now(), "aggregate", available
	if len(issues) == 0 {
		aggregate.Target, aggregate.Message = "internet", "healthy"
	}
	return aggregate, issues, observed
}

func incidentSample(source Sample, category string) Sample {
	source.CreatedAt, source.ProbeType, source.Target = time.Now(), "aggregate", category
	return source
}

func (a *App) updateIncident(ctx context.Context, sample Sample) {
	if sample.Severity == Info {
		observed := make(map[string]bool)
		for category := range a.incidentStates {
			observed[category] = true
		}
		a.updateIncidents(ctx, nil, observed)
		return
	}
	a.updateIncidents(ctx, []Sample{sample}, map[string]bool{sample.Target: true})
}

func (a *App) updateIncidents(ctx context.Context, issues []Sample, observed map[string]bool) {
	a.incidentMu.Lock()
	defer a.incidentMu.Unlock()
	activeList, err := activeIncidents(ctx, a.db)
	if err != nil {
		a.logger.Error("incident lookup failed", "error", err)
		return
	}
	active := make(map[string]Incident)
	for _, incident := range activeList {
		active[incident.Category] = incident
		if a.incidentStates[incident.Category] == nil {
			a.incidentStates[incident.Category] = &incidentState{}
		}
	}
	current := make(map[string]Sample)
	for _, issue := range issues {
		current[issue.Target] = issue
		if a.incidentStates[issue.Target] == nil {
			a.incidentStates[issue.Target] = &incidentState{}
		}
	}
	for category, state := range a.incidentStates {
		issue, failing := current[category]
		incident, isActive := active[category]
		if !failing && !observed[category] {
			continue
		}
		if !failing {
			state.badCycles = 0
			state.peakIssue = Sample{}
			state.healthyCycles++
			healthyCyclesRequired := 3
			if strings.HasPrefix(category, "asset_cache_bust:") {
				healthyCyclesRequired = 1
			}
			if isActive && state.healthyCycles >= healthyCyclesRequired {
				if err := closeIncident(ctx, a.db, incident.ID); err != nil {
					a.logger.Error("incident close failed", "category", category, "error", err)
				}
			}
			continue
		}
		state.healthyCycles = 0
		state.badCycles++
		if !isActive {
			if state.badCycles == 1 || severityRank(issue.Severity) > severityRank(state.peakIssue.Severity) {
				if issue.incidentContext == "" {
					issue.incidentContext = state.peakIssue.incidentContext
				}
				state.peakIssue = issue
			}
			if state.badCycles >= 2 {
				if err := openIncidentWithPeak(ctx, a.db, issue, state.peakIssue); err != nil {
					a.logger.Error("incident creation failed", "category", category, "error", err)
				}
			}
			continue
		}
		peakSeverity := issue.Severity
		promotePeak := severityRank(issue.Severity) > severityRank(incident.Severity)
		if severityRank(incident.Severity) > severityRank(peakSeverity) {
			peakSeverity = incident.Severity
		}
		if err := updateIncident(ctx, a.db, incident.ID, issue, peakSeverity, promotePeak); err != nil {
			a.logger.Error("incident update failed", "category", category, "error", err)
		}
	}
}

func tcpControlContext(publicDNS Sample, hasPublic bool, doh Sample, hasDoH bool, httpSample Sample, hasHTTP bool) string {
	dnsState := controlState(publicDNS, hasPublic, publicDNS.DurationMS)
	dohState := controlState(doh, hasDoH, doh.DurationMS)
	httpState := httpConnectState(httpSample, hasHTTP)
	assessment := "insufficient healthy controls to isolate scope"
	httpConnectFailed := hasHTTP && httpSample.connectFailed
	httpConnectHealthy := hasHTTP && httpSample.ConnectMS > 0 && httpSample.ConnectMS <= 250 && !httpConnectFailed
	if httpConnectHealthy && ((hasPublic && publicDNS.Success) || (hasDoH && doh.Success)) {
		assessment = "likely Cloudflare TCP control-path degradation, not a broad outage"
	} else if httpConnectFailed || (hasHTTP && httpSample.ConnectMS > 250) {
		assessment = "multiple outbound TCP/HTTPS paths degraded; likely broader connectivity trouble"
	}
	return fmt.Sprintf(". Same-cycle controls: direct DNS=%s, DoH=%s, HTTP connect=%s. Assessment: %s", dnsState, dohState, httpState, assessment)
}

func httpConnectState(sample Sample, present bool) string {
	if !present || sample.ConnectMS <= 0 {
		return "unavailable"
	}
	if sample.connectFailed {
		return fmt.Sprintf("error (%.0fms)", sample.ConnectMS)
	}
	severity, _ := classifyLatency(sample.ConnectMS, "HTTP connection")
	state := string(severity)
	if severity == Info {
		state = "healthy"
	}
	return fmt.Sprintf("%s (%.0fms)", state, sample.ConnectMS)
}

func controlState(sample Sample, present bool, durationMS float64) string {
	if !present {
		return "unavailable"
	}
	state := string(sample.Severity)
	if sample.Success && sample.Severity == Info {
		state = "healthy"
	}
	return fmt.Sprintf("%s (%.0fms)", state, durationMS)
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

func transferProbeTimeout(bytes int64) time.Duration {
	duration := time.Duration(float64(bytes*8)/500_000*float64(time.Second)) + 10*time.Second
	if duration < 30*time.Second {
		return 30 * time.Second
	}
	return duration
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
