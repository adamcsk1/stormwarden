package app

import (
	"context"
	"database/sql"
	"errors"
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
	piholeHealthMu     sync.RWMutex
	piholeHealth       piHoleHealthStatus
	piholeCheck        *piHoleHealthCheck
	burst              *burstLimiter
	traceLimit         *burstLimiter
	ping               pingFn
	trace              traceFn
	netMu              sync.RWMutex
	netInfo            NetInfo
	ispHop             string
	baseMu             sync.Mutex
	baseline           *Baseline
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
	if cfg.BurstCooldown <= 0 {
		cfg.BurstCooldown = 2 * time.Minute
	}
	if cfg.BurstTimeout <= 0 {
		cfg.BurstTimeout = 8 * time.Second
	}
	if cfg.BurstCount <= 0 {
		cfg.BurstCount = 10
	}
	if cfg.BurstInterval <= 0 {
		cfg.BurstInterval = 150 * time.Millisecond
	}
	if cfg.TracerouteCooldown <= 0 {
		cfg.TracerouteCooldown = 10 * time.Minute
	}
	if cfg.TracerouteMaxHops <= 0 {
		cfg.TracerouteMaxHops = 15
	}
	a := &App{
		cfg: cfg, db: db, logger: logger, startedAt: time.Now(), sessions: newSessionStore(), exportJobs: make(chan exportJob, 16), loginLimiter: newLoginLimiter(), lastTransfer: lastTransfer, lastAssetProbe: lastAssetProbe, nextCacheBustProbe: lastCacheBustProbe.Add(cacheBustInterval), lastPersist: lastPersist, incidentStates: make(map[string]*incidentState),
		burst: newBurstLimiter(cfg.BurstCooldown), traceLimit: newBurstLimiter(cfg.TracerouteCooldown),
	}
	a.refreshNetInfo()
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

func (a *App) Annotate(note string) error {
	return insertAnnotation(context.Background(), a.db, note)
}

func (a *App) clearRecordedData(ctx context.Context) error {
	a.dataMu.Lock()
	defer a.dataMu.Unlock()
	a.incidentMu.Lock()
	defer a.incidentMu.Unlock()
	if err := clearRecordedData(ctx, a.db); err != nil {
		return err
	}
	a.incidentStates = make(map[string]*incidentState)
	a.criticalCycles = 0
	a.baseMu.Lock()
	a.baseline = nil
	a.baseMu.Unlock()
	return nil
}

func (a *App) Start(ctx context.Context) {
	go a.scheduler(ctx)
	go a.assetScheduler(ctx)
	go a.maintenance(ctx)
	go a.exportWorker(ctx)
	go a.discoverLoop(ctx)
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
		{ProbeType: "http", Target: "http", Run: func(probeCtx context.Context) Sample {
			return probeHTTPStatusResolver(probeCtx, "http", a.cfg.HTTPURL, 512, a.cfg.HTTPExpectedStatus, a.cfg.HTTPDNSAddr)
		}},
	}
	for _, control := range a.cfg.tcpControls() {
		control := control
		probes = append(probes, probeFunc{ProbeType: "tcp", Target: tcpSampleTarget(control.Name), Run: func(probeCtx context.Context) Sample {
			return probeTCP(probeCtx, tcpSampleTarget(control.Name), control.Address)
		}})
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

	if extra := a.maybeBurst(ctx, samples); len(extra) > 0 {
		samples = append(samples, extra...)
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
	var tcpSamples []Sample
	for _, sample := range samples {
		if sample.ProbeType == "tcp" {
			tcpSamples = append(tcpSamples, sample)
		}
	}
	hasTCP := len(tcpSamples) > 0
	tcp, anyTCPSuccess, allTCPFailed := worstTCP(tcpSamples)
	diagnosis := classify(Snapshot{Samples: samples, Baseline: a.currentBaseline(context.Background())})
	var issues []Sample
	observed := map[string]bool{
		"local_dns": hasPiHole && hasPiHoleUDP, "external_dns": hasPiHole && hasPiHoleUDP && hasPublic && hasDoH,
		"pihole_udp_path": hasPiHoleUDP, "pihole_tcp_path": hasPiHole,
		"direct_udp_path": hasPublic && hasDoH, "direct_doh_path": hasPublic && hasDoH,
		"tcp_connect": hasTCP, "internet_outage": hasPiHole && hasPiHoleUDP && hasPublic && hasDoH && hasTCP,
		"slow_ttfb": hasHTTP, "tls_handshake": hasHTTP, "internet_connectivity": hasHTTP,
		"slow_transfer":          hasTransfer,
		"wan_or_isp_packet_loss": hasTCP, "destination_or_route_specific": hasTCP,
		"tcp_connect_establishment": hasTCP, "tls_or_remote_service": hasHTTP,
		"http_or_server": hasHTTP, "dns_resolution_failure": hasPublic || hasDoH,
		"local_network_or_host": true, "host_or_nic": true, "gateway_or_router": true, "unknown": true,
	}
	if diagnosis.Classification != "" {
		observed[diagnosis.Classification] = true
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
		category := diagnosis.Classification
		if category == "" || category == "unknown" || category == "local_dns" || category == "dns_resolution_failure" {
			category = "tcp_connect"
		}
		issue := incidentSample(tcp, category)
		issue.Message = diagnosis.Summary
		if issue.Message == "" {
			issue.Message = tcp.Message
		}
		issue.Severity = diagnosis.Severity
		if severityRank(tcp.Severity) > severityRank(issue.Severity) {
			issue.Severity = tcp.Severity
		}
		issue.diagnosis = &diagnosis
		issues = append(issues, issue)
	}
	if hasHTTP && httpSample.Severity != Info && (!hasPiHole || pihole.Success) && (!hasTCP || anyTCPSuccess) {
		category := categoryFor(httpSample)
		if diagnosis.Classification == "tls_or_remote_service" || diagnosis.Classification == "http_or_server" {
			category = diagnosis.Classification
		}
		issue := incidentSample(httpSample, category)
		issue.diagnosis = &diagnosis
		issues = append(issues, issue)
	}
	if hasTransfer && transfer.Severity != Info {
		issues = append(issues, incidentSample(transfer, "slow_transfer"))
	}
	outageEvidence := hasPiHole && hasPiHoleUDP && hasPublic && hasDoH && hasTCP && !pihole.Success && !piholeUDP.Success && !publicDNS.Success && !doh.Success && allTCPFailed
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
	available := dnsAvailable && (!hasTCP || anyTCPSuccess) && (!hasHTTP || httpSample.Success)
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

func worstTCP(samples []Sample) (Sample, bool, bool) {
	if len(samples) == 0 {
		return Sample{}, false, false
	}
	worst := samples[0]
	anyOK, allFailed := false, true
	for _, sample := range samples {
		if sample.Success {
			anyOK, allFailed = true, false
		}
		if severityRank(sample.Severity) > severityRank(worst.Severity) {
			worst = sample
		}
	}
	return worst, anyOK, allFailed
}

func (a *App) discoverLoop(ctx context.Context) {
	a.discoverISPHop(ctx)
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.refreshNetInfo()
			a.discoverISPHop(ctx)
		}
	}
}

func (a *App) discoverISPHop(ctx context.Context) {
	if a.cfg.ISPHopAddr != "" || !a.cfg.ISPHopAuto || !a.cfg.TracerouteEnabled {
		return
	}
	trace := a.trace
	if trace == nil {
		trace = execTrace
	}
	addr := a.cfg.PingInternetAddr
	if addr == "" {
		addr = "1.1.1.1"
	}
	traceCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	sample := trace(traceCtx, addr, min(a.cfg.TracerouteMaxHops, 8))
	hops := parseTrace(strings.ReplaceAll(sample.Message, " | ", "\n"))
	if len(hops) == 0 {
		var rebuilt []traceHop
		for i, part := range strings.Split(sample.Message, " | ") {
			fields := strings.Fields(part)
			if len(fields) >= 2 {
				rebuilt = append(rebuilt, traceHop{N: i + 1, Addr: fields[len(fields)-1]})
			}
		}
		hops = rebuilt
	}
	a.netMu.RLock()
	gw := a.netInfo.LANGateway
	a.netMu.RUnlock()
	if hop := pickISPHop(hops, gw); hop != "" {
		a.ispHop = hop
		a.refreshNetInfo()
	}
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
