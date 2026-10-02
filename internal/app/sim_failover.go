package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	simPrimarySetting       = "teltonika_primary_sim"
	simCooldownSetting      = "teltonika_sim_cooldown_hours"
	simStateSetting         = "teltonika_sim_failover_state"
	simDefaultCooldown      = 2 * time.Hour
	simMaxCooldown          = 168 * time.Hour
	simRetryCooldownCap     = 24 * time.Hour
	simSwitchTimeout        = 5 * time.Minute
	simStatusPollInterval   = 15 * time.Second
	simTransitionPoll       = 5 * time.Second
	simSmokeCycleInterval   = 15 * time.Second
	simConsecutiveWANCycles = 2
)

const (
	simModeNormal    = "normal"
	simModeBackup    = "backup"
	simModeSwitching = "switching"
	simModeFailed    = "failed"
)

const (
	simPurposeAutoBackup    = "auto-backup"
	simPurposeManualBackup  = "manual-backup"
	simPurposeAutoPrimary   = "auto-primary"
	simPurposeManualPrimary = "manual-primary"
	simPurposeRetryBackup   = "retry-backup"
)

type simFailoverState struct {
	Mode       string        `json:"mode"`
	PrimarySIM string        `json:"primary_sim"`
	TargetSIM  string        `json:"target_sim,omitempty"`
	Purpose    string        `json:"purpose,omitempty"`
	ReturnAt   time.Time     `json:"return_at,omitempty"`
	RetryDelay time.Duration `json:"retry_delay,omitempty"`
	RetryCount int           `json:"retry_count,omitempty"`
	Message    string        `json:"message,omitempty"`
}

type simFailoverView struct {
	Configured           bool
	Enabled              bool
	CSRF                 string
	PrimarySIM           string
	ActiveSIM            string
	DataConnState        string
	Mode                 string
	ModeLabel            string
	Message              string
	NextTestAt           time.Time
	HasNextTest          bool
	CooldownHours        int
	Stabilization        string
	Switching            bool
	CanSwitchToSecondary bool
	CanSwitchToPrimary   bool
}

func (a *App) loadSIMFailoverState(ctx context.Context) error {
	a.simMu.Lock()
	defer a.simMu.Unlock()
	a.simState = simFailoverState{Mode: simModeNormal, RetryDelay: simDefaultCooldown}
	raw, err := setting(ctx, a.db, simStateSetting)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var saved simFailoverState
	if err := json.Unmarshal([]byte(raw), &saved); err != nil || !validSIMState(saved) {
		return errors.New("invalid persisted SIM failover state")
	}
	a.simState = saved
	return nil
}

func validSIMState(state simFailoverState) bool {
	if state.PrimarySIM != "unset" && state.PrimarySIM != "1" && state.PrimarySIM != "2" {
		return false
	}
	switch state.Mode {
	case simModeNormal, simModeFailed:
		return true
	case simModeBackup:
		return otherSIM(state.PrimarySIM) != "" && !state.ReturnAt.IsZero() && state.RetryDelay > 0
	case simModeSwitching:
		switch state.Purpose {
		case simPurposeAutoPrimary, simPurposeManualPrimary:
			return state.TargetSIM == state.PrimarySIM && otherSIM(state.PrimarySIM) != ""
		case simPurposeAutoBackup, simPurposeManualBackup, simPurposeRetryBackup:
			return state.TargetSIM == otherSIM(state.PrimarySIM) && state.TargetSIM != ""
		}
		return false
	default:
		return false
	}
}

func (a *App) simSettings(ctx context.Context) (string, time.Duration, error) {
	primary, err := setting(ctx, a.db, simPrimarySetting)
	if errors.Is(err, sql.ErrNoRows) {
		primary, err = "unset", nil
	}
	if err != nil {
		return "", 0, err
	}
	primary = strings.ToLower(strings.TrimSpace(primary))
	if primary == "" {
		primary = "unset"
	}
	if primary != "unset" && primary != "1" && primary != "2" {
		return "", 0, errors.New("primary SIM must be Unset, SIM1, or SIM2")
	}
	hours := int(simDefaultCooldown / time.Hour)
	if raw, readErr := setting(ctx, a.db, simCooldownSetting); readErr == nil {
		hours, err = strconv.Atoi(raw)
		if err != nil || hours < 1 || hours > int(simMaxCooldown/time.Hour) {
			return "", 0, errors.New("SIM cooldown must be 1-168 hours")
		}
	} else if !errors.Is(readErr, sql.ErrNoRows) {
		return "", 0, readErr
	}
	return primary, time.Duration(hours) * time.Hour, nil
}

func (a *App) saveSIMFailoverStateLocked() error {
	raw, err := json.Marshal(a.simState)
	if err != nil {
		return err
	}
	return setSetting(context.Background(), a.db, simStateSetting, string(raw))
}

func (a *App) simFailoverLoop(ctx context.Context) {
	a.simFailoverTick(ctx)
	ticker := time.NewTicker(simStatusPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.simFailoverTick(ctx)
		}
	}
}

func (a *App) simFailoverTick(ctx context.Context) {
	if a.teltonika == nil {
		return
	}
	statusCtx, cancel := context.WithTimeout(ctx, teltonikaHTTPTimeout+time.Second)
	status, err := a.teltonika.status(statusCtx)
	cancel()
	a.simMu.Lock()
	if err != nil {
		a.simStatus = teltonikaSIMStatus{DataConnState: "status unavailable: " + redactSMTPErr(err, a.cfg.TeltonikaPassword)}
	} else {
		a.simStatus = status
	}
	a.simMu.Unlock()

	a.simMu.Lock()
	primary, cooldown, err := a.simSettings(ctx)
	if err != nil {
		a.simMu.Unlock()
		a.logger.Error("SIM failover settings unavailable", "error", err)
		return
	}

	if a.simState.PrimarySIM != primary {
		a.simState = simFailoverState{Mode: simModeNormal, PrimarySIM: primary, RetryDelay: cooldown}
		a.simBadCycles = 0
		if err := a.saveSIMFailoverStateLocked(); err != nil {
			a.logger.Error("SIM failover state reset failed", "error", err)
		}
	}
	if primary == "unset" && a.simState.Mode != simModeNormal {
		a.simState = simFailoverState{Mode: simModeNormal, PrimarySIM: "unset", RetryDelay: cooldown, Message: "SIM switching disabled: primary SIM is Unset."}
		a.simBadCycles = 0
		if err := a.saveSIMFailoverStateLocked(); err != nil {
			a.logger.Error("SIM failover disable failed", "error", err)
		}
	}
	state, switching := a.simState, a.simTransition
	a.simMu.Unlock()

	if primary == "unset" {
		return
	}
	if switching {
		return
	}
	if state.Mode == simModeSwitching {
		a.resumeSIMTransition(ctx, state)
		return
	}
	if state.Mode == simModeBackup && !state.ReturnAt.IsZero() && !time.Now().Before(state.ReturnAt) && status.ActiveSIM == otherSIM(primary) {
		if err := a.beginSIMTransition(simPurposeAutoPrimary, primary); err != nil {
			a.logger.Error("primary SIM return could not start", "error", err)
		}
	}
}

func simDataConnected(state string) bool {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case "connected", "up", "online":
		return true
	default:
		return false
	}
}

func (a *App) observeSIMFailover(ctx context.Context, issues, samples []Sample) {
	a.simMu.Lock()
	primary, _, err := a.simSettings(ctx)
	if err != nil || primary == "unset" || a.teltonika == nil {
		a.simMu.Unlock()
		return
	}
	status, state, switching := a.simStatus, a.simState, a.simTransition
	if switching || state.Mode != simModeNormal || state.PrimarySIM != primary || status.ActiveSIM != primary {
		a.simBadCycles = 0
		a.simMu.Unlock()
		return
	}
	a.simMu.Unlock()
	// Normal diagnostics are rate-limited. Confirm prospective failover with fresh
	// LAN/upstream evidence instead of waiting for the next two-minute burst.
	badTCP := 0
	for _, sample := range samples {
		if sample.ProbeType == "tcp" && pathDegraded(sample) {
			badTCP++
		}
	}
	if badTCP >= 2 && a.cfg.PingEnabled && !simLANHealthy(samples) {
		diagCtx, cancel := context.WithTimeout(ctx, a.cfg.BurstTimeout)
		extra := a.runPingBursts(diagCtx)
		cancel()
		samples = append(samples, extra...)
		for _, sample := range extra {
			if err := insertSample(ctx, a.db, sample); err != nil {
				a.logger.Error("SIM confirmation probe persistence failed", "error", err)
			}
		}
		diagnosis := classify(Snapshot{Samples: samples})
		if diagnosis.Classification == "wan_or_isp_packet_loss" && diagnosis.Confidence == "high" {
			issues = append(issues, Sample{Target: diagnosis.Classification, Severity: diagnosis.Severity, diagnosis: &diagnosis})
		}
	}
	a.simMu.Lock()
	if a.simTransition || a.simState.Mode != simModeNormal || a.simState.PrimarySIM != primary || a.simStatus.ActiveSIM != primary {
		a.simBadCycles = 0
		a.simMu.Unlock()
		return
	}
	qualifying, outage := qualifyingSIMFailure(issues)
	if !qualifying || !simLANHealthy(samples) {
		a.simBadCycles = 0
		a.simMu.Unlock()
		return
	}
	a.simBadCycles++
	needed := simConsecutiveWANCycles
	if outage {
		needed = 1 // internet_outage is already emitted after two complete failed cycles.
	}
	start := a.simBadCycles >= needed
	if start {
		a.simBadCycles = 0
	}
	a.simMu.Unlock()
	if start {
		if err := a.beginSIMTransition(simPurposeAutoBackup, otherSIM(primary)); err != nil {
			a.logger.Error("secondary SIM failover could not start", "error", err)
		}
	}
}

func qualifyingSIMFailure(issues []Sample) (qualifies, confirmedOutage bool) {
	for _, issue := range issues {
		switch issue.Target {
		case "local_network_or_host", "host_or_nic", "gateway_or_router":
			return false, false
		}
	}
	for _, issue := range issues {
		if issue.Target == "internet_outage" && issue.Severity == Critical {
			return true, true
		}
		if issue.Target == "wan_or_isp_packet_loss" && issue.diagnosis != nil && issue.diagnosis.Confidence == "high" && severityRank(issue.Severity) >= severityRank(Error) {
			qualifies = true
		}
	}
	return qualifies, false
}

func simLANHealthy(samples []Sample) bool {
	if extract(Snapshot{Samples: samples}).nicRising() {
		return false
	}
	for _, sample := range samples {
		if sample.Target == "icmp:pihole" && sample.ProbeType == "icmp-burst" && (!sample.Success || sample.Mbps > 0) {
			return false
		}
	}
	for _, sample := range samples {
		if sample.Target == "icmp:gateway" && sample.ProbeType == "icmp-burst" && sample.Success && sample.Mbps == 0 && !probeHealthIssue(sample) {
			return true
		}
	}
	return false
}

func (a *App) beginSIMTransition(purpose, target string) error {
	a.simMu.Lock()
	primary, cooldown, err := a.simSettings(context.Background())
	if err != nil {
		a.simMu.Unlock()
		return err
	}
	if primary == "unset" || a.teltonika == nil || (target != "1" && target != "2") {
		a.simMu.Unlock()
		return errors.New("SIM switching disabled or target invalid")
	}
	intent := simFailoverState{Mode: simModeSwitching, PrimarySIM: primary, TargetSIM: target, Purpose: purpose}
	if !validSIMState(intent) {
		a.simMu.Unlock()
		return errors.New("SIM action no longer matches configured primary")
	}
	if a.simTransition {
		a.simMu.Unlock()
		return errors.New("SIM transition already in progress")
	}
	if a.simContext != nil && a.simContext.Err() != nil {
		a.simMu.Unlock()
		return errors.New("SIM controller is shutting down")
	}
	if a.simState.Mode == simModeFailed && strings.HasPrefix(purpose, "auto-") {
		a.simMu.Unlock()
		return errors.New("SIM failover is in failed state; use manual control")
	}
	if purpose == simPurposeAutoBackup && (a.simState.Mode != simModeNormal || a.simStatus.ActiveSIM != primary) {
		a.simMu.Unlock()
		return errors.New("automatic failover no longer eligible")
	}
	if purpose == simPurposeAutoPrimary && a.simState.Mode != simModeBackup {
		a.simMu.Unlock()
		return errors.New("primary retry no longer eligible")
	}
	previous := a.simState
	a.simState.Mode = simModeSwitching
	a.simState.PrimarySIM = primary
	a.simState.TargetSIM = target
	a.simState.Purpose = purpose
	a.simState.Message = "Switching to SIM" + target + "."
	if purpose == simPurposeAutoBackup || purpose == simPurposeManualBackup {
		a.simState.RetryDelay = cooldown
		a.simState.RetryCount = 0
		a.simState.ReturnAt = time.Time{}
	}
	if err := a.saveSIMFailoverStateLocked(); err != nil {
		a.simState = previous
		a.simMu.Unlock()
		return err
	}
	a.simTransition = true
	workerCtx := a.simContext
	if workerCtx == nil {
		workerCtx = context.Background()
	}
	a.simWorkers.Add(1)
	a.simMu.Unlock()
	go func() {
		defer a.simWorkers.Done()
		a.runSIMTransition(workerCtx, target, purpose, primary, cooldown)
	}()
	return nil
}

func (a *App) resumeSIMTransition(ctx context.Context, state simFailoverState) {
	a.simMu.Lock()
	if a.simTransition || a.simState.Mode != simModeSwitching || a.simState.TargetSIM == "" {
		a.simMu.Unlock()
		return
	}
	a.simTransition = true
	state = a.simState
	primary, cooldown := state.PrimarySIM, simDefaultCooldown
	if _, configuredCooldown, err := a.simSettings(ctx); err == nil {
		cooldown = configuredCooldown
	}
	purpose, target := state.Purpose, state.TargetSIM
	workerCtx := a.simContext
	if workerCtx == nil || workerCtx.Err() != nil {
		a.simTransition = false
		a.simMu.Unlock()
		return
	}
	a.simWorkers.Add(1)
	a.simMu.Unlock()
	go func() {
		defer a.simWorkers.Done()
		a.runSIMTransition(workerCtx, target, purpose, primary, cooldown)
	}()
}

func (a *App) runSIMTransition(parent context.Context, target, purpose, primary string, cooldown time.Duration) {
	ctx, cancel := context.WithTimeout(parent, 35*time.Minute)
	defer cancel()
	defer func() {
		if parent.Err() != nil {
			a.simMu.Lock()
			a.simTransition = false // Preserve persisted intent for restart; never switch during shutdown.
			a.simMu.Unlock()
		}
	}()
	if err := a.switchAndWait(ctx, target); err != nil {
		if parent.Err() != nil {
			return
		}
		if purpose == simPurposeAutoPrimary || purpose == simPurposeManualPrimary {
			a.finishFailedPrimaryReturn(ctx, primary, cooldown, purpose, err)
			return
		}
		a.finishSIMTransition(simFailoverState{Mode: simModeFailed, PrimarySIM: primary, TargetSIM: target, Message: "SIM switch failed: " + redactSMTPErr(err, a.cfg.TeltonikaPassword)})
		return
	}

	if purpose == simPurposeAutoPrimary {
		if !a.simSmokeTest(ctx) {
			if parent.Err() != nil {
				return
			}
			a.retryOnSecondary(ctx, primary, cooldown)
			return
		}
	}
	if target == primary {
		message := "Primary SIM passed smoke tests; normal monitoring resumed."
		if purpose == simPurposeManualPrimary {
			message = "Manual return to primary complete; failover state reset and normal monitoring resumed."
		}
		a.finishSIMTransition(simFailoverState{Mode: simModeNormal, PrimarySIM: primary, RetryDelay: cooldown, Message: message})
		return
	}
	delay := cooldown
	retryCount := 0
	if purpose == simPurposeRetryBackup {
		a.simMu.Lock()
		delay, retryCount = a.simState.RetryDelay, a.simState.RetryCount
		a.simMu.Unlock()
		if delay <= 0 {
			delay = cooldown
		}
	}
	a.finishSIMTransition(simFailoverState{
		Mode: simModeBackup, PrimarySIM: primary, ReturnAt: time.Now().Add(delay), RetryDelay: delay, RetryCount: retryCount,
		Message: fmt.Sprintf("Using SIM%s; primary retest scheduled after %s.", target, delay),
	})
}

func (a *App) switchAndWait(ctx context.Context, target string) error {
	statusCtx, cancel := context.WithTimeout(ctx, teltonikaHTTPTimeout+time.Second)
	status, err := a.teltonika.status(statusCtx)
	cancel()
	if err != nil {
		return err
	}
	if status.ActiveSIM != target {
		if err := a.teltonika.setActiveSIM(ctx, target, status.ModemID); err != nil {
			return err
		}
	}
	connectDeadline := time.Now().Add(simSwitchTimeout)
	stableSince := time.Time{}
	stabilization := a.cfg.TeltonikaSIMStabilization
	if stabilization <= 0 {
		stabilization = time.Minute
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		statusCtx, cancel := context.WithTimeout(ctx, teltonikaHTTPTimeout+time.Second)
		status, err := a.teltonika.status(statusCtx)
		cancel()
		if err == nil && simConnectionStable(status, target, &stableSince, time.Now(), stabilization) {
			a.simMu.Lock()
			a.simStatus = status
			a.simMu.Unlock()
			return nil
		}
		if err != nil {
			stableSince = time.Time{}
		}
		if stableSince.IsZero() && time.Now().After(connectDeadline) {
			if err != nil {
				return fmt.Errorf("waiting for SIM%s connection: %w", target, err)
			}
			return fmt.Errorf("SIM%s did not connect within %s", target, simSwitchTimeout)
		}
		timer := time.NewTimer(simTransitionPoll)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func simConnectionStable(status teltonikaSIMStatus, target string, since *time.Time, now time.Time, interval time.Duration) bool {
	if status.ActiveSIM != target || !simDataConnected(status.DataConnState) {
		*since = time.Time{}
		return false
	}
	if since.IsZero() {
		*since = now
	}
	return now.Sub(*since) >= interval
}

func (a *App) simSmokeTest(ctx context.Context) bool {
	controls := independentSIMControls(a.cfg.tcpControls())
	if len(controls) < 2 {
		return false
	}
	for cycle := 0; cycle < 2; cycle++ {
		if !a.simPrimaryConnected(ctx) {
			return false
		}
		started := time.Now()
		probes := make([]probeFunc, 0, len(controls))
		for _, control := range controls {
			control := control
			probes = append(probes, probeFunc{ProbeType: "tcp", Target: tcpSampleTarget(control.Name), Run: func(probeCtx context.Context) Sample {
				return probeTCP(probeCtx, tcpSampleTarget(control.Name), control.Address)
			}})
		}
		samples := runConcurrentProbes(ctx, 10*time.Second, probes)
		if ctx.Err() != nil {
			return false
		}
		if !simSmokeHealthy(samples, len(controls)) || !a.simPrimaryConnected(ctx) {
			return false
		}
		if cycle == 0 {
			wait := time.Until(started.Add(simSmokeCycleInterval))
			if wait > 0 {
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return false
				case <-timer.C:
				}
			}
		}
	}
	return true
}

func simSmokeHealthy(samples []Sample, controls int) bool {
	if controls < 2 {
		return false
	}
	successes := 0
	for _, sample := range samples {
		if sample.Success && sample.Severity == Info && !probeHealthIssue(sample) {
			successes++
		}
	}
	return successes >= 2
}

func independentSIMControls(controls []TCPControl) []TCPControl {
	seen := map[string]bool{}
	var result []TCPControl
	for _, control := range controls {
		host, _, err := net.SplitHostPort(control.Address)
		ip := net.ParseIP(host)
		if err != nil || ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || seen[ip.String()] {
			continue
		}
		seen[ip.String()] = true
		result = append(result, control)
	}
	return result
}

func (a *App) simPrimaryConnected(ctx context.Context) bool {
	status, err := a.teltonika.status(ctx)
	a.simMu.Lock()
	primary := a.simState.PrimarySIM
	a.simMu.Unlock()
	return err == nil && status.ActiveSIM == primary && simDataConnected(status.DataConnState)
}

func (a *App) retryOnSecondary(ctx context.Context, primary string, base time.Duration) {
	backup := otherSIM(primary)
	a.simMu.Lock()
	previous := a.simState.RetryDelay
	count := a.simState.RetryCount + 1
	a.simState.TargetSIM = backup
	a.simState.Purpose = simPurposeRetryBackup
	a.simState.Message = "Primary failed smoke test; returning to secondary SIM."
	a.simMu.Unlock()
	delay := nextSIMRetryDelay(previous, base)
	a.simMu.Lock()
	a.simState.RetryDelay = delay
	a.simState.RetryCount = count
	if err := a.saveSIMFailoverStateLocked(); err != nil {
		a.logger.Error("SIM retry state persistence failed", "error", err)
	}
	a.simMu.Unlock()
	if err := a.switchAndWait(ctx, backup); err != nil {
		if ctx.Err() == context.Canceled {
			return
		}
		a.finishSIMTransition(simFailoverState{Mode: simModeFailed, PrimarySIM: primary, TargetSIM: backup, RetryDelay: delay, RetryCount: count, Message: "Primary smoke test failed; secondary switch failed: " + redactSMTPErr(err, a.cfg.TeltonikaPassword)})
		return
	}
	a.finishSIMTransition(simFailoverState{
		Mode: simModeBackup, PrimarySIM: primary, RetryDelay: delay, RetryCount: count, ReturnAt: time.Now().Add(delay),
		Message: fmt.Sprintf("Primary smoke test failed; using SIM%s. Retest in %s.", backup, delay),
	})
}

func nextSIMRetryDelay(previous, base time.Duration) time.Duration {
	if base <= 0 {
		base = simDefaultCooldown
	}
	if previous < base {
		previous = base
	}
	cap := max(simRetryCooldownCap, base*2)
	if previous >= cap/2 {
		return cap
	}
	return min(previous*2, cap)
}

func (a *App) finishFailedPrimaryReturn(ctx context.Context, primary string, cooldown time.Duration, purpose string, cause error) {
	if purpose == simPurposeManualPrimary {
		a.finishSIMTransition(simFailoverState{Mode: simModeFailed, PrimarySIM: primary, Message: "Manual return to primary failed: " + redactSMTPErr(cause, a.cfg.TeltonikaPassword)})
		return
	}
	a.retryOnSecondary(ctx, primary, cooldown)
}

func (a *App) finishSIMTransition(state simFailoverState) {
	if state.Mode == simModeNormal {
		a.probeMu.Lock()
		defer a.probeMu.Unlock()
		a.criticalCycles = 0
	}
	a.simMu.Lock()
	a.simState = state
	a.simTransition = false
	if state.Mode == simModeNormal || state.Mode == simModeBackup {
		a.simBadCycles = 0
	}
	if err := a.saveSIMFailoverStateLocked(); err != nil {
		a.logger.Error("SIM failover state persistence failed", "error", err)
	}
	a.simMu.Unlock()
}

func otherSIM(primary string) string {
	if primary == "1" {
		return "2"
	}
	if primary == "2" {
		return "1"
	}
	return ""
}

func simSlotLabel(slot string) string {
	if slot == "1" || slot == "2" {
		return "SIM" + slot
	}
	return "Unset"
}

func (a *App) simFailoverView(ctx context.Context, csrf string) simFailoverView {
	a.simMu.Lock()
	primary, cooldown, err := a.simSettings(ctx)
	if err != nil {
		primary, cooldown = "unset", simDefaultCooldown
	}
	state, status, switching := a.simState, a.simStatus, a.simTransition
	a.simMu.Unlock()
	view := simFailoverView{
		Configured: a.teltonika != nil, Enabled: a.teltonika != nil && primary != "unset", CSRF: csrf,
		PrimarySIM: primary, ActiveSIM: status.ActiveSIM, DataConnState: status.DataConnState,
		Mode: state.Mode, Message: state.Message, NextTestAt: state.ReturnAt,
		CooldownHours: int(cooldown / time.Hour), Stabilization: a.cfg.TeltonikaSIMStabilization.String(), Switching: switching,
	}
	if a.cfg.TeltonikaSIMStabilization <= 0 {
		view.Stabilization = "60s"
	}
	view.HasNextTest = !state.ReturnAt.IsZero()
	switch state.Mode {
	case simModeBackup:
		view.ModeLabel = "Using secondary"
	case simModeSwitching:
		view.ModeLabel = "Switching"
	case simModeFailed:
		view.ModeLabel = "Switch failed"
	default:
		view.ModeLabel = "Normal"
	}
	if a.teltonika == nil {
		view.Message = "Configure TELTONIKA_URL and TELTONIKA_PASSWORD to enable SIM status/control."
	} else if primary == "unset" {
		view.Message = "Primary SIM is Unset; SIM switching disabled. Active SIM status remains read-only."
	} else if status.DataConnState != "" && strings.HasPrefix(status.DataConnState, "status unavailable:") {
		view.Message = status.DataConnState
	} else if state.Mode == simModeNormal && status.ActiveSIM != "" && status.ActiveSIM != primary {
		view.Message = fmt.Sprintf("Active SIM is %s; configured primary is %s. Status check only; no automatic correction.", simSlotLabel(status.ActiveSIM), simSlotLabel(primary))
	}
	view.CanSwitchToSecondary = view.Enabled && !switching && status.ActiveSIM == primary && state.Mode != simModeBackup
	view.CanSwitchToPrimary = view.Enabled && !switching && ((status.ActiveSIM != "" && status.ActiveSIM != primary) || state.Mode == simModeFailed)
	return view
}

func (a *App) simFailoverFragment(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, "sim-failover.html", a.simFailoverView(r.Context(), s.CSRF))
}

func (a *App) simFailoverStatusFragment(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, "sim-failover-status.html", a.simFailoverView(r.Context(), s.CSRF))
}

func (a *App) saveSIMFailoverSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	primary := strings.ToLower(strings.TrimSpace(r.FormValue("primary_sim")))
	if primary != "unset" && primary != "1" && primary != "2" {
		http.Error(w, "primary SIM must be Unset, SIM1, or SIM2", http.StatusBadRequest)
		return
	}
	hours, err := strconv.Atoi(r.FormValue("sim_cooldown_hours"))
	if err != nil || hours < 1 || hours > int(simMaxCooldown/time.Hour) {
		http.Error(w, "SIM cooldown must be 1-168 hours", http.StatusBadRequest)
		return
	}
	a.simMu.Lock()
	if a.simTransition {
		a.simMu.Unlock()
		a.simFailoverError(w, r, "Cannot change SIM settings during a switch.", http.StatusConflict)
		return
	}
	newState := a.simState
	if newState.PrimarySIM != primary {
		newState = simFailoverState{Mode: simModeNormal, PrimarySIM: primary, RetryDelay: time.Duration(hours) * time.Hour}
	}
	stateRaw, err := json.Marshal(newState)
	if err != nil {
		a.simMu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err == nil {
		defer tx.Rollback()
		for key, value := range map[string]string{simPrimarySetting: primary, simCooldownSetting: strconv.Itoa(hours), simStateSetting: string(stateRaw)} {
			if _, err = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
				break
			}
		}
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
	}
	if err != nil {
		a.simMu.Unlock()
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if a.simState.PrimarySIM != primary {
		a.simBadCycles = 0
	}
	a.simState = newState
	a.simMu.Unlock()
	a.render(w, "sim-failover.html", a.simFailoverView(r.Context(), r.Context().Value(sessionContextKey).(session).CSRF))
}

func (a *App) simFailoverAction(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	primary, _, err := a.simSettings(r.Context())
	if err != nil || primary == "unset" || a.teltonika == nil {
		a.simFailoverError(w, r, "SIM switching is not configured.", http.StatusConflict)
		return
	}
	var purpose, target string
	switch r.FormValue("action") {
	case "secondary":
		purpose, target = simPurposeManualBackup, otherSIM(primary)
	case "primary":
		purpose, target = simPurposeManualPrimary, primary
	default:
		http.Error(w, "invalid SIM action", http.StatusBadRequest)
		return
	}
	if err := a.beginSIMTransition(purpose, target); err != nil {
		a.simFailoverError(w, r, err.Error(), http.StatusConflict)
		return
	}
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, "sim-failover.html", a.simFailoverView(r.Context(), s.CSRF))
}

func (a *App) simFailoverError(w http.ResponseWriter, r *http.Request, message string, status int) {
	if r.Header.Get("HX-Request") != "true" {
		http.Error(w, message, status)
		return
	}
	s := r.Context().Value(sessionContextKey).(session)
	view := a.simFailoverView(r.Context(), s.CSRF)
	view.Message = message
	w.Header().Set("HX-Retarget", "#sim-failover-status")
	w.Header().Set("HX-Reswap", "outerHTML")
	a.render(w, "sim-failover-status.html", view)
}
