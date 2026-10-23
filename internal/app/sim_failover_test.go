package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSIMSettingsUnsetDefaultAndStoredCooldown(t *testing.T) {
	a := newTestApp(t)
	primary, cooldown, err := a.simSettings(context.Background())
	if err != nil || primary != "unset" || cooldown != 2*time.Hour {
		t.Fatalf("defaults primary=%q cooldown=%s err=%v", primary, cooldown, err)
	}
	if err := setSetting(context.Background(), a.db, simPrimarySetting, "2"); err != nil {
		t.Fatal(err)
	}
	if err := setSetting(context.Background(), a.db, simCooldownSetting, "5"); err != nil {
		t.Fatal(err)
	}
	primary, cooldown, err = a.simSettings(context.Background())
	if err != nil || primary != "2" || cooldown != 5*time.Hour {
		t.Fatalf("stored primary=%q cooldown=%s err=%v", primary, cooldown, err)
	}
}

func TestSIMFailoverSettingsSaveAndUnsetBlocksSwitch(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}, "primary_sim": {"1"}, "sim_cooldown_hours": {"3"}}
	request := httptest.NewRequest(http.MethodPost, "/ui/sim-failover/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "value=\"1\" selected") {
		t.Fatalf("settings response status=%d body=%s", result.Code, result.Body.String())
	}
	primary, cooldown, err := a.simSettings(context.Background())
	if err != nil || primary != "1" || cooldown != 3*time.Hour {
		t.Fatalf("saved primary=%q cooldown=%s err=%v", primary, cooldown, err)
	}
	if err := setSetting(context.Background(), a.db, simPrimarySetting, "unset"); err != nil {
		t.Fatal(err)
	}
	if err := a.beginSIMTransition(simPurposeManualBackup, "2"); err == nil {
		t.Fatal("switch started with primary Unset")
	}
}

func TestSIMFailoverSettingsRejectInvalidValues(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}, "primary_sim": {"3"}, "sim_cooldown_hours": {"0"}}
	request := httptest.NewRequest(http.MethodPost, "/ui/sim-failover/settings", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusBadRequest {
		t.Fatalf("invalid SIM settings status=%d body=%s", result.Code, result.Body.String())
	}
}

func TestSIMFailoverEligibilityAndRetryBackoff(t *testing.T) {
	local := []Sample{{Target: "local_dns", Severity: Critical}}
	if qualifies, _ := qualifyingSIMFailure(local); qualifies {
		t.Fatal("local DNS failure triggered SIM failover")
	}
	wan := []Sample{{Target: "wan_or_isp_packet_loss", Severity: Error, diagnosis: &Diagnosis{Confidence: "high"}}}
	if qualifies, outage := qualifyingSIMFailure(wan); !qualifies || outage {
		t.Fatalf("high-confidence WAN loss=%v outage=%v", qualifies, outage)
	}
	outage := []Sample{{Target: "internet_outage", Severity: Critical}}
	if qualifies, confirmed := qualifyingSIMFailure(outage); !qualifies || !confirmed {
		t.Fatalf("confirmed outage=%v confirmed=%v", qualifies, confirmed)
	}
	if got := nextSIMRetryDelay(2*time.Hour, 2*time.Hour); got != 4*time.Hour {
		t.Fatalf("first retry delay=%s", got)
	}
	if got := nextSIMRetryDelay(16*time.Hour, 2*time.Hour); got != 24*time.Hour {
		t.Fatalf("capped retry delay=%s", got)
	}
	if got := nextSIMRetryDelay(48*time.Hour, 48*time.Hour); got != 96*time.Hour {
		t.Fatalf("long base retry delay=%s", got)
	}
}

func TestSIMSmokeRequiresMultipleIndependentTCPControls(t *testing.T) {
	if simSmokeHealthy([]Sample{{Success: true, Severity: Info}}, 3) {
		t.Fatal("single healthy control passed smoke test")
	}
	if !simSmokeHealthy([]Sample{{Success: true, Severity: Info}, {Success: true, Severity: Info}, {Success: false}}, 3) {
		t.Fatal("two healthy controls failed smoke test")
	}
	if simSmokeHealthy([]Sample{{Success: true, Severity: Info}}, 1) {
		t.Fatal("single configured control passed smoke test")
	}
	if simSmokeHealthy([]Sample{{Success: true, Severity: Warning}, {Success: true, Severity: Error}}, 2) {
		t.Fatal("degraded controls passed smoke test")
	}
}

func TestSIMReviewRegressions(t *testing.T) {
	a := newTestApp(t)
	// Local failures must veto the aggregate outage category.
	if ok, _ := qualifyingSIMFailure([]Sample{{Target: "internet_outage", Severity: Critical}, {Target: "gateway_or_router", Severity: Critical}}); ok {
		t.Fatal("router outage qualified for ISP failover")
	}
	if simLANHealthy(nil) || simLANHealthy([]Sample{{Target: "icmp:gateway", ProbeType: "icmp-burst", Success: true, Mbps: 20}}) {
		t.Fatal("missing/lossy LAN evidence treated as healthy")
	}
	if !simLANHealthy([]Sample{{Target: "icmp:gateway", ProbeType: "icmp-burst", Success: true}}) {
		t.Fatal("healthy gateway rejected")
	}
	controls := independentSIMControls([]TCPControl{{Address: "1.1.1.1:443"}, {Address: "1.1.1.1:80"}, {Address: "192.168.1.1:443"}, {Address: "example.com:443"}, {Address: "8.8.8.8:443"}})
	if len(controls) != 2 {
		t.Fatalf("independent public controls=%+v", controls)
	}
	// An unsuccessful wrapper must never supply status or config.
	var wrapper any
	_ = json.Unmarshal([]byte(`{"success":false,"data":[{"id":"m","active_sim":1,"position":"2","modem":"m"}]}`), &wrapper)
	if _, ok := firstSIMStatus(wrapper); ok {
		t.Fatal("failed status envelope accepted")
	}
	if _, ok := findSIMCard(wrapper, "2", "m"); ok {
		t.Fatal("failed config envelope accepted")
	}
	// Persisted switching intent survives cancellation for restart recovery.
	a.simState = simFailoverState{Mode: simModeSwitching, PrimarySIM: "1", TargetSIM: "2", Purpose: simPurposeManualBackup}
	if err := a.saveSIMFailoverStateLocked(); err != nil {
		t.Fatal(err)
	}
	a.simTransition = true
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: "http://127.0.0.1:1"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.runSIMTransition(ctx, "2", simPurposeManualBackup, "1", time.Hour)
	if a.simState.Mode != simModeSwitching || a.simTransition {
		t.Fatalf("shutdown destroyed transition intent: %+v", a.simState)
	}
	if err := a.loadSIMFailoverState(context.Background()); err != nil || a.simState.Purpose != simPurposeManualBackup {
		t.Fatalf("restart lost pending transition: %+v error=%v", a.simState, err)
	}
	// SIM markup belongs inside the single settings replacement root.
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != 200 || strings.Count(body, `id="sim-failover"`) != 1 || !strings.HasSuffix(strings.TrimSpace(body), "</div>") {
		t.Fatalf("invalid settings replacement: %d %s", result.Code, body)
	}
}

func TestSIMControlsRequireCSRF(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	for _, route := range []string{"/ui/sim-failover/settings", "/ui/sim-failover/action"} {
		r := httptest.NewRequest(http.MethodPost, route, strings.NewReader("primary_sim=1&sim_cooldown_hours=2&action=secondary"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		a.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s accepted missing CSRF: %d", route, w.Code)
		}
	}
}

func TestManualSIMTransitionsPersistAndReset(t *testing.T) {
	var active atomic.Int32
	active.Store(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/login":
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"session","expires":300}}`))
		case "/api/modems/status":
			_, _ = fmt.Fprintf(w, `{"success":true,"data":[{"id":"modem-1","active_sim":%d,"data_conn_state":"connected"}]}`, active.Load())
		case "/api/sim_cards/config":
			_, _ = w.Write([]byte(`{"success":true,"data":[{"id":"sim-1","modem":"modem-1","position":"1"},{"id":"sim-2","modem":"modem-1","position":"2"}]}`))
		case "/api/sim_cards/config/sim-1", "/api/sim_cards/config/sim-2":
			var body struct {
				Data map[string]string `json:"data"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Data["primary"] != "1" {
				http.Error(w, "bad switch", http.StatusBadRequest)
				return
			}
			if strings.HasSuffix(r.URL.Path, "sim-1") {
				active.Store(1)
			} else {
				active.Store(2)
			}
			_, _ = w.Write([]byte(`{"success":true}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := newTestApp(t)
	a.cfg.TeltonikaURL, a.cfg.TeltonikaPassword = srv.URL, "secret"
	a.cfg.TeltonikaSIMStabilization = time.Nanosecond
	a.cfg.TCPControls = []TCPControl{{Name: "unusable", Address: "127.0.0.1:1"}}
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "secret"})
	if err := setSetting(context.Background(), a.db, simPrimarySetting, "1"); err != nil {
		t.Fatal(err)
	}
	if err := a.beginSIMTransition(simPurposeManualBackup, "2"); err != nil {
		t.Fatal(err)
	}
	waitForSIMState(t, a, simModeBackup)
	if active.Load() != 2 || a.simState.ReturnAt.IsZero() {
		t.Fatalf("backup transition state=%+v active=%d", a.simState, active.Load())
	}
	if err := a.beginSIMTransition(simPurposeAutoPrimary, "1"); err != nil {
		t.Fatal(err)
	}
	waitForSIMState(t, a, simModeBackup)
	if active.Load() != 2 || a.simState.RetryCount != 1 || a.simState.RetryDelay != 4*time.Hour {
		t.Fatalf("failed primary smoke test did not back off: %+v active=%d", a.simState, active.Load())
	}
	if err := a.beginSIMTransition(simPurposeManualPrimary, "1"); err != nil {
		t.Fatal(err)
	}
	waitForSIMState(t, a, simModeNormal)
	if active.Load() != 1 || a.simState.RetryCount != 0 || !a.simState.ReturnAt.IsZero() {
		t.Fatalf("primary transition state=%+v active=%d", a.simState, active.Load())
	}
	raw, err := setting(context.Background(), a.db, simStateSetting)
	if err != nil {
		t.Fatal(err)
	}
	var persisted simFailoverState
	if err := json.Unmarshal([]byte(raw), &persisted); err != nil || persisted.Mode != simModeNormal {
		t.Fatalf("persisted state=%+v err=%v", persisted, err)
	}
}

func TestSIMStabilizationRestartsAfterDrop(t *testing.T) {
	now := time.Now()
	since := time.Time{}
	status := teltonikaSIMStatus{ActiveSIM: "2", DataConnState: "connected"}
	if simConnectionStable(status, "2", &since, now, time.Minute) {
		t.Fatal("connection stable immediately")
	}
	if !simConnectionStable(status, "2", &since, now.Add(time.Minute), time.Minute) {
		t.Fatal("stable interval not honored")
	}
	status.DataConnState = "disconnected"
	if simConnectionStable(status, "2", &since, now.Add(2*time.Minute), time.Minute) || !since.IsZero() {
		t.Fatal("connection drop did not reset timer")
	}
	status.DataConnState = "connected"
	if simConnectionStable(status, "2", &since, now.Add(3*time.Minute), time.Minute) {
		t.Fatal("old stable interval reused after drop")
	}
}

func waitForSIMState(t *testing.T, a *App, mode string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		a.simMu.Lock()
		state, switching := a.simState, a.simTransition
		a.simMu.Unlock()
		if state.Mode == mode && !switching {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.simMu.Lock()
	state, switching := a.simState, a.simTransition
	a.simMu.Unlock()
	t.Fatalf("SIM state did not reach %q; state=%+v switching=%v", mode, state, switching)
}
