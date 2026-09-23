package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestParseModemStatsNested(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`{
		"operator":"Yettel","conntype":"4G (LTE)","band":"B3","cell_id":"12345",
		"signal":{"rssi":-67,"rsrp":-96,"rsrq":-12,"sinr":11.5},
		"ca":{"scc":[{"band":"B7"}]}
	}`), &data); err != nil {
		t.Fatal(err)
	}
	s := parseModemStats(data)
	if s.RSRP == nil || *s.RSRP != -96 || s.SINR == nil || *s.SINR != 11.5 {
		t.Fatalf("signal %+v", s)
	}
	if s.Operator != "Yettel" || s.Band != "B3" || s.CACount != 2 || !strings.Contains(s.CABands, "B7") {
		t.Fatalf("cell %+v", s)
	}
}

func TestParseModemStatsUnits(t *testing.T) {
	var data any
	_ = json.Unmarshal([]byte(`{"rssi":"-67 dBm","rsrp":"-96 dBm","rsrq":"-12 dB","sinr":"8 dB"}`), &data)
	s := parseModemStats(data)
	if s.RSSI == nil || *s.RSSI != -67 || s.RSRQ == nil || *s.RSRQ != -12 {
		t.Fatalf("units %+v", s)
	}
}

func TestTeltonikaFetchAndReuseSession(t *testing.T) {
	var logins atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/login":
			logins.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"sess","expires":300}}`))
		case "/api/modems/status":
			if r.Header.Get("Authorization") != "Bearer sess" {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"success":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"success":true,"data":[{"rssi":-70,"rsrp":-100,"rsrq":-14,"sinr":4,"operator":"Yettel","conntype":"5G"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "stormwarden", TeltonikaPassword: "Secret1a", TeltonikaInsecureSkipVerify: true})
	sample, err := c.fetch(context.Background())
	if err != nil || sample.RSRP == nil || *sample.RSRP != -100 {
		t.Fatalf("fetch=%v sample=%+v", err, sample)
	}
	if _, err := c.fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 1 {
		t.Fatalf("logins=%d", logins.Load())
	}
}

func TestLoadConfigTeltonika(t *testing.T) {
	t.Setenv("APP_PASSWORD", "test-password")
	t.Setenv("TELTONIKA_URL", "https://192.0.2.1")
	t.Setenv("TELTONIKA_PASSWORD", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("partial teltonika accepted")
	}
	t.Setenv("TELTONIKA_PASSWORD", "Secret1a")
	t.Setenv("TELTONIKA_INSECURESKIPVERIFY", "true")
	cfg, err := LoadConfig()
	if err != nil || !cfg.teltonikaEnabled() || !cfg.TeltonikaInsecureSkipVerify || cfg.TeltonikaUser != "admin" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	t.Setenv("TELTONIKA_URL", "http://192.0.2.1")
	t.Setenv("TELTONIKA_ALLOW_INSECURE_HTTP", "false")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("http without opt-in accepted")
	}
}

func TestRadioGradeTeltonikaTable(t *testing.T) {
	rsrq := -21.0
	if radioGrade(ModemSample{RSRQ: &rsrq}) != "poor" {
		t.Fatal("rsrq -21")
	}
	rsrp := -101.0
	if radioGrade(ModemSample{RSRP: &rsrp}) != "poor" {
		t.Fatal("rsrp -101")
	}
	sinr := 0.0
	if radioGrade(ModemSample{SINR: &sinr}) != "poor" {
		t.Fatal("sinr 0")
	}
	good := -12.0
	if radioGrade(ModemSample{RSRQ: &good}) != "good" {
		t.Fatal("rsrq -12")
	}
	if radioGrade(ModemSample{}) != "" {
		t.Fatal("empty graded")
	}
}

func TestRadioPoorIncidentAfterTwoSamples(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	rsrq := -22.0
	s := ModemSample{CreatedAt: time.Now(), RSRQ: &rsrq}
	a.updateRadioIncident(ctx, s)
	inc, err := activeIncident(ctx, a.db)
	if err != nil || inc != nil {
		t.Fatalf("first poor opened: %+v", inc)
	}
	a.updateRadioIncident(ctx, s)
	inc, err = activeIncident(ctx, a.db)
	if err != nil || inc == nil || inc.Category != "radio_poor" || inc.Severity != Error {
		t.Fatalf("second poor: %+v err=%v", inc, err)
	}
	good := -8.0
	a.updateRadioIncident(ctx, ModemSample{CreatedAt: time.Now(), RSRQ: &good})
	a.updateRadioIncident(ctx, ModemSample{CreatedAt: time.Now(), RSRQ: &good})
	a.updateRadioIncident(ctx, ModemSample{CreatedAt: time.Now(), RSRQ: &good})
	inc, err = activeIncident(ctx, a.db)
	if err != nil || inc != nil {
		t.Fatalf("recovered still open: %+v", inc)
	}
}

func TestParseModemStatsDoesNotTreatB30AsB3(t *testing.T) {
	var data any
	_ = json.Unmarshal([]byte(`{"band":"B3","ca":{"scc":[{"band":"B30"}]}}`), &data)
	s := parseModemStats(data)
	if s.CABands != "B3+B30" {
		t.Fatalf("cabands=%q", s.CABands)
	}
}

func TestModemEvidenceUsesDiagnosisCategory(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	rsrp := -90.0
	if err := insertModemSample(ctx, a.db, ModemSample{CreatedAt: time.Now(), RSRP: &rsrp, Message: "modem rsrp=-90dBm"}); err != nil {
		t.Fatal(err)
	}
	issue := Sample{ProbeType: "aggregate", Target: "tcp_connect", Severity: Error, Message: "dns down", diagnosis: &Diagnosis{Classification: "dns_resolution_failure"}}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	incident, err := activeIncident(ctx, a.db)
	if err != nil || incident == nil || !strings.Contains(incident.Evidence, "rsrp=-90") {
		t.Fatalf("diagnosis evidence missing: %+v err=%v", incident, err)
	}
}

func TestTeltonikaEmptyRadioDoesNotRelogin(t *testing.T) {
	var logins atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/login" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"sess","expires":300}}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":[{"operator":"Yettel"}]}`))
	}))
	defer srv.Close()
	c := newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "p", TeltonikaInsecureSkipVerify: true})
	if _, err := c.fetch(context.Background()); err == nil {
		t.Fatal("expected no radio")
	}
	if logins.Load() != 1 {
		t.Fatalf("relogin on empty radio logins=%d", logins.Load())
	}
}

func TestTeltonikaAuthRetry(t *testing.T) {
	var logins, stats atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/login" {
			logins.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"sess","expires":300}}`))
			return
		}
		if stats.Add(1) == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false}`))
			return
		}
		_, _ = w.Write([]byte(`{"success":true,"data":[{"rsrp":-90,"rsrq":-12,"sinr":8}]}`))
	}))
	defer srv.Close()
	c := newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "p", TeltonikaInsecureSkipVerify: true})
	c.session, c.until = "stale", time.Now().Add(time.Minute)
	sample, err := c.fetch(context.Background())
	if err != nil || sample.RSRP == nil || *sample.RSRP != -90 {
		t.Fatalf("retry=%v sample=%+v", err, sample)
	}
	if logins.Load() != 1 || stats.Load() != 2 {
		t.Fatalf("logins=%d stats=%d", logins.Load(), stats.Load())
	}
}

func TestParseModemStatsCASignal(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`{"band":"B3","rsrp":-96,"ca_signal":[{"band":"B7","primary":false}]}`), &data); err != nil {
		t.Fatal(err)
	}
	s := parseModemStats(data)
	if s.CABands != "B3+B7" || s.CACount != 2 {
		t.Fatalf("ca %+v", s)
	}
}

func TestModemEvidenceOnWANIncident(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	rsrp := -96.0
	if err := insertModemSample(ctx, a.db, ModemSample{CreatedAt: time.Now(), RSRP: &rsrp, Operator: "Yettel", Message: "modem rsrp=-96dBm operator=Yettel"}); err != nil {
		t.Fatal(err)
	}
	issue := Sample{ProbeType: "aggregate", Target: "wan_or_isp_packet_loss", Severity: Error, Message: "WAN loss"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	incident, err := activeIncident(ctx, a.db)
	if err != nil || incident == nil || !strings.Contains(incident.Evidence, "rsrp=-96") {
		t.Fatalf("evidence missing: %+v err=%v", incident, err)
	}
}

func TestIncidentTimelineIncludesNearbyModemSample(t *testing.T) {
	now := time.Now().Truncate(time.Millisecond)
	rsrp := -96.0
	lines := formatIncidentTimeline(
		[]Sample{{CreatedAt: now.Add(time.Minute), Target: "tcp:cloudflare", Severity: Error, DurationMS: 4000}},
		[]ModemSample{{CreatedAt: now, RSRP: &rsrp, Band: "B3", NetworkType: "LTE"}},
		time.UTC,
	)
	if len(lines) != 2 || !strings.Contains(lines[0], "mobile radio") || !strings.Contains(lines[0], "rsrp=-96dBm") || !strings.Contains(lines[1], "tcp:cloudflare") {
		t.Fatalf("timeline=%q", lines)
	}
}

func TestModemFragmentMarksOldReadingStale(t *testing.T) {
	a := newTestApp(t)
	a.cfg.TeltonikaURL, a.cfg.TeltonikaPassword = "https://192.0.2.1", "Secret1a"
	rsrp := -96.0
	if err := insertModemSample(context.Background(), a.db, ModemSample{CreatedAt: time.Now().Add(-2*teltonikaPollInterval - time.Second), RSRP: &rsrp}); err != nil {
		t.Fatal(err)
	}
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/modem", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), ">stale<") {
		t.Fatalf("modem fragment status=%d body=%s", result.Code, result.Body.String())
	}
}

func stubTeltonika(t *testing.T, stats *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/login":
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"sess","expires":300}}`))
		case "/api/modems/status":
			stats.Add(1)
			_, _ = w.Write([]byte(`{"success":true,"data":[{"rssi":-70,"rsrp":-100,"rsrq":-14,"sinr":4}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPollModemCooldown(t *testing.T) {
	var stats atomic.Int32
	srv := stubTeltonika(t, &stats)
	a := newTestApp(t)
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "p", TeltonikaInsecureSkipVerify: true})
	ctx := context.Background()
	a.pollModem(ctx)
	a.pollModem(ctx)
	if stats.Load() != 1 {
		t.Fatalf("cooldown failed stats=%d", stats.Load())
	}
	a.lastModemAttempt = time.Now().Add(-teltonikaPollInterval)
	a.pollModem(ctx)
	if stats.Load() != 2 {
		t.Fatalf("stale poll skipped stats=%d", stats.Load())
	}
}

func TestIncidentPollUsesCooldown(t *testing.T) {
	var stats atomic.Int32
	srv := stubTeltonika(t, &stats)
	a := newTestApp(t)
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "p", TeltonikaInsecureSkipVerify: true})
	ctx := context.Background()
	a.pollModem(ctx)
	issue := Sample{ProbeType: "aggregate", Target: "wan_or_isp_packet_loss", Severity: Error, Message: "WAN loss"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	if stats.Load() != 1 {
		t.Fatalf("incident flooded modem stats=%d", stats.Load())
	}
	incident, err := activeIncident(ctx, a.db)
	if err != nil || incident == nil || !strings.Contains(incident.Evidence, "rsrp=-100") {
		t.Fatalf("stale snapshot not attached: %+v err=%v", incident, err)
	}
}

func TestIncidentPollWhenStale(t *testing.T) {
	var stats atomic.Int32
	srv := stubTeltonika(t, &stats)
	a := newTestApp(t)
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "p", TeltonikaInsecureSkipVerify: true})
	ctx := context.Background()
	a.lastModemAttempt = time.Now().Add(-teltonikaPollInterval)
	issue := Sample{ProbeType: "aggregate", Target: "internet_outage", Severity: Critical, Message: "down"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	if stats.Load() != 1 {
		t.Fatalf("stale incident did not poll stats=%d", stats.Load())
	}
}

func TestTeltonikaHealthUnconfigured(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, "Teltonika API") || !strings.Contains(body, "TELTONIKA_URL") || !strings.Contains(body, "hx-post=\"/ui/teltonika-health\"") {
		t.Fatalf("unconfigured teltonika health status=%d body=%s", result.Code, body)
	}
}

func TestTeltonikaHealthRequiresCSRF(t *testing.T) {
	a := newTestApp(t)
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: "https://192.0.2.1", TeltonikaPassword: "Secret1a", TeltonikaInsecureSkipVerify: true})
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodPost, "/ui/teltonika-health", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusForbidden {
		t.Fatalf("CSRF status=%d", result.Code)
	}
}

func TestTeltonikaHealthCheckAndBypassCooldown(t *testing.T) {
	var stats atomic.Int32
	srv := stubTeltonika(t, &stats)
	a := newTestApp(t)
	a.cfg.TeltonikaPassword = "Secret1a"
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "Secret1a", TeltonikaInsecureSkipVerify: true})
	ctx := context.Background()
	a.pollModem(ctx)
	if stats.Load() != 1 {
		t.Fatalf("setup poll stats=%d", stats.Load())
	}
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/teltonika-health", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">Healthy<") || !strings.Contains(body, "rsrp=-100") || strings.Contains(body, "Secret1a") {
		t.Fatalf("health status=%d body=%s", result.Code, body)
	}
	if stats.Load() != 2 {
		t.Fatalf("manual check should bypass cooldown stats=%d", stats.Load())
	}
	a.pollModem(ctx)
	if stats.Load() != 2 {
		t.Fatalf("auto poll after manual check stats=%d", stats.Load())
	}
	settings := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	settings.AddCookie(cookie)
	settingsResult := httptest.NewRecorder()
	a.Handler().ServeHTTP(settingsResult, settings)
	if settingsResult.Code != http.StatusOK || !strings.Contains(settingsResult.Body.String(), ">Healthy<") || !strings.Contains(settingsResult.Body.String(), "Last checked:") {
		t.Fatalf("stored health body=%s", settingsResult.Body.String())
	}
}
