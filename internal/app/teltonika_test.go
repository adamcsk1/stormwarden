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

func TestRUTX50BulkCellInfo(t *testing.T) {
	const status = `{"success":true,"data":[{"success":true,"data":[{"operator":"Example Network","conntype":"5G (NSA)","mode":0,"band":"LTE B3","rsrp":-77,"cellid":"123456","tac":"4321","imei":"synthetic-imei","imsi":"synthetic-imsi","cell_info":[{"earfcn":1850,"nr-arfcn":"N/A","pcid":315,"tac":"4321","cellid":"123456","mcc":"999","mnc":"01"},{"earfcn":"N/A","nr-arfcn":427010,"pcid":218,"tac":"N/A","cellid":"123456","mcc":"999","mnc":"01"}]}]},{"success":true,"data":[{"sim":"2"}]}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			_, _ = w.Write([]byte(`{"success":true,"data":{"token":"session","expires":300}}`))
		case "/api/modems/status":
			_, _ = w.Write([]byte(status))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	a := newTestApp(t)
	a.cfg.TeltonikaURL, a.cfg.TeltonikaPassword = srv.URL, "test"
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "test"})
	a.pollModem(context.Background())
	s, err := latestModemSample(context.Background(), a.db)
	if err != nil || s == nil {
		t.Fatalf("stored sample=%+v error=%v", s, err)
	}
	if s.NetworkType != "5G (NSA)" || s.CellID != "123456" || s.TAC != "4321" || s.LTEPCI != "315" || s.NRPCI != "218" || s.EARFCN != "1850" || s.NRARFCN != "427010" || s.MCC != "999" || s.MNC != "01" {
		t.Fatalf("parsed cell info=%+v", s)
	}
	if strings.Contains(s.Message, "synthetic-imei") || strings.Contains(s.Message, "synthetic-imsi") {
		t.Fatalf("device identifiers persisted in evidence: %s", s.Message)
	}
	result := httptest.NewRecorder()
	a.modemFragment(result, httptest.NewRequest(http.MethodGet, "/ui/modem", nil))
	for _, text := range []string{"Cell info", "<span>Cell ID</span><strong>123456</strong>", "<span>TAC</span><strong>4321</strong>", "<strong>315 / 218</strong>", "<strong>1850 / 427010</strong>", "<strong>999</strong>", "<strong>01</strong>"} {
		if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), text) {
			t.Fatalf("missing %q in modem status=%d body=%s", text, result.Code, result.Body.String())
		}
	}
}

func TestCellInfoIgnoresUnavailableFieldsAndKeepsPCISeparate(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`{"rsrp":-90,"tac":"N/A","cell_info":[{"earfcn":1800,"pcid":315,"tac":"4567","mcc":"216","mnc":"01"},{"earfcn":"N/A","nr-arfcn":427010,"pcid":218}]}`), &data); err != nil {
		t.Fatal(err)
	}
	s := parseModemStats(data)
	if s.CellID != "" || s.TAC != "4567" || s.LTEPCI != "315" || s.NRPCI != "218" || s.MNC != "01" {
		t.Fatalf("missing cell ID or unavailable TAC misparsed: %+v", s)
	}
	var pciOnly any
	_ = json.Unmarshal([]byte(`{"rsrp":-90,"pci":315}`), &pciOnly)
	s = parseModemStats(pciOnly)
	if s.CellID != "" || s.LTEPCI != "315" {
		t.Fatalf("PCI mistaken for Cell ID: %+v", s)
	}
}

func TestBulkStatusDoesNotMixModemCells(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`[{"success":true,"data":[{"cell_info":[{"earfcn":1850,"pcid":111}],"cellid":"idle-cell"},{"rsrp":-85,"cellid":"live-cell","cell_info":[{"earfcn":1950,"pcid":222,"mnc":"01"}]}]},{"success":true,"data":[{"sim":"2"}]}]`), &data); err != nil {
		t.Fatal(err)
	}
	s, ok := firstRadioSample(data)
	if !ok || s.CellID != "live-cell" || s.LTEPCI != "222" || s.EARFCN != "1950" || s.MNC != "01" {
		t.Fatalf("cell fields combined across modems: %+v", s)
	}
}

func TestBulkWrapperCannotSupplyRadioAfterEmptyModems(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`{"success":true,"rsrp":-90,"data":[{"cellid":"idle"}]}`), &data); err != nil {
		t.Fatal(err)
	}
	if s, ok := firstRadioSample(data); ok {
		t.Fatalf("non-modem wrapper counted as radio: %+v", s)
	}
}

func TestNRChannelDoesNotBecomeLTEPCI(t *testing.T) {
	var data any
	if err := json.Unmarshal([]byte(`{"rsrp":-85,"pci":218,"cell_info":[{"earfcn":"N/A","nr-arfcn":427010,"pcid":"N/A"}]}`), &data); err != nil {
		t.Fatal(err)
	}
	s := parseModemStats(data)
	if s.NRARFCN != "427010" || s.NRPCI != "" || s.LTEPCI != "" || s.CellID != "" {
		t.Fatalf("missing NR PCI mislabeled LTE: %+v", s)
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

func TestFetchModemBypassesCooldownAndRequiresCSRF(t *testing.T) {
	var stats atomic.Int32
	srv := stubTeltonika(t, &stats)
	a := newTestApp(t)
	a.cfg.TeltonikaURL, a.cfg.TeltonikaPassword = srv.URL, "Secret1a"
	a.teltonika = newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaUser: "u", TeltonikaPassword: "Secret1a", TeltonikaInsecureSkipVerify: true})
	a.pollModem(context.Background())
	cookie := login(t, a)
	bad := httptest.NewRequest(http.MethodPost, "/ui/modem/fetch", nil)
	bad.AddCookie(cookie)
	denied := httptest.NewRecorder()
	a.Handler().ServeHTTP(denied, bad)
	if denied.Code != http.StatusForbidden || stats.Load() != 1 {
		t.Fatalf("missing CSRF status=%d fetches=%d", denied.Code, stats.Load())
	}
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/modem/fetch", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "2 samples/24h") || stats.Load() != 2 {
		t.Fatalf("fetch status=%d fetches=%d body=%s", result.Code, stats.Load(), result.Body.String())
	}
	a.pollModem(context.Background())
	if stats.Load() != 2 {
		t.Fatalf("regular modem poll ignored cooldown: fetches=%d", stats.Load())
	}
}
