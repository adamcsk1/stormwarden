package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSyncMailStateCadence(t *testing.T) {
	current := map[string]mailIssue{"local_dns": {Summary: "Pi-hole failed"}}
	t0 := int64(1_000_000)
	due, state := syncMailState(current, mailState{}, t0)
	if len(due) != 1 || due[0] != "local_dns" {
		t.Fatalf("first seen due=%v", due)
	}
	markMailSent(&state, due, t0)

	due, state = syncMailState(current, state, t0+3600)
	if len(due) != 0 {
		t.Fatalf("hour later due=%v", due)
	}

	due, state = syncMailState(current, state, t0+8*3600)
	if len(due) != 1 {
		t.Fatalf("shot 2 due=%v", due)
	}
	markMailSent(&state, due, t0+8*3600)

	due, state = syncMailState(current, state, t0+8*3600+3600)
	if len(due) != 0 {
		t.Fatalf("hour after shot 2 due=%v", due)
	}

	t3 := t0 + 12*3600
	due, state = syncMailState(current, state, t3)
	if len(due) != 1 {
		t.Fatalf("shot 3 due=%v", due)
	}
	markMailSent(&state, due, t3)

	due, state = syncMailState(current, state, t3+3600)
	if len(due) != 0 {
		t.Fatalf("hour after shot 3 due=%v", due)
	}

	due, state = syncMailState(current, state, t3+24*3600)
	if len(due) != 1 {
		t.Fatalf("daily due=%v", due)
	}
	markMailSent(&state, due, t3+24*3600)

	due, state = syncMailState(map[string]mailIssue{}, state, t3+25*3600)
	if len(due) != 0 || len(state.Issues) != 0 {
		t.Fatalf("cleared due=%v issues=%v", due, state.Issues)
	}

	due, _ = syncMailState(current, state, t3+26*3600)
	if len(due) != 1 {
		t.Fatalf("reopened due=%v", due)
	}
}

func TestSyncMailStateKeepsUnsentAfterClear(t *testing.T) {
	t0 := int64(1_700_000_000)
	current := map[string]mailIssue{"internet_outage": {Summary: "WAN down", StartedAt: t0}}
	due, state := syncMailState(current, mailState{}, t0)
	if len(due) != 1 {
		t.Fatalf("due=%v", due)
	}
	markMailAttempt(&state, due, t0)

	due, state = syncMailState(map[string]mailIssue{}, state, t0+60)
	if len(due) != 1 || len(state.Issues) != 1 || state.Issues["internet_outage"].Summary != "WAN down" {
		t.Fatalf("dropped unsent due=%v issues=%v", due, state.Issues)
	}

	due, state = syncMailState(map[string]mailIssue{"internet_outage": {Summary: "WAN down", StartedAt: t0 + 120}}, state, t0+120)
	rec := state.Issues["internet_outage"]
	if len(due) != 1 || rec.Sent != 0 || len(rec.Times) != 2 {
		t.Fatalf("flap due=%v rec=%+v", due, rec)
	}
}

func TestMarkMailSentSkipsPassedCadence(t *testing.T) {
	t0 := int64(1_700_000_000)
	state := mailState{Issues: map[string]mailShot{"internet_outage": {FirstSeen: t0, Summary: "WAN down"}}}
	markMailSent(&state, []string{"internet_outage"}, t0+10*3600)
	rec := state.Issues["internet_outage"]
	if rec.Sent < 2 {
		t.Fatalf("did not skip passed shot: %+v", rec)
	}
	due, _ := syncMailState(map[string]mailIssue{"internet_outage": {Summary: "WAN down", StartedAt: t0}}, state, t0+10*3600+60)
	if len(due) != 0 {
		t.Fatalf("immediate extra mail due=%v rec=%+v", due, rec)
	}
}

func TestFormatMailDelayedProblemTime(t *testing.T) {
	state := mailState{Issues: map[string]mailShot{
		"internet_outage": {FirstSeen: 100, Summary: "WAN down", Times: []int64{100, 250}},
		"local_dns":       {FirstSeen: 100, Summary: "down"},
	}}
	live := formatMail("host", time.Unix(100, 0).UTC(), state, []string{"local_dns"}, nil)
	if strings.Contains(live, "Problem time") || !strings.Contains(live, "local_dns: down") {
		t.Fatalf("live body=%s", live)
	}
	one := formatMail("host", time.Unix(200, 0).UTC(), state, []string{"internet_outage"}, []string{"internet_outage"})
	if !strings.Contains(one, "Problem time was 1970-01-01 00:01:40 UTC.") || !strings.Contains(one, "Happened:") || !strings.Contains(one, "1970-01-01 00:04:10 UTC") {
		t.Fatalf("delayed body=%s", one)
	}
	many := formatMail("host", time.Unix(200, 0).UTC(), state, []string{"internet_outage", "local_dns"}, []string{"internet_outage", "local_dns"})
	if !strings.Contains(many, "Problem times:") || !strings.Contains(many, "internet_outage: 1970-01-01 00:01:40 UTC, 1970-01-01 00:04:10 UTC") || !strings.Contains(many, "local_dns: 1970-01-01 00:01:40 UTC") {
		t.Fatalf("multi body=%s", many)
	}
	mixed := formatMail("host", time.Unix(200, 0).UTC(), state, []string{"internet_outage", "local_dns"}, []string{"internet_outage"})
	if strings.Contains(mixed, "Problem time was") || !strings.Contains(mixed, "Problem times:") || !strings.Contains(mixed, "internet_outage: 1970-01-01 00:01:40 UTC, 1970-01-01 00:04:10 UTC") {
		t.Fatalf("mixed body=%s", mixed)
	}
}

func TestFilterMailRetryAfterFail(t *testing.T) {
	now := int64(1_000_000)
	state := mailState{Issues: map[string]mailShot{"local_dns": {FirstSeen: now, LastAttempt: now}}}
	due := filterMailRetry([]string{"local_dns"}, state, now+60)
	if len(due) != 0 {
		t.Fatalf("retry too soon: %v", due)
	}
	due = filterMailRetry([]string{"local_dns"}, state, now+mailRetrySecs)
	if len(due) != 1 {
		t.Fatalf("retry after cooldown: %v", due)
	}
}

func TestMailKeyFilters(t *testing.T) {
	if key := mailKey(Incident{Severity: Error, Category: "local_dns"}); key != "local_dns" {
		t.Fatalf("local_dns=%q", key)
	}
	if key := mailKey(Incident{Severity: Warning, Category: "local_dns"}); key != "" {
		t.Fatalf("warning mailed: %q", key)
	}
	if key := mailKey(Incident{Severity: Error, Category: "gateway_or_router"}); key != "" {
		t.Fatalf("gateway mailed: %q", key)
	}
	evidence, _ := json.Marshal(incidentEvidenceDoc{Classification: "dns_resolution_failure"})
	if key := mailKey(Incident{Severity: Error, Category: "tcp_connect", Evidence: string(evidence)}); key != "dns_resolution_failure" {
		t.Fatalf("diagnosis key=%q", key)
	}
	if key := mailKey(Incident{Severity: Error, Category: "slow_ttfb"}); key != "" {
		t.Fatalf("http mailed: %q", key)
	}
}

func TestSendDueMailAndFailDoesNotAdvance(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	now := time.Unix(1_000_000, 0).UTC()
	issue := Sample{ProbeType: "aggregate", Target: "local_dns", Severity: Error, Message: "Pi-hole failed"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	a.cfg.SMTPHost = "smtp.example"
	a.cfg.SMTPTo = "ops@example"

	var sent int
	a.sendMail = func(subject, body string) error {
		sent++
		if !strings.Contains(subject, "1 issue") || !strings.Contains(body, "local_dns") {
			t.Fatalf("mail subject=%q body=%q", subject, body)
		}
		return errors.New("dial tcp: i/o timeout")
	}
	a.sendDueMail(ctx, now)
	if sent != 1 {
		t.Fatalf("sends=%d", sent)
	}
	state, err := loadMailState(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	rec := state.Issues["local_dns"]
	if rec.Sent != 0 || rec.LastAttempt != now.Unix() {
		t.Fatalf("fail advanced shots: %+v", rec)
	}

	a.sendDueMail(ctx, now.Add(time.Minute))
	if sent != 1 {
		t.Fatalf("retried inside cooldown sends=%d", sent)
	}

	a.sendMail = func(subject, body string) error {
		sent++
		return nil
	}
	a.sendDueMail(ctx, now.Add(15*time.Minute))
	if sent != 2 {
		t.Fatalf("success after cooldown sends=%d", sent)
	}
	state, err = loadMailState(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	rec = state.Issues["local_dns"]
	if rec.Sent != 1 {
		t.Fatalf("success did not count: %+v", rec)
	}

	a.sendDueMail(ctx, now.Add(16*time.Minute))
	if sent != 2 {
		t.Fatalf("duplicate first shot sends=%d", sent)
	}
}

func TestSendDueMailQueuedAfterClear(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0).UTC()
	issue := Sample{ProbeType: "aggregate", Target: "internet_outage", Severity: Error, Message: "WAN down"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	a.cfg.SMTPHost = "smtp.example"
	a.cfg.SMTPTo = "ops@example"

	a.sendMail = func(subject, body string) error {
		return errors.New("dial tcp: i/o timeout")
	}
	a.sendDueMail(ctx, now)

	active, err := activeIncidents(ctx, a.db)
	if err != nil || len(active) != 1 {
		t.Fatalf("active=%d err=%v", len(active), err)
	}
	started := active[0].StartedAt.UTC().Format(mailTimeLayout)
	if err := closeIncident(ctx, a.db, active[0].ID); err != nil {
		t.Fatal(err)
	}

	var bodies []string
	a.sendMail = func(subject, body string) error {
		bodies = append(bodies, body)
		return nil
	}
	a.sendDueMail(ctx, now.Add(time.Minute))
	if len(bodies) != 0 {
		t.Fatalf("sent inside cooldown: %d", len(bodies))
	}
	a.sendDueMail(ctx, now.Add(time.Duration(mailRetrySecs)*time.Second))
	if len(bodies) != 1 || !strings.Contains(bodies[0], "Problem time was "+started+".") || !strings.Contains(bodies[0], "internet_outage: WAN down") {
		t.Fatalf("bodies=%v", bodies)
	}
	state, err := loadMailState(ctx, a.db)
	if err != nil || len(state.Issues) != 0 {
		t.Fatalf("queued shot kept after send: %+v err=%v", state.Issues, err)
	}
	a.sendDueMail(ctx, now.Add(time.Duration(mailRetrySecs)*time.Second+time.Minute))
	if len(bodies) != 1 {
		t.Fatalf("duplicate sends=%d", len(bodies))
	}

	if err := openIncident(ctx, a.db, issue); err != nil {
		t.Fatal(err)
	}
	a.sendDueMail(ctx, now.Add(time.Duration(mailRetrySecs)*time.Second+2*time.Minute))
	if len(bodies) != 2 || strings.Contains(bodies[1], "Problem time was") {
		t.Fatalf("reopen bodies=%v", bodies)
	}
}

func TestSendDueMailDisabledAndUnlisted(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	sent := 0
	a.sendMail = func(subject, body string) error {
		sent++
		return nil
	}
	warn := Sample{ProbeType: "aggregate", Target: "slow_ttfb", Severity: Warning, Message: "slow"}
	a.updateIncident(ctx, warn)
	a.updateIncident(ctx, warn)
	a.cfg.SMTPHost = "smtp.example"
	a.cfg.SMTPTo = "ops@example"
	a.sendDueMail(ctx, time.Now())
	if sent != 0 {
		t.Fatal("unlisted category mailed")
	}

	a.cfg.SMTPHost, a.cfg.SMTPTo = "", ""
	issue := Sample{ProbeType: "aggregate", Target: "local_dns", Severity: Error, Message: "down"}
	a.updateIncident(ctx, issue)
	a.updateIncident(ctx, issue)
	a.sendDueMail(ctx, time.Now())
	if sent != 0 {
		t.Fatal("disabled SMTP mailed")
	}
}

func TestLoadConfigSMTP(t *testing.T) {
	t.Setenv("APP_PASSWORD", "test-password")
	t.Setenv("SMTP_HOST", "smtp.example")
	t.Setenv("SMTP_TO", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("partial SMTP accepted")
	}
	t.Setenv("SMTP_TO", "ops@example, other@example")
	t.Setenv("SMTP_PORT", "587")
	t.Setenv("SMTP_STARTTLS", "1")
	t.Setenv("SMTP_SSL", "0")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.smtpEnabled() || cfg.SMTPPort != 587 || !cfg.SMTPStartTLS || cfg.SMTPSSL || len(smtpRecipients(cfg.SMTPTo)) != 2 {
		t.Fatalf("cfg=%+v", cfg)
	}
	t.Setenv("SMTP_PORT", "65536")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("bad SMTP_PORT accepted")
	}
}

func TestSMTPHealthUnconfigured(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">SMTP<") || !strings.Contains(body, "SMTP_HOST") || !strings.Contains(body, "hx-post=\"/ui/smtp-health\"") || !strings.Contains(body, "disabled") {
		t.Fatalf("unconfigured smtp health status=%d body=%s", result.Code, body)
	}
}

func TestSMTPHealthRequiresCSRF(t *testing.T) {
	a := newTestApp(t)
	a.cfg.SMTPHost, a.cfg.SMTPTo = "smtp.example", "ops@example"
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodPost, "/ui/smtp-health", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusForbidden {
		t.Fatalf("CSRF status=%d", result.Code)
	}
}

func TestSMTPHealthSendAndRedact(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	a.cfg.SMTPHost, a.cfg.SMTPTo, a.cfg.SMTPPassword = "smtp.example", "ops@example", "Secret1a"
	var gotSubject, gotBody string
	a.sendMail = func(subject, body string) error {
		gotSubject, gotBody = subject, body
		return nil
	}
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/smtp-health", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">Sent<") || !strings.Contains(body, "Test email accepted") || gotSubject != "[stormwarden] test email" || !strings.Contains(gotBody, "SMTP test") {
		t.Fatalf("send status=%d body=%s subject=%q mail=%q", result.Code, body, gotSubject, gotBody)
	}
	state, err := loadMailState(ctx, a.db)
	if err != nil || len(state.Issues) != 0 {
		t.Fatalf("cadence mutated: %+v err=%v", state, err)
	}
	a.sendMail = func(subject, body string) error {
		return errors.New("535 auth failed Secret1a")
	}
	fail := httptest.NewRequest(http.MethodPost, "/ui/smtp-health", strings.NewReader(form.Encode()))
	fail.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	fail.AddCookie(cookie)
	failResult := httptest.NewRecorder()
	a.Handler().ServeHTTP(failResult, fail)
	failBody := failResult.Body.String()
	if failResult.Code != http.StatusOK || !strings.Contains(failBody, ">Failed<") || strings.Contains(failBody, "Secret1a") || !strings.Contains(failBody, "***") {
		t.Fatalf("fail status=%d body=%s", failResult.Code, failBody)
	}
}

func TestRedactSMTPErr(t *testing.T) {
	err := errors.New("auth failed secret-pass")
	got := redactSMTPErr(err, "secret-pass")
	if strings.Contains(got, "secret-pass") || !strings.Contains(got, "***") {
		t.Fatalf("leaked: %q", got)
	}
}

func TestFormatSMTPMessageStripsHeaders(t *testing.T) {
	msg := string(formatSMTPMessage("a@x", "b@x", "sub\r\nX-Inject: 1", "body"))
	if strings.Contains(msg, "\nX-Inject") || strings.Contains(msg, "\rX-Inject") {
		t.Fatalf("header inject: %q", msg)
	}
}
