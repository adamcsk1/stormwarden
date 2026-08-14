package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPiHoleCorrelationUsesOneTemporarySession(t *testing.T) {
	var auths, logouts, active atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth":
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload["password"] != "app-password" {
				t.Errorf("invalid authentication payload: %v", payload)
			}
			auths.Add(1)
			active.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"test-sid"}}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/auth":
			if r.Header.Get("X-FTL-SID") != "test-sid" {
				t.Error("logout missing SID")
			}
			logouts.Add(1)
			active.Add(-1)
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/queries":
			if r.Header.Get("X-FTL-SID") != "test-sid" || r.URL.Query().Get("domain") != "abc.example.com" {
				t.Error("query request missing correlation filters")
			}
			_, _ = io.WriteString(w, `{"queries":[{"domain":"abc.example.com","status":"FORWARDED","upstream":"1.1.1.1#53","reply":{"type":"NXDOMAIN","time":12.3}}]}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/messages":
			_, _ = io.WriteString(w, `{"messages":[{"timestamp":`+strconv.FormatInt(time.Now().Unix(), 10)+`,"type":"DNSMASQ_WARN","plain":"upstream warning\ncontinued"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(evidence, "query=observed status=FORWARDED") || !strings.Contains(evidence, "reply_time=12.3ms") || !strings.Contains(evidence, "diagnostic_types=DNSMASQ_WARN") || strings.Contains(evidence, "upstream warning") {
		t.Fatalf("unexpected evidence: %q", evidence)
	}

	var wait sync.WaitGroup
	for range 10 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			if repeated, repeatErr := client.correlate(context.Background(), time.Now(), "abc.example.com"); repeatErr != nil || repeated != "" {
				t.Errorf("cooldown correlation = %q, %v", repeated, repeatErr)
			}
		}()
	}
	wait.Wait()
	if auths.Load() != 1 || logouts.Load() != 1 || active.Load() != 0 {
		t.Fatalf("sessions: auth=%d logout=%d active=%d", auths.Load(), logouts.Load(), active.Load())
	}
}

func TestPiHoleCorrelationLogsOutAfterReadFailure(t *testing.T) {
	var logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"test-sid"}}`)
		case r.Method == http.MethodDelete:
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/queries":
			http.Error(w, "failed", http.StatusServiceUnavailable)
		case r.URL.Path == "/api/info/messages":
			_, _ = io.WriteString(w, `{"messages":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com")
	if err == nil || !strings.Contains(evidence, "query=unavailable") {
		t.Fatalf("correlation = %q, %v", evidence, err)
	}
	if logouts.Load() != 1 {
		t.Fatalf("logout count = %d", logouts.Load())
	}
}

func TestPiHoleCorrelationWithoutRequiredAuthentication(t *testing.T) {
	var logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":null}}`)
		case r.Method == http.MethodDelete:
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/queries":
			if r.Header.Get("X-FTL-SID") != "" {
				t.Error("SID header sent for unauthenticated API")
			}
			_, _ = io.WriteString(w, `{"queries":[{"domain":"abc.example.com","status":"CACHE","reply":{"type":"NXDOMAIN","time":1}}]}`)
		case r.URL.Path == "/api/info/messages":
			_, _ = io.WriteString(w, `{"messages":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "unused-password")
	evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com")
	if err != nil || !strings.Contains(evidence, "query=observed") {
		t.Fatalf("correlation = %q, %v", evidence, err)
	}
	if logouts.Load() != 0 {
		t.Fatalf("logout attempted without session: %d", logouts.Load())
	}
}

func TestPiHoleLogoutFailureBlocksNewSession(t *testing.T) {
	var auths atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"test-sid"}}`)
		case r.Method == http.MethodDelete:
			http.Error(w, "failed", http.StatusInternalServerError)
		case r.URL.Path == "/api/queries":
			_, _ = io.WriteString(w, `{"queries":[]}`)
		case r.URL.Path == "/api/info/messages":
			_, _ = io.WriteString(w, `{"messages":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.correlate(context.Background(), time.Now(), "abc.example.com"); err == nil || !strings.Contains(err.Error(), "logout") {
		t.Fatalf("logout failure not reported: %v", err)
	}
	if evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com"); err != nil || evidence != "" || auths.Load() != 1 {
		t.Fatalf("logout failure backoff = %q, %v, auths=%d", evidence, err, auths.Load())
	}
}

func TestPiHoleAPIDoesNotFollowCredentialRedirects(t *testing.T) {
	var leaked atomic.Bool
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-FTL-SID") != "" {
			leaked.Store(true)
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "app-password") {
			leaked.Store(true)
		}
	}))
	defer redirectTarget.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.correlate(context.Background(), time.Now(), "abc.example.com"); err == nil {
		t.Fatal("redirected authentication accepted")
	}
	if leaked.Load() {
		t.Fatal("Pi-hole API credentials followed redirect")
	}
}

func TestPiHoleAuthenticationLogsOutPartiallyDecodedSession(t *testing.T) {
	var auths, logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"partial-sid"},"broken":`)
			return
		}
		if r.Method == http.MethodDelete && r.Header.Get("X-FTL-SID") == "partial-sid" {
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.correlate(context.Background(), time.Now(), "abc.example.com"); err == nil {
		t.Fatal("malformed authentication response accepted")
	}
	if logouts.Load() != 1 {
		t.Fatalf("logout count = %d", logouts.Load())
	}
	if evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com"); err != nil || evidence != "" || auths.Load() != 1 {
		t.Fatalf("authentication failure backoff = %q, %v, auths=%d", evidence, err, auths.Load())
	}
}

func TestPiHoleCorrelationIgnoresUnrelatedIncident(t *testing.T) {
	client := newPiHoleAPIClient("http://127.0.0.1:1/api", "app-password")
	a := &App{piholeAPI: client, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	issues := []Sample{{Target: "tcp_connect", Severity: Warning}}
	a.correlatePiHoleIncident(context.Background(), issues)
	if !client.lastAttempt.IsZero() || issues[0].incidentContext != "" {
		t.Fatal("unrelated incident contacted Pi-hole API")
	}
}

func TestPiHoleContextAppearsOnlyInIncidentEvidence(t *testing.T) {
	sample := Sample{CreatedAt: time.Now(), Severity: Error, Target: "local_dns", Message: "failed", incidentContext: "pihole_api query=not_observed"}
	evidence := incidentEvidence(sample)
	if !strings.Contains(evidence, "pihole_api query=not_observed") {
		t.Fatalf("missing Pi-hole evidence: %q", evidence)
	}
	encoded, err := json.Marshal(sample)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "pihole_api") {
		t.Fatal("internal correlation leaked into sample JSON")
	}
}

func TestPiHoleContextSurvivesPreIncidentSeverityIncrease(t *testing.T) {
	a := newTestApp(t)
	ctx := context.Background()
	a.updateIncidents(ctx, []Sample{{CreatedAt: time.Now(), Target: "local_dns", Severity: Warning, Message: "slow", incidentContext: "pihole_api query=observed"}}, map[string]bool{"local_dns": true})
	a.updateIncidents(ctx, []Sample{{CreatedAt: time.Now(), Target: "local_dns", Severity: Error, Message: "failed"}}, map[string]bool{"local_dns": true})
	incident, err := activeIncident(ctx, a.db)
	if err != nil {
		t.Fatal(err)
	}
	if incident == nil || !strings.Contains(incident.Evidence, "pihole_api query=observed") {
		t.Fatalf("incident lost first-cycle correlation: %#v", incident)
	}
}

func TestLoadConfigRequiresCompletePiHoleAPISettings(t *testing.T) {
	t.Setenv("APP_PASSWORD", "test-password")
	t.Setenv("PIHOLE_API_URL", "http://192.0.2.2/api")
	t.Setenv("PIHOLE_API_PASSWORD", "")
	t.Setenv("PIHOLE_API_ALLOW_INSECURE_HTTP", "true")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("incomplete Pi-hole API configuration accepted")
	}
	t.Setenv("PIHOLE_API_PASSWORD", "app-password")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PiHoleAPIURL != "http://192.0.2.2/api" || cfg.PiHoleAPIPassword != "app-password" {
		t.Fatal("Pi-hole API configuration not loaded")
	}
	t.Setenv("PIHOLE_API_ALLOW_INSECURE_HTTP", "false")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("insecure Pi-hole API URL accepted without opt-in")
	}
}
