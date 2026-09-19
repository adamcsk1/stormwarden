package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestPiHoleHealthCheckUsesOneTemporarySession(t *testing.T) {
	var auths, healthReads, logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/auth":
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"health-sid"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/ftl":
			if r.Header.Get("X-FTL-SID") != "health-sid" {
				t.Error("health request missing SID")
			}
			healthReads.Add(1)
			_, _ = io.WriteString(w, `{"ftl":{"pid":321,"uptime":65000}}`)
		case r.Method == http.MethodDelete && r.URL.Path == "/api/auth":
			if r.Header.Get("X-FTL-SID") != "health-sid" {
				t.Error("health logout missing SID")
			}
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	message, err := client.checkHealth(context.Background())
	if err != nil || !strings.Contains(message, "PID 321") || !strings.Contains(message, "1m5s") {
		t.Fatalf("health check = %q, %v", message, err)
	}
	if auths.Load() != 1 || healthReads.Load() != 1 || logouts.Load() != 1 {
		t.Fatalf("requests: auth=%d health=%d logout=%d", auths.Load(), healthReads.Load(), logouts.Load())
	}
}

func TestPiHoleHealthCheckSupportsSIDlessAPI(t *testing.T) {
	var logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":null}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/ftl":
			if r.Header.Get("X-FTL-SID") != "" {
				t.Error("SID sent when authentication is unnecessary")
			}
			_, _ = io.WriteString(w, `{"ftl":{"pid":12,"uptime":1000}}`)
		case r.Method == http.MethodDelete:
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := newPiHoleAPIClient(server.URL+"/api", "unused-password")
	if _, err := client.checkHealth(context.Background()); err != nil {
		t.Fatal(err)
	}
	if logouts.Load() != 0 {
		t.Fatalf("SID-less health check logged out: %d", logouts.Load())
	}
}

func TestPiHoleHealthReadFailureStillLogsOut(t *testing.T) {
	var logouts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"health-sid"}}`)
		case r.Method == http.MethodGet:
			http.Error(w, "failed", http.StatusServiceUnavailable)
		case r.Method == http.MethodDelete:
			logouts.Add(1)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.checkHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("health read failure = %v", err)
	}
	if logouts.Load() != 1 || !client.blockedUntil.IsZero() {
		t.Fatalf("logout=%d blockedUntil=%v", logouts.Load(), client.blockedUntil)
	}
}

func TestPiHoleHealthLogoutFailureBlocksNewSession(t *testing.T) {
	var auths atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"health-sid"}}`)
		case r.Method == http.MethodGet:
			_, _ = io.WriteString(w, `{"ftl":{"pid":12,"uptime":1000}}`)
		case r.Method == http.MethodDelete:
			http.Error(w, "failed", http.StatusInternalServerError)
		}
	}))
	defer server.Close()
	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.checkHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "logout") {
		t.Fatalf("health logout failure = %v", err)
	}
	if _, err := client.checkHealth(context.Background()); err == nil || !strings.Contains(err.Error(), "paused") || auths.Load() != 1 {
		t.Fatalf("health cleanup backoff err=%v auths=%d", err, auths.Load())
	}
}

func TestPiHoleAuthenticationRejectionAllowsImmediateRetryAndCorrelation(t *testing.T) {
	var auths atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			attempt := auths.Add(1)
			if attempt == 1 {
				http.Error(w, "denied", http.StatusUnauthorized)
				return
			}
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"test-sid"}}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/api/info/ftl":
			_, _ = io.WriteString(w, `{"ftl":{"pid":12,"uptime":1000}}`)
		case r.URL.Path == "/api/queries":
			_, _ = io.WriteString(w, `{"queries":[{"domain":"abc.example.com","status":"CACHE","reply":{"type":"NXDOMAIN","time":1}}]}`)
		case r.URL.Path == "/api/info/messages":
			_, _ = io.WriteString(w, `{"messages":[]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	if _, err := client.checkHealth(context.Background()); err == nil || !client.blockedUntil.IsZero() {
		t.Fatalf("definitive rejection err=%v blockedUntil=%v", err, client.blockedUntil)
	}
	if _, err := client.checkHealth(context.Background()); err != nil {
		t.Fatalf("immediate retry failed: %v", err)
	}
	evidence, err := client.correlate(context.Background(), time.Now(), "abc.example.com")
	if err != nil || !strings.Contains(evidence, "query=observed") || auths.Load() != 3 {
		t.Fatalf("correlation after rejection = %q, %v, auths=%d", evidence, err, auths.Load())
	}
}

func TestPiHoleHealthRouteStoresResultUntilRecheck(t *testing.T) {
	var auths atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"health-sid"}}`)
		case r.Method == http.MethodGet && r.URL.Path == "/api/info/ftl":
			_, _ = io.WriteString(w, `{"ftl":{"pid":44,"uptime":2000}}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	a := newTestApp(t)
	a.piholeAPI = newPiHoleAPIClient(server.URL+"/api", "app-password")
	cookie := login(t, a)
	s, ok := a.sessions.get(cookie.Value)
	if !ok {
		t.Fatal("login session missing")
	}
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/pihole-api-health", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), ">Healthy<") || !strings.Contains(result.Body.String(), "PID 44") {
		t.Fatalf("health response status=%d body=%s", result.Code, result.Body.String())
	}

	settings := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	settings.AddCookie(cookie)
	settingsResult := httptest.NewRecorder()
	a.Handler().ServeHTTP(settingsResult, settings)
	if settingsResult.Code != http.StatusOK || !strings.Contains(settingsResult.Body.String(), ">Healthy<") || !strings.Contains(settingsResult.Body.String(), "Last checked:") || auths.Load() != 1 {
		t.Fatalf("stored health status=%d body=%s auths=%d", settingsResult.Code, settingsResult.Body.String(), auths.Load())
	}
}

func TestPiHoleHealthRouteRequiresCSRF(t *testing.T) {
	var auths atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		auths.Add(1)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}))
	defer server.Close()
	a := newTestApp(t)
	client := newPiHoleAPIClient(server.URL+"/api", "app-password")
	a.piholeAPI = client
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodPost, "/ui/pihole-api-health", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	if result.Code != http.StatusForbidden || auths.Load() != 0 {
		t.Fatalf("CSRF failure status=%d auths=%d", result.Code, auths.Load())
	}
}

func TestPiHoleHealthRouteAllowsOnlyOneInFlightCheck(t *testing.T) {
	var auths atomic.Int32
	healthStarted := make(chan struct{})
	releaseHealth := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			auths.Add(1)
			_, _ = io.WriteString(w, `{"session":{"valid":true,"sid":"health-sid"}}`)
		case r.Method == http.MethodGet:
			close(healthStarted)
			<-releaseHealth
			_, _ = io.WriteString(w, `{"ftl":{"pid":55,"uptime":1000}}`)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer server.Close()
	a := newTestApp(t)
	a.piholeAPI = newPiHoleAPIClient(server.URL+"/api", "app-password")
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}}
	newRequest := func() *http.Request {
		request := httptest.NewRequest(http.MethodPost, "/ui/pihole-api-health", strings.NewReader(form.Encode()))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		request.AddCookie(cookie)
		return request
	}
	firstResult := httptest.NewRecorder()
	firstDone := make(chan struct{})
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	go func() {
		a.Handler().ServeHTTP(firstResult, newRequest().WithContext(leaderCtx))
		close(firstDone)
	}()
	<-healthStarted
	secondResult := httptest.NewRecorder()
	secondDone := make(chan struct{})
	go func() {
		a.Handler().ServeHTTP(secondResult, newRequest())
		close(secondDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		a.piholeHealthMu.RLock()
		waiters := 0
		if a.piholeCheck != nil {
			waiters = a.piholeCheck.waiters
		}
		a.piholeHealthMu.RUnlock()
		if waiters == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("duplicate check did not wait for active result")
		}
		time.Sleep(time.Millisecond)
	}
	cancelLeader()
	close(releaseHealth)
	<-firstDone
	<-secondDone
	if firstResult.Code != http.StatusOK || !strings.Contains(firstResult.Body.String(), ">Healthy<") || auths.Load() != 1 {
		t.Fatalf("first check status=%d body=%s auths=%d", firstResult.Code, firstResult.Body.String(), auths.Load())
	}
	if secondResult.Code != http.StatusOK || !strings.Contains(secondResult.Body.String(), ">Healthy<") || auths.Load() != 1 {
		t.Fatalf("duplicate check status=%d body=%s auths=%d", secondResult.Code, secondResult.Body.String(), auths.Load())
	}
}

func TestPiHoleHealthCompletedViewUsesGenerationSnapshot(t *testing.T) {
	a := newTestApp(t)
	a.piholeAPI = newPiHoleAPIClient("http://127.0.0.1:1/api", "app-password")
	completed := piHoleHealthStatus{State: "healthy", Message: "first generation", CheckedAt: time.Now()}
	a.piholeHealth = piHoleHealthStatus{State: "checking", Message: "second generation"}
	view := a.piHoleHealthViewForStatus("csrf", completed)
	if view.State != "Healthy" || view.Message != "first generation" || view.Checking {
		t.Fatalf("completed generation rendered as %+v", view)
	}
}

func TestPiHoleSettingsDuringCheckCanJoinResult(t *testing.T) {
	a := newTestApp(t)
	a.piholeAPI = newPiHoleAPIClient("http://127.0.0.1:1/api", "app-password")
	a.piholeHealth = piHoleHealthStatus{State: "checking"}
	a.piholeCheck = &piHoleHealthCheck{done: make(chan struct{})}
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">Wait for result<") || strings.Contains(body, "disabled>Wait for result") {
		t.Fatalf("in-flight settings status=%d body=%s", result.Code, body)
	}
}

func TestPiHoleClientLockHonorsCancellation(t *testing.T) {
	client := newPiHoleAPIClient("http://127.0.0.1:1/api", "app-password")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.checkHealth(ctx); !errors.Is(err, context.Canceled) || len(client.gate) != 1 || !client.blockedUntil.IsZero() {
		t.Fatalf("available lock cancellation err=%v gate=%d blocked=%v", err, len(client.gate), client.blockedUntil)
	}

	<-client.gate
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := client.checkHealth(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("lock cancellation = %v", err)
	}
	client.gate <- struct{}{}
}

func TestPiHoleHealthRouteStoresFailureWithoutSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "denied", http.StatusUnauthorized)
	}))
	defer server.Close()
	a := newTestApp(t)
	a.piholeAPI = newPiHoleAPIClient(server.URL+"/api", "secret-app-password")
	cookie := login(t, a)
	s, _ := a.sessions.get(cookie.Value)
	form := url.Values{"csrf": {s.CSRF}}
	request := httptest.NewRequest(http.MethodPost, "/ui/pihole-api-health", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">Failed<") || !strings.Contains(body, "HTTP 401") || strings.Contains(body, "secret-app-password") {
		t.Fatalf("failed health response status=%d body=%s", result.Code, body)
	}
}

func TestPiHoleHealthRendersDisabledWhenUnconfigured(t *testing.T) {
	a := newTestApp(t)
	cookie := login(t, a)
	request := httptest.NewRequest(http.MethodGet, "/ui/settings", nil)
	request.AddCookie(cookie)
	result := httptest.NewRecorder()
	a.Handler().ServeHTTP(result, request)
	body := result.Body.String()
	if result.Code != http.StatusOK || !strings.Contains(body, ">Not configured<") || !strings.Contains(body, "button class=\"quiet\" type=\"submit\" disabled") {
		t.Fatalf("unconfigured health status=%d body=%s", result.Code, body)
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
	if _, err := client.checkHealth(context.Background()); err == nil || auths.Load() != 2 || logouts.Load() != 2 {
		t.Fatalf("cleaned malformed session retry err=%v auths=%d logouts=%d", err, auths.Load(), logouts.Load())
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
