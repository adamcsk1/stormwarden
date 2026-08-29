package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed web/templates/*.html web/static/*
var webFiles embed.FS

type session struct {
	CSRF      string
	ExpiresAt time.Time
}

type sessionStore struct {
	mu    sync.RWMutex
	items map[string]session
}

func newSessionStore() *sessionStore { return &sessionStore{items: make(map[string]session)} }

func (s *sessionStore) create() (string, session, error) {
	token, err := randomToken()
	if err != nil {
		return "", session{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return "", session{}, err
	}
	value := session{CSRF: csrf, ExpiresAt: time.Now().Add(24 * time.Hour)}
	s.mu.Lock()
	s.items[token] = value
	s.mu.Unlock()
	return token, value, nil
}

func (s *sessionStore) get(token string) (session, bool) {
	s.mu.RLock()
	value, ok := s.items[token]
	s.mu.RUnlock()
	return value, ok && time.Now().Before(value.ExpiresAt)
}

func (s *sessionStore) delete(token string) { s.mu.Lock(); delete(s.items, token); s.mu.Unlock() }
func (s *sessionStore) cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for token, item := range s.items {
		if time.Now().After(item.ExpiresAt) {
			delete(s.items, token)
		}
	}
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

type loginAttempt struct {
	failures                  int
	windowStart, blockedUntil time.Time
}
type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string]loginAttempt
}

func newLoginLimiter() *loginLimiter { return &loginLimiter{attempts: make(map[string]loginAttempt)} }
func (l *loginLimiter) makeRoom(ip string) {
	if _, exists := l.attempts[ip]; exists || len(l.attempts) < 1000 {
		return
	}
	var oldestKey string
	var oldest time.Time
	for key, attempt := range l.attempts {
		if oldestKey == "" || attempt.windowStart.Before(oldest) {
			oldestKey, oldest = key, attempt.windowStart
		}
	}
	delete(l.attempts, oldestKey)
}
func (l *loginLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	item := l.attempts[ip]
	if now.Sub(item.windowStart) > 10*time.Minute {
		delete(l.attempts, ip)
		return true
	}
	return !now.Before(item.blockedUntil)
}
func (l *loginLimiter) failure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.makeRoom(ip)
	now := time.Now()
	item := l.attempts[ip]
	if item.windowStart.IsZero() || now.Sub(item.windowStart) > 10*time.Minute {
		item = loginAttempt{windowStart: now}
	}
	item.failures++
	if item.failures >= 5 {
		shift := min(item.failures-5, 8)
		item.blockedUntil = now.Add(time.Second * time.Duration(1<<shift))
	}
	l.attempts[ip] = item
}
func (l *loginLimiter) success(ip string) { l.mu.Lock(); delete(l.attempts, ip); l.mu.Unlock() }
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

type contextKey string

const sessionContextKey contextKey = "session"

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	staticFS, _ := fs.Sub(webFiles, "web/static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.Handle("GET /", a.requireAuth(http.HandlerFunc(a.dashboard)))
	mux.Handle("POST /logout", a.requireAuth(http.HandlerFunc(a.logout)))
	mux.Handle("GET /ui/summary", a.requireAuth(http.HandlerFunc(a.summaryFragment)))
	mux.Handle("GET /ui/metrics", a.requireAuth(http.HandlerFunc(a.metricsFragment)))
	mux.Handle("GET /ui/dns-paths", a.requireAuth(http.HandlerFunc(a.dnsPathsFragment)))
	mux.Handle("GET /ui/assets", a.requireAuth(http.HandlerFunc(a.assetsFragment)))
	mux.Handle("GET /ui/incidents", a.requireAuth(http.HandlerFunc(a.incidentsFragment)))
	mux.Handle("GET /ui/incidents/{id}", a.requireAuth(http.HandlerFunc(a.incidentDetailFragment)))
	mux.Handle("GET /ui/layers", a.requireAuth(http.HandlerFunc(a.layersFragment)))
	mux.Handle("GET /ui/compare", a.requireAuth(http.HandlerFunc(a.compareFragment)))
	mux.Handle("POST /ui/annotations", a.requireAuth(http.HandlerFunc(a.createAnnotation)))
	mux.Handle("GET /ui/settings", a.requireAuth(http.HandlerFunc(a.settingsFragment)))
	mux.Handle("POST /ui/settings", a.requireAuth(http.HandlerFunc(a.saveSettings)))
	mux.Handle("POST /ui/clear-data", a.requireAuth(http.HandlerFunc(a.clearData)))
	mux.Handle("POST /ui/pihole-api-health", a.requireAuth(http.HandlerFunc(a.checkPiHoleAPIHealth)))
	mux.Handle("GET /ui/exports", a.requireAuth(http.HandlerFunc(a.exportsFragment)))
	mux.Handle("POST /ui/exports", a.requireAuth(http.HandlerFunc(a.createExport)))
	mux.Handle("GET /exports/{id}/download", a.requireAuth(http.HandlerFunc(a.downloadExport)))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

func (a *App) health(w http.ResponseWriter, r *http.Request) {
	if err := a.db.PingContext(r.Context()); err != nil {
		http.Error(w, "database unavailable", http.StatusServiceUnavailable)
		return
	}
	a.healthMu.RLock()
	lastPersist, persistErr := a.lastPersist, a.lastPersistErr
	a.healthMu.RUnlock()
	if time.Since(a.startedAt) > time.Minute && (lastPersist.IsZero() || time.Since(lastPersist) > time.Minute) {
		message := "probe scheduler has not persisted a cycle recently"
		if persistErr != nil {
			message += ": " + persistErr.Error()
		}
		http.Error(w, message, http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("ok\n"))
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requestSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, "login.html", map[string]any{"Error": r.URL.Query().Get("error") != ""})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !a.loginLimiter.allow(ip) {
		w.Header().Set("Retry-After", "2")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	want, got := sha256.Sum256([]byte(a.cfg.Password)), sha256.Sum256([]byte(r.FormValue("password")))
	if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
		a.loginLimiter.failure(ip)
		http.Redirect(w, r, "/login?error=1", http.StatusSeeOther)
		return
	}
	token, _, err := a.sessions.create()
	if err != nil {
		http.Error(w, "secure session creation failed", http.StatusInternalServerError)
		return
	}
	a.loginLimiter.success(ip)
	http.SetCookie(w, &http.Cookie{Name: "ia_session", Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.cfg.CookieSecure, MaxAge: 86400})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if !a.validCSRF(r) {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie("ia_session"); err == nil {
		a.sessions.delete(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "ia_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: a.cfg.CookieSecure})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.requestSession(r)
		if !ok {
			if strings.HasPrefix(r.URL.Path, "/ui/") {
				http.Error(w, "session expired", http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), sessionContextKey, s)))
	})
}

func (a *App) requestSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie("ia_session")
	if err != nil {
		return session{}, false
	}
	return a.sessions.get(cookie.Value)
}

func (a *App) validCSRF(r *http.Request) bool {
	s, ok := r.Context().Value(sessionContextKey).(session)
	if !ok {
		return false
	}
	want, got := sha256.Sum256([]byte(s.CSRF)), sha256.Sum256([]byte(r.FormValue("csrf")))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, "dashboard.html", map[string]any{"CSRF": s.CSRF})
}

func (a *App) summaryFragment(w http.ResponseWriter, r *http.Request) {
	summary, err := a.dashboardSummary(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, "summary.html", summary)
}

func (a *App) dashboardSummary(ctx context.Context) (DashboardSummary, error) {
	s := DashboardSummary{Severity: Info, Status: "Collecting data", Availability24: 100}
	cutoff := dbTime(time.Now().Add(-24 * time.Hour))
	var total, successful int
	err := a.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(success),0)
FROM samples WHERE probe_type='aggregate' AND created_at >= ?`, cutoff).Scan(&total, &successful)
	if err != nil {
		return s, err
	}
	if total > 0 {
		s.Availability24 = float64(successful) * 100 / float64(total)
	}
	err = a.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(severity='warning'),0), COALESCE(SUM(severity='error'),0), COALESCE(SUM(severity='critical'),0)
FROM incidents WHERE started_at>=? OR ended_at IS NULL OR ended_at>=?`, cutoff, cutoff).Scan(&s.Warnings24, &s.Errors24, &s.Critical24)
	if err != nil {
		return s, err
	}
	var last string
	var severity Severity
	if err := a.db.QueryRowContext(ctx, `SELECT created_at, severity FROM samples WHERE probe_type='aggregate' ORDER BY id DESC LIMIT 1`).Scan(&last, &severity); err == nil {
		s.LastSampleAt, _ = parseDBTime(last)
		s.Severity, s.Status = severity, "Internet healthy"
	}
	s.ActiveIncident, err = activeIncident(ctx, a.db)
	if s.ActiveIncident != nil {
		s.Severity, s.Status = s.ActiveIncident.Severity, s.ActiveIncident.Summary
	}
	return s, err
}

func (a *App) metricsFragment(w http.ResponseWriter, r *http.Request) {
	samples, err := recentSamples(r.Context(), a.db, time.Now().Add(-time.Hour), 100)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	a.render(w, "metrics.html", map[string]any{"Samples": samples})
}

type dnsPathView struct {
	Label  string
	Sample *Sample
	Stale  bool
}

func (a *App) dnsPathsFragment(w http.ResponseWriter, r *http.Request) {
	definitions := []struct{ target, label string }{
		{"pihole", "Pi-hole TCP"},
		{"pihole-udp", "Pi-hole UDP"},
		{"public-dns", "Direct UDP"},
		{"direct-doh", "Direct DoH"},
	}
	paths := make([]dnsPathView, 0, len(definitions))
	for _, definition := range definitions {
		sample, err := latestSampleByTarget(r.Context(), a.db, definition.target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		paths = append(paths, dnsPathView{Label: definition.label, Sample: sample, Stale: sample != nil && time.Since(sample.CreatedAt) > 45*time.Second})
	}
	a.render(w, "dns-paths.html", map[string]any{"Paths": paths})
}

type assetPathView struct {
	Name     string
	Interval string
	Sample   *Sample
	Stale    bool
}

func (a *App) assetsFragment(w http.ResponseWriter, r *http.Request) {
	configured, _ := setting(r.Context(), a.db, "asset_targets")
	targets, err := parseAssetTargets(configured)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	assets := make([]assetPathView, 0, len(targets))
	for _, target := range targets {
		sample, err := latestSampleByTarget(r.Context(), a.db, assetSampleTarget(target))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		interval, staleAfter := "every 30s", 75*time.Second
		if target.CacheBust {
			interval, staleAfter = "every 5m · cache-busted", 11*time.Minute
		}
		assets = append(assets, assetPathView{Name: target.Name, Interval: interval, Sample: sample, Stale: sample != nil && time.Since(sample.CreatedAt) > staleAfter})
	}
	a.render(w, "assets.html", map[string]any{"Assets": assets})
}

func (a *App) incidentsFragment(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 0 {
		page = 0
	}
	incidents, hasMore, err := incidentPage(r.Context(), a.db, 50, page*50)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	views := make([]incidentView, 0, len(incidents))
	for _, incident := range incidents {
		views = append(views, a.toIncidentView(incident, false))
	}
	a.render(w, "incidents.html", map[string]any{"Incidents": views, "DisplayPage": page + 1, "Previous": page > 0, "PreviousPage": max(page-1, 0), "Next": hasMore, "NextPage": page + 1})
}

type incidentView struct {
	Incident
	EvidenceItems      []string
	ContradictionItems []string
	Events             string
	Timeline           []string
}

func (a *App) toIncidentView(incident Incident, withTimeline bool) incidentView {
	view := incidentView{Incident: incident}
	doc := parseEvidenceDoc(incident.Evidence)
	view.EvidenceItems, view.ContradictionItems = doc.Evidence, doc.Contradictions
	if len(doc.Contradictions) == 0 && incident.Contradictions != "" {
		view.ContradictionItems = strings.Split(incident.Contradictions, "\n")
	}
	view.Events = strings.Join(doc.Events, "\n")
	if view.Events == "" && doc.Classification == "" {
		view.Events = incident.Evidence
	}
	if withTimeline {
		end := time.Now()
		if incident.EndedAt != nil {
			end = incident.EndedAt.Add(30 * time.Second)
		}
		samples, _ := samplesBetween(context.Background(), a.db, incident.StartedAt.Add(-30*time.Second), end, 80)
		view.Timeline = formatTimeline(samples, a.cfg.Timezone)
	}
	return view
}

func formatTimeline(samples []Sample, loc *time.Location) []string {
	if loc == nil {
		loc = time.UTC
	}
	lines := make([]string, 0, len(samples))
	for _, s := range samples {
		state := strings.ToUpper(string(s.Severity))
		if s.Success && s.Severity == Info {
			state = "OK"
		}
		if s.ProbeType == "icmp-burst" && s.Mbps > 0 {
			state = "LOSS"
		}
		detail := fmt.Sprintf("%.0f ms", s.DurationMS)
		if s.ProbeType == "icmp-burst" && s.Mbps > 0 {
			detail = fmt.Sprintf("%.0f%%", s.Mbps)
		}
		if retransmissionSuspected(s.ConnectMS) || retransmissionSuspected(s.DurationMS) {
			detail += "  tcp_retransmission_suspected"
		}
		lines = append(lines, fmt.Sprintf("%s  %-22s %-8s %s", s.CreatedAt.In(loc).Format("15:04:05.000"), s.Target, state, detail))
	}
	return lines
}

func (a *App) incidentDetailFragment(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	incident, err := incidentByID(r.Context(), a.db, id)
	if err != nil || incident == nil {
		http.Error(w, "incident not found", http.StatusNotFound)
		return
	}
	a.render(w, "incident-detail.html", a.toIncidentView(*incident, true))
}

func (a *App) layersFragment(w http.ResponseWriter, r *http.Request) {
	type layer struct {
		Label  string
		Sample *Sample
		Stale  bool
	}
	defs := []struct{ target, label string }{
		{"icmp:pihole", "Pi-hole ping"},
		{"icmp:gateway", "Gateway ping"},
		{"icmp:isp_hop", "ISP hop ping"},
		{"icmp:internet", "Internet ping"},
	}
	layers := make([]layer, 0, len(defs)+6)
	for _, def := range defs {
		sample, err := latestSampleByTarget(r.Context(), a.db, def.target)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		layers = append(layers, layer{Label: def.label, Sample: sample, Stale: sample != nil && time.Since(sample.CreatedAt) > 10*time.Minute})
	}
	for _, control := range a.cfg.tcpControls() {
		sample, err := latestSampleByTarget(r.Context(), a.db, tcpSampleTarget(control.Name))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		layers = append(layers, layer{Label: "TCP " + control.Name, Sample: sample, Stale: sample != nil && time.Since(sample.CreatedAt) > 45*time.Second})
	}
	a.netMu.RLock()
	info := a.netInfo
	a.netMu.RUnlock()
	a.render(w, "layers.html", map[string]any{"Layers": layers, "Net": info})
}

func (a *App) compareFragment(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	rangeName := r.URL.Query().Get("range")
	var aFrom, aTo, bFrom, bTo time.Time
	labelA, labelB := "last 24h", "previous 24h"
	switch rangeName {
	case "week":
		aFrom, aTo = now.Add(-7*24*time.Hour), now
		bFrom, bTo = now.Add(-14*24*time.Hour), now.Add(-7*24*time.Hour)
		labelA, labelB = "this week", "previous week"
	default:
		rangeName = "24h"
		aFrom, aTo = now.Add(-24*time.Hour), now
		bFrom, bTo = now.Add(-48*time.Hour), now.Add(-24*time.Hour)
	}
	left, right := periodStats(r.Context(), a.db, aFrom, aTo), periodStats(r.Context(), a.db, bFrom, bTo)
	left.Label, right.Label = labelA, labelB
	a.render(w, "compare.html", map[string]any{"A": left, "B": right, "Range": rangeName})
}

func (a *App) createAnnotation(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	if err := insertAnnotation(r.Context(), a.db, r.FormValue("note")); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	r.URL.RawQuery = "saved=1"
	a.settingsFragment(w, r)
}

func (a *App) settingsFragment(w http.ResponseWriter, r *http.Request) {
	profile, _ := setting(r.Context(), a.db, "profile")
	assetTargets, _ := setting(r.Context(), a.db, "asset_targets")
	s := r.Context().Value(sessionContextKey).(session)
	a.netMu.RLock()
	info := a.netInfo
	a.netMu.RUnlock()
	notes, _ := recentAnnotations(r.Context(), a.db, 8)
	a.render(w, "settings.html", map[string]any{"Profile": profile, "AssetTargets": assetTargets, "CSRF": s.CSRF, "Saved": r.URL.Query().Get("saved") != "", "Cleared": r.URL.Query().Get("cleared") != "", "PiHoleHealth": a.piHoleHealthView(s.CSRF), "Net": info, "Annotations": notes})
}

func (a *App) clearData(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	if err := a.clearRecordedData(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	r.URL.RawQuery = "cleared=1"
	a.settingsFragment(w, r)
}

type piHoleHealthView struct {
	Configured bool
	State      string
	Severity   string
	Message    string
	CheckedAt  time.Time
	HasChecked bool
	Checking   bool
	CSRF       string
}

func (a *App) piHoleHealthView(csrf string) piHoleHealthView {
	view := piHoleHealthView{CSRF: csrf}
	if a.piholeAPI == nil {
		view.State, view.Severity, view.Message = "Not configured", "warning", "Set PIHOLE_API_URL and PIHOLE_API_PASSWORD, then restart Stormwarden."
		return view
	}
	a.piholeHealthMu.RLock()
	status := a.piholeHealth
	a.piholeHealthMu.RUnlock()
	return a.piHoleHealthViewForStatus(csrf, status)
}

func (a *App) piHoleHealthViewForStatus(csrf string, status piHoleHealthStatus) piHoleHealthView {
	view := piHoleHealthView{Configured: true, CSRF: csrf}
	view.CheckedAt, view.HasChecked = status.CheckedAt, !status.CheckedAt.IsZero()
	switch status.State {
	case "checking":
		view.Checking = true
		view.State, view.Severity, view.Message = "Checking", "warning", "Contacting Pi-hole API..."
	case "healthy":
		view.State, view.Severity, view.Message = "Healthy", "info", status.Message
	case "failed":
		view.State, view.Severity, view.Message = "Failed", "error", status.Message
	default:
		view.State, view.Severity, view.Message = "Not checked", "info", "Run a manual check to verify API authentication and FTL health."
	}
	return view
}

func (a *App) checkPiHoleAPIHealth(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	s := r.Context().Value(sessionContextKey).(session)
	if a.piholeAPI == nil {
		a.render(w, "pihole-api-health-content.html", a.piHoleHealthView(s.CSRF))
		return
	}
	a.piholeHealthMu.Lock()
	if a.piholeCheck != nil {
		check := a.piholeCheck
		check.waiters++
		a.piholeHealthMu.Unlock()
		defer func() {
			a.piholeHealthMu.Lock()
			check.waiters--
			a.piholeHealthMu.Unlock()
		}()
		select {
		case <-r.Context().Done():
			return
		case <-check.done:
		}
		a.render(w, "pihole-api-health-content.html", a.piHoleHealthViewForStatus(s.CSRF, check.status))
		return
	}
	check := &piHoleHealthCheck{done: make(chan struct{})}
	a.piholeCheck = check
	a.piholeHealth.State, a.piholeHealth.Message = "checking", ""
	a.piholeHealthMu.Unlock()
	checkCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	message, err := a.piholeAPI.checkHealth(checkCtx)
	checkedAt := time.Now()
	status := piHoleHealthStatus{State: "healthy", Message: message, CheckedAt: checkedAt}
	if err != nil {
		status.State, status.Message = "failed", "Pi-hole API check failed: "+err.Error()
	}
	a.piholeHealthMu.Lock()
	a.piholeHealth = status
	check.status = status
	a.piholeCheck = nil
	close(check.done)
	a.piholeHealthMu.Unlock()
	a.render(w, "pihole-api-health-content.html", a.piHoleHealthViewForStatus(s.CSRF, status))
}

func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 32*1024)
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	profile := r.FormValue("profile")
	if profile != "minimal" && profile != "low" && profile != "detailed" {
		http.Error(w, "invalid profile", http.StatusBadRequest)
		return
	}
	assetTargets := strings.TrimSpace(r.FormValue("asset_targets"))
	if _, err := parseAssetTargets(assetTargets); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.assetMu.Lock()
	a.incidentMu.Lock()
	defer a.assetMu.Unlock()
	defer a.incidentMu.Unlock()
	incidents, err := activeIncidents(r.Context(), a.db)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	configured, _ := parseAssetTargets(assetTargets)
	retained := make(map[string]bool, len(configured))
	for _, target := range configured {
		retained[assetIncidentCategory(target)] = true
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()
	for key, value := range map[string]string{"profile": profile, "asset_targets": assetTargets} {
		if _, err := tx.ExecContext(r.Context(), `INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	for _, incident := range incidents {
		if isAssetIncidentCategory(incident.Category) && !retained[incident.Category] {
			if _, err := tx.ExecContext(r.Context(), `UPDATE incidents SET ended_at=? WHERE id=? AND ended_at IS NULL`, dbTime(time.Now()), incident.ID); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}
	}
	if err := tx.Commit(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for category := range a.incidentStates {
		if isAssetIncidentCategory(category) && !retained[category] {
			delete(a.incidentStates, category)
		}
	}
	r.URL.RawQuery = "saved=1"
	a.settingsFragment(w, r)
}

func (a *App) render(w http.ResponseWriter, name string, data any) {
	funcs := template.FuncMap{
		"localTime": func(t time.Time) string {
			if t.IsZero() {
				return "Waiting for first probe"
			}
			return t.In(a.cfg.Timezone).Format("2006-01-02 15:04:05")
		},
		"duration": func(start time.Time) string { return time.Since(start).Round(time.Second).String() },
		"f1":       func(value float64) string { return strconv.FormatFloat(value, 'f', 1, 64) },
	}
	t, err := template.New("").Funcs(funcs).ParseFS(webFiles, "web/templates/*.html")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		a.logger.Error("template rendering failed", "template", name, "error", err)
	}
}
