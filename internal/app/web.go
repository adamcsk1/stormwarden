package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
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
	mux.Handle("GET /ui/incidents", a.requireAuth(http.HandlerFunc(a.incidentsFragment)))
	mux.Handle("GET /ui/settings", a.requireAuth(http.HandlerFunc(a.settingsFragment)))
	mux.Handle("POST /ui/settings", a.requireAuth(http.HandlerFunc(a.saveSettings)))
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
	var total, successful int
	err := a.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(success),0),
COALESCE(SUM(severity='warning'),0), COALESCE(SUM(severity='error'),0), COALESCE(SUM(severity='critical'),0)
FROM samples WHERE probe_type='aggregate' AND created_at >= ?`, dbTime(time.Now().Add(-24*time.Hour))).Scan(&total, &successful, &s.Warnings24, &s.Errors24, &s.Critical24)
	if err != nil {
		return s, err
	}
	if total > 0 {
		s.Availability24 = float64(successful) * 100 / float64(total)
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
	a.render(w, "incidents.html", map[string]any{"Incidents": incidents, "Page": page, "Previous": page > 0, "PreviousPage": max(page-1, 0), "Next": hasMore, "NextPage": page + 1})
}

func (a *App) settingsFragment(w http.ResponseWriter, r *http.Request) {
	profile, _ := setting(r.Context(), a.db, "profile")
	s := r.Context().Value(sessionContextKey).(session)
	a.render(w, "settings.html", map[string]any{"Profile": profile, "CSRF": s.CSRF, "Saved": r.URL.Query().Get("saved") != ""})
}

func (a *App) saveSettings(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || !a.validCSRF(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}
	profile := r.FormValue("profile")
	if profile != "minimal" && profile != "low" && profile != "detailed" {
		http.Error(w, "invalid profile", http.StatusBadRequest)
		return
	}
	if err := setSetting(r.Context(), a.db, "profile", profile); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
