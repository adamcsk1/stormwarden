package app

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	mailCadenceKey  = "mail_cadence"
	mailShot2Secs   = 8 * 3600
	mailShot3Secs   = 4 * 3600
	mailDailySecs   = 24 * 3600
	mailRetrySecs   = 15 * 60
	mailSMTPTimeout = 30 * time.Second
)

var mailCategories = map[string]bool{
	"internet_outage":        true,
	"wan_or_isp_packet_loss": true,
	"host_or_nic":            true,
	"local_network_or_host":  true,
	"external_dns":           true,
	"dns_resolution_failure": true,
	"local_dns":              true,
	"radio_poor":             true,
}

type mailShot struct {
	FirstSeen   int64   `json:"first_seen"`
	Sent        int     `json:"sent"`
	LastSent    int64   `json:"last_sent"`
	LastAttempt int64   `json:"last_attempt"`
	Summary     string  `json:"summary,omitempty"`
	Times       []int64 `json:"times,omitempty"`
}

type mailIssue struct {
	Summary   string
	StartedAt int64
}

type mailState struct {
	Issues map[string]mailShot `json:"issues"`
}

func (c Config) smtpEnabled() bool {
	return c.SMTPHost != "" && c.SMTPTo != ""
}

func smtpRecipients(to string) []string {
	var out []string
	for _, part := range strings.Split(to, ",") {
		part = strings.TrimSpace(sanitizeHeader(part))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func mailKey(inc Incident) string {
	if severityRank(inc.Severity) < severityRank(Error) {
		return ""
	}
	if mailCategories[inc.Category] {
		return inc.Category
	}
	class := parseEvidenceDoc(inc.Evidence).Classification
	if mailCategories[class] {
		return class
	}
	return ""
}

func collectMailIssues(incidents []Incident) map[string]mailIssue {
	type hit struct {
		rank      int
		summary   string
		startedAt int64
	}
	best := map[string]hit{}
	for _, inc := range incidents {
		key := mailKey(inc)
		if key == "" {
			continue
		}
		rank := severityRank(inc.Severity)
		if prev, ok := best[key]; ok && prev.rank >= rank {
			continue
		}
		started := inc.StartedAt.Unix()
		if inc.StartedAt.IsZero() {
			started = 0
		}
		best[key] = hit{rank, inc.Summary, started}
	}
	out := make(map[string]mailIssue, len(best))
	for key, hit := range best {
		out[key] = mailIssue{Summary: hit.summary, StartedAt: hit.startedAt}
	}
	return out
}

func mailDue(rec mailShot, now int64) bool {
	switch {
	case rec.Sent == 0:
		return true
	case rec.Sent == 1 && now-rec.FirstSeen >= mailShot2Secs:
		return true
	case rec.Sent == 2 && now-rec.LastSent >= mailShot3Secs:
		return true
	case rec.Sent >= 3 && now-rec.LastSent >= mailDailySecs:
		return true
	default:
		return false
	}
}

func syncMailState(current map[string]mailIssue, prev mailState, now int64) (due []string, next mailState) {
	next.Issues = map[string]mailShot{}
	for key, issue := range current {
		rec, ok := prev.Issues[key]
		if !ok {
			rec = mailShot{FirstSeen: now}
		}
		if issue.Summary != "" {
			rec.Summary = issue.Summary
		}
		rec.Times = appendMailTime(rec.Times, issue.StartedAt)
		next.Issues[key] = rec
		if mailDue(rec, now) {
			due = append(due, key)
		}
	}
	for key, rec := range prev.Issues {
		if _, ok := current[key]; ok {
			continue
		}
		if !mailPending(rec) {
			continue
		}
		next.Issues[key] = rec
		if mailDue(rec, now) {
			due = append(due, key)
		}
	}
	sort.Strings(due)
	return due, next
}

func mailPending(rec mailShot) bool {
	return rec.Sent == 0 || rec.LastAttempt > rec.LastSent
}

const mailTimeCap = 20

func appendMailTime(times []int64, started int64) []int64 {
	if started <= 0 {
		return times
	}
	for _, t := range times {
		if t == started {
			return times
		}
	}
	times = append(times, started)
	if len(times) > mailTimeCap {
		// ponytail: cap 20 occurrence times; drop oldest if SMTP stays down through a flap storm
		times = append([]int64(nil), times[len(times)-mailTimeCap:]...)
	}
	return times
}

func filterMailRetry(due []string, state mailState, now int64) []string {
	out := due[:0]
	for _, key := range due {
		rec := state.Issues[key]
		if rec.LastAttempt > rec.LastSent && now-rec.LastAttempt < mailRetrySecs {
			continue
		}
		out = append(out, key)
	}
	return out
}

func markMailSent(state *mailState, keys []string, now int64) {
	if state.Issues == nil {
		state.Issues = map[string]mailShot{}
	}
	for _, key := range keys {
		rec := state.Issues[key]
		rec.Sent++
		rec.LastSent = now
		rec.LastAttempt = now
		for rec.FirstSeen > 0 && mailDue(rec, now) {
			rec.Sent++
			rec.LastSent = now
			rec.LastAttempt = now
		}
		state.Issues[key] = rec
	}
}

func markMailAttempt(state *mailState, keys []string, now int64) {
	if state.Issues == nil {
		state.Issues = map[string]mailShot{}
	}
	for _, key := range keys {
		rec := state.Issues[key]
		rec.LastAttempt = now
		state.Issues[key] = rec
	}
}

func loadMailState(ctx context.Context, db *sql.DB) (mailState, error) {
	raw, err := setting(ctx, db, mailCadenceKey)
	if errors.Is(err, sql.ErrNoRows) || raw == "" {
		return mailState{Issues: map[string]mailShot{}}, nil
	}
	if err != nil {
		return mailState{}, err
	}
	var state mailState
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return mailState{}, err
	}
	if state.Issues == nil {
		state.Issues = map[string]mailShot{}
	}
	return state, nil
}

func saveMailState(ctx context.Context, db *sql.DB, state mailState) error {
	if state.Issues == nil {
		state.Issues = map[string]mailShot{}
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return setSetting(ctx, db, mailCadenceKey, string(raw))
}

func sanitizeHeader(value string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return ' '
		}
		return r
	}, value)
}

const mailTimeLayout = "2006-01-02 15:04:05 UTC"

func formatMail(host string, now time.Time, state mailState, due, delayed []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "stormwarden on %s\n%s\n\n", host, now.UTC().Format(mailTimeLayout))
	writeProblemTimes(&b, state, delayed, len(due) == 1)
	b.WriteString("ISSUES:\n")
	for _, key := range due {
		fmt.Fprintf(&b, "- %s: %s\n", key, state.Issues[key].Summary)
	}
	return b.String()
}

func delayedMailKeys(state mailState, current map[string]mailIssue, due []string) []string {
	var out []string
	for _, key := range due {
		rec := state.Issues[key]
		_, open := current[key]
		if rec.LastAttempt > rec.LastSent || !open {
			out = append(out, key)
		}
	}
	return out
}

func writeProblemTimes(b *strings.Builder, state mailState, delayed []string, singleIssue bool) {
	if len(delayed) == 0 {
		return
	}
	if len(delayed) == 1 && singleIssue {
		times := shotTimes(state.Issues[delayed[0]])
		if len(times) == 0 {
			return
		}
		fmt.Fprintf(b, "Problem time was %s.\n", formatMailTime(times[0]))
		if len(times) > 1 {
			b.WriteString("Happened:\n")
			for _, t := range times {
				fmt.Fprintf(b, "- %s\n", formatMailTime(t))
			}
		}
		b.WriteString("\n")
		return
	}
	b.WriteString("Problem times:\n")
	for _, key := range delayed {
		times := shotTimes(state.Issues[key])
		if len(times) == 0 {
			continue
		}
		parts := make([]string, len(times))
		for i, t := range times {
			parts[i] = formatMailTime(t)
		}
		fmt.Fprintf(b, "- %s: %s\n", key, strings.Join(parts, ", "))
	}
	b.WriteString("\n")
}

func shotTimes(rec mailShot) []int64 {
	if len(rec.Times) == 0 {
		if rec.FirstSeen <= 0 {
			return nil
		}
		return []int64{rec.FirstSeen}
	}
	out := append([]int64(nil), rec.Times...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func formatMailTime(unix int64) string {
	return time.Unix(unix, 0).UTC().Format(mailTimeLayout)
}

func formatSMTPMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", sanitizeHeader(from))
	fmt.Fprintf(&b, "To: %s\r\n", sanitizeHeader(to))
	fmt.Fprintf(&b, "Subject: %s\r\n", sanitizeHeader(subject))
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n")
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

func sendSMTP(cfg Config, subject, body string) error {
	recipients := smtpRecipients(cfg.SMTPTo)
	if cfg.SMTPHost == "" || len(recipients) == 0 {
		return errors.New("SMTP_HOST and SMTP_TO required to send mail")
	}
	from := strings.TrimSpace(sanitizeHeader(cfg.SMTPFrom))
	if from == "" {
		from = strings.TrimSpace(sanitizeHeader(cfg.SMTPUser))
	}
	if from == "" {
		from = recipients[0]
	}
	addr := net.JoinHostPort(cfg.SMTPHost, strconv.Itoa(cfg.SMTPPort))
	tlsCfg := &tls.Config{ServerName: cfg.SMTPHost, MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.SMTPInsecureSkipVerify}
	dialer := &net.Dialer{Timeout: mailSMTPTimeout}
	var conn net.Conn
	var err error
	if cfg.SMTPSSL {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(mailSMTPTimeout))
	client, err := smtp.NewClient(conn, cfg.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return err
	}
	defer client.Close()
	if cfg.SMTPStartTLS && !cfg.SMTPSSL {
		if err := client.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if cfg.SMTPUser != "" {
		if err := client.Auth(smtp.PlainAuth("", cfg.SMTPUser, cfg.SMTPPassword, cfg.SMTPHost)); err != nil {
			return err
		}
	}
	if err := client.Mail(from); err != nil {
		return err
	}
	for _, to := range recipients {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(formatSMTPMessage(from, cfg.SMTPTo, subject, body)); err != nil {
		_ = writer.Close()
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func redactSMTPErr(err error, password string) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if password != "" {
		msg = strings.ReplaceAll(msg, password, "***")
	}
	return msg
}

func mailHost() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "stormwarden"
	}
	return host
}

func (a *App) sendTestMail() error {
	if !a.cfg.smtpEnabled() {
		return errors.New("not configured")
	}
	a.mailMu.Lock()
	defer a.mailMu.Unlock()
	body := fmt.Sprintf("stormwarden on %s\nSMTP test.\n", mailHost())
	send := a.sendMail
	if send == nil {
		send = func(subject, body string) error { return sendSMTP(a.cfg, subject, body) }
	}
	return send("[stormwarden] test email", body)
}

func (a *App) queueMail() {
	if !a.cfg.smtpEnabled() {
		return
	}
	if !a.mailMu.TryLock() {
		return
	}
	go func() {
		defer a.mailMu.Unlock()
		defer func() {
			if rec := recover(); rec != nil {
				a.logger.Error("mail send panicked", "panic", fmt.Sprint(rec))
			}
		}()
		ctx, cancel := context.WithTimeout(context.Background(), mailSMTPTimeout+5*time.Second)
		defer cancel()
		a.sendDueMail(ctx, time.Now())
	}()
}

func (a *App) sendDueMail(ctx context.Context, now time.Time) {
	if !a.cfg.smtpEnabled() {
		return
	}
	incidents, err := activeIncidents(ctx, a.db)
	if err != nil {
		a.logger.Error("mail incident lookup failed", "error", err)
		return
	}
	current := collectMailIssues(incidents)
	state, err := loadMailState(ctx, a.db)
	if err != nil {
		a.logger.Error("mail cadence state invalid", "error", err)
		return
	}
	unix := now.Unix()
	due, next := syncMailState(current, state, unix)
	due = filterMailRetry(due, next, unix)
	if len(due) == 0 {
		if len(next.Issues) == 0 && len(state.Issues) == 0 {
			return
		}
		if err := saveMailState(ctx, a.db, next); err != nil {
			a.logger.Error("mail cadence save failed", "error", err)
		}
		return
	}
	host := mailHost()
	subject := fmt.Sprintf("[stormwarden] %d issue(s)", len(due))
	delayed := delayedMailKeys(next, current, due)
	body := formatMail(host, now, next, due, delayed)
	send := a.sendMail
	if send == nil {
		send = func(subject, body string) error { return sendSMTP(a.cfg, subject, body) }
	}
	if err := send(subject, body); err != nil {
		markMailAttempt(&next, due, unix)
		if saveErr := saveMailState(ctx, a.db, next); saveErr != nil {
			a.logger.Error("mail cadence save failed", "error", saveErr)
		}
		a.logger.Error("SMTP submission failed; alert counters unchanged", "error", redactSMTPErr(err, a.cfg.SMTPPassword))
		return
	}
	markMailSent(&next, due, unix)
	for key, rec := range next.Issues {
		if _, open := current[key]; open || mailPending(rec) {
			continue
		}
		delete(next.Issues, key)
	}
	if err := saveMailState(ctx, a.db, next); err != nil {
		a.logger.Error("mail cadence save failed", "error", err)
	}
	a.logger.Info("SMTP submission accepted", "issues", len(due))
}
