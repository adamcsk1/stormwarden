package app

import (
	"archive/zip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http/httptrace"
	"sync"
	"time"
)

// Only allowlisted values belong here: never copy errors, URLs or response text.
type teltonikaDiagnostic struct {
	CreatedAt   time.Time `json:"created_at"`
	Operation   string    `json:"operation"`
	Trigger     string    `json:"trigger"`
	Stage       string    `json:"stage"`
	Result      string    `json:"result"`
	Status      int       `json:"http_status,omitempty"`
	ElapsedMS   float64   `json:"elapsed_ms"`
	LockWaitMS  float64   `json:"lock_wait_ms"`
	TimeoutMS   float64   `json:"timeout_ms"`
	Reused      bool      `json:"connection_reused"`
	TCPMS       *float64  `json:"tcp_ms,omitempty"`
	TLSMS       *float64  `json:"tls_ms,omitempty"`
	FirstByteMS *float64  `json:"first_byte_ms,omitempty"`
}

type teltonikaAttemptKey struct{}
type teltonikaAttempt struct {
	trigger  string
	lockWait time.Duration
	records  []teltonikaDiagnostic
}

func teltonikaErrorCategory(err error) string {
	if err == nil {
		return "ok"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timeout"
	}
	if errors.Is(err, context.Canceled) {
		return "canceled"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	var status teltonikaHTTPError
	if errors.As(err, &status) {
		return fmt.Sprintf("http_%d", int(status))
	}
	return "request_failed"
}

// Trace callbacks may run concurrently, including after Do returns.
func traceTeltonika(ctx context.Context, operation string) (context.Context, func(int, error) teltonikaDiagnostic) {
	start := time.Now()
	d := teltonikaDiagnostic{CreatedAt: start.UTC(), Operation: operation, Stage: "connection", TimeoutMS: float64(teltonikaHTTPTimeout.Milliseconds())}
	if attempt, ok := ctx.Value(teltonikaAttemptKey{}).(*teltonikaAttempt); ok {
		d.Trigger, d.LockWaitMS = attempt.trigger, float64(attempt.lockWait)/float64(time.Millisecond)
	}
	if deadline, ok := ctx.Deadline(); ok {
		d.TimeoutMS = min(d.TimeoutMS, max(0, float64(time.Until(deadline))/float64(time.Millisecond)))
	}
	var mu sync.Mutex
	var tcpStart, tlsStart time.Time
	set := func(f func()) { mu.Lock(); defer mu.Unlock(); f() }
	duration := func(start time.Time) *float64 { v := float64(time.Since(start)) / float64(time.Millisecond); return &v }
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { set(func() { d.Stage = "dns" }) },
		ConnectStart:      func(_, _ string) { set(func() { d.Stage = "tcp_connect"; tcpStart = time.Now() }) },
		ConnectDone:       func(_, _ string, _ error) { set(func() { d.TCPMS = duration(tcpStart) }) },
		TLSHandshakeStart: func() { set(func() { d.Stage = "tls_handshake"; tlsStart = time.Now() }) },
		TLSHandshakeDone:  func(_ tls.ConnectionState, _ error) { set(func() { d.TLSMS = duration(tlsStart) }) },
		GotConn:           func(info httptrace.GotConnInfo) { set(func() { d.Reused = info.Reused; d.Stage = "write_request" }) },
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			set(func() {
				if info.Err == nil {
					d.Stage = "response_headers"
				}
			})
		},
		GotFirstResponseByte: func() { set(func() { d.FirstByteMS = duration(start) }) },
	}
	return httptrace.WithClientTrace(ctx, trace), func(status int, err error) teltonikaDiagnostic {
		mu.Lock()
		defer mu.Unlock()
		result := d
		result.Status, result.Result = status, teltonikaErrorCategory(err)
		result.ElapsedMS = float64(time.Since(start)) / float64(time.Millisecond)
		if status != 0 {
			result.Stage = "response_body"
		}
		var httpErr teltonikaHTTPError
		if errors.As(err, &httpErr) {
			result.Result = "http_error"
			result.Stage = "complete"
		}
		if err == nil {
			result.Stage = "complete"
		}
		return result
	}
}

func (a *App) recordTeltonikaDiagnostic(d teltonikaDiagnostic) {
	a.logger.Info("teltonika request", "diagnostic", d)
	raw, err := json.Marshal(d)
	if err != nil {
		return
	}
	// Request context often expired; persist with a separate bounded context.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	a.dataMu.RLock()
	defer a.dataMu.RUnlock()
	if _, err := a.db.ExecContext(ctx, `INSERT INTO teltonika_diagnostics(created_at, record) VALUES (?, ?)`, dbTime(d.CreatedAt), string(raw)); err != nil {
		a.logger.Error("teltonika diagnostic persistence failed")
	}
}

func zipTeltonikaDiagnostics(ctx context.Context, tx *sql.Tx, zw *zip.Writer, from, to string) error {
	w, err := zw.Create("teltonika-diagnostics.jsonl")
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT record FROM teltonika_diagnostics WHERE created_at>=? AND created_at<? ORDER BY created_at, id`, from, to)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if _, err := w.Write([]byte(raw + "\n")); err != nil {
			return err
		}
	}
	return rows.Err()
}
