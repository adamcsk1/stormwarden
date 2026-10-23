package app

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"testing"
	"time"
)

func TestTeltonikaDiagnosticStagesAndLateCallbacks(t *testing.T) {
	ctx, finish := traceTeltonika(context.Background(), "login")
	trace := httptrace.ContextClientTrace(ctx)
	trace.ConnectStart("tcp", "ignored-secret")
	if got := finish(0, context.DeadlineExceeded); got.Stage != "tcp_connect" || got.Result != "timeout" {
		t.Fatalf("TCP: %+v", got)
	}
	trace.ConnectDone("tcp", "ignored-secret", nil)
	trace.TLSHandshakeStart()
	if got := finish(0, context.DeadlineExceeded); got.Stage != "tls_handshake" {
		t.Fatalf("TLS: %+v", got)
	}
	trace.GotConn(httptrace.GotConnInfo{Reused: true})
	trace.WroteRequest(httptrace.WroteRequestInfo{})
	trace.GotFirstResponseByte()
	if got := finish(0, context.DeadlineExceeded); got.Stage != "response_headers" {
		t.Fatalf("headers: %+v", got)
	}
	if got := finish(200, context.DeadlineExceeded); got.Stage != "response_body" {
		t.Fatalf("body: %+v", got)
	}
	if got := finish(403, teltonikaHTTPError(403)); got.Result != "http_error" || got.Stage != "complete" || got.Status != 403 {
		t.Fatalf("HTTP: %+v", got)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			trace.GotFirstResponseByte()
		}
	}()
	for range 100 {
		_, _ = json.Marshal(finish(200, nil))
	}
	<-done
}

func TestTeltonikaDiagnosticTimeoutStage(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	c := newTeltonikaClient(Config{TeltonikaURL: srv.URL, TeltonikaInsecureSkipVerify: true})
	var got teltonikaDiagnostic
	c.recordDiagnostic = func(d teltonikaDiagnostic) { got = d }
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := c.do(ctx, http.MethodPost, "/api/login", nil, false)
	if err == nil || got.Result != "timeout" || got.Stage != "response_headers" || got.TCPMS == nil || got.TLSMS == nil {
		t.Fatalf("err=%v diagnostic=%+v", err, got)
	}
}

func TestTeltonikaDiagnosticsSafeExportAndRetention(t *testing.T) {
	a := newTestApp(t)
	var logs bytes.Buffer
	a.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	const secret = "SENTINEL-credential"
	a.cfg.TeltonikaURL = "https://" + secret + ":" + secret + "@example.test/private/" + secret + "?token=" + secret + "#" + secret
	a.cfg.TeltonikaPassword = secret
	a.teltonika = newTeltonikaClient(a.cfg)
	a.teltonika.http.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("token=" + secret)
	})
	a.pollModem(context.Background())
	// A hostile API response must not leak through the poll error either.
	a.teltonika.http.Transport = roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"success":false,"errors":[{"error":"` + secret + `"}]}`)), Header: make(http.Header)}, nil
	})
	a.lastModemAttempt = time.Time{}
	a.pollModem(context.Background())
	calls := 0
	a.teltonika.http.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		body := `{"success":true,"data":{"token":"` + secret + `","expires":300}}`
		if calls > 1 {
			if r.Header.Get("Authorization") != "Bearer "+secret {
				t.Fatal("missing test token")
			}
			body = `{"success":true,"data":[{"rsrp":-80}]}`
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Set-Cookie": {"session=" + secret}}}, nil
	})
	if _, skipped, err := a.takeModemSample(context.Background(), true); err != nil || skipped {
		t.Fatalf("manual fetch: skipped=%v err=%v", skipped, err)
	}
	old := teltonikaDiagnostic{CreatedAt: time.Now().Add(-40 * 24 * time.Hour), Operation: "login", Result: "timeout", Stage: "tcp_connect"}
	a.recordTeltonikaDiagnostic(old)
	if strings.Contains(logs.String(), secret) {
		t.Fatal("credential in console logs")
	}
	var buffer bytes.Buffer
	zw := zip.NewWriter(&buffer)
	if err := a.writeExport(context.Background(), zw, time.Now().Add(-time.Hour), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buffer.Bytes()), int64(buffer.Len()))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range zr.File {
		r, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatalf("credential in %s", f.Name)
		}
		if f.Name == "teltonika-diagnostics.jsonl" {
			found = true
			lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
			if len(lines) != 7 {
				t.Fatalf("want 7 records, got %d", len(lines))
			}
			var d teltonikaDiagnostic
			if err := json.Unmarshal([]byte(lines[0]), &d); err != nil {
				t.Fatal(err)
			}
			if d.Trigger != "poll" {
				t.Fatalf("missing trigger: %+v", d)
			}
			if err := json.Unmarshal([]byte(lines[len(lines)-1]), &d); err != nil {
				t.Fatal(err)
			}
			if d.Trigger != "manual" || d.Result != "ok" {
				t.Fatalf("manual diagnostic: %+v", d)
			}
		}
	}
	if !found {
		t.Fatal("diagnostics missing from ZIP")
	}
	if err := cleanup(context.Background(), a.db, 30*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM teltonika_diagnostics`).Scan(&n); err != nil || n != 7 {
		t.Fatalf("retention count=%d err=%v", n, err)
	}
	// Reopen database: diagnostics must survive a process restart.
	db, err := openDB(a.cfg.DataPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.QueryRow(`SELECT COUNT(*) FROM teltonika_diagnostics`).Scan(&n); err != nil || n != 7 {
		t.Fatalf("persisted count=%d err=%v", n, err)
	}
	if err := clearRecordedData(context.Background(), a.db); err != nil {
		t.Fatal(err)
	}
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM teltonika_diagnostics`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("clear count=%d err=%v", n, err)
	}
}
