package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func withDoHClient(t *testing.T, client *http.Client) {
	t.Helper()
	old := sharedDoHClient
	sharedDoHClient = client
	t.Cleanup(func() { sharedDoHClient = old })
}

func blockingDialClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 4 * time.Second,
		DisableKeepAlives:     true,
	}}
}

func TestDoHTCPConnectStall(t *testing.T) {
	withDoHClient(t, blockingDialClient())
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	sample := probeDoH(ctx, "direct-doh", "https://192.0.2.1/dns-query")
	if sample.Success || (sample.NetworkResult != networkTCPConnectTimeout && sample.NetworkResult != networkRequestTimeout) {
		t.Fatalf("connect stall: %+v", sample)
	}
	if sample.ProbeControl != probeCompleted && sample.ProbeControl != probeCancelledCleanly {
		t.Fatalf("control: %+v", sample)
	}
	if sample.ProbeStage != stageConnect && sample.ProbeStage != "" {
		t.Fatalf("stage: %+v", sample)
	}
}

func TestDoHTLSHandshakeStall(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	t.Cleanup(func() { close(stop); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				select {
				case <-stop:
				case <-time.After(2 * time.Second):
				}
			}(conn)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	sample := probeDoH(ctx, "direct-doh", "https://"+ln.Addr().String()+"/dns-query")
	if sample.Success {
		t.Fatalf("tls stall succeeded: %+v", sample)
	}
	if sample.NetworkResult != networkTLSHandshakeTimeout && sample.NetworkResult != networkRequestTimeout {
		t.Fatalf("tls stall result: %+v", sample)
	}
	if sample.ProbeControl != probeCompleted && sample.ProbeControl != probeCancelledCleanly {
		t.Fatalf("control: %+v", sample)
	}
}

func TestDoHHeaderStall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	sample := probeDoH(ctx, "direct-doh", server.URL)
	if sample.Success {
		t.Fatalf("header stall succeeded: %+v", sample)
	}
	if sample.NetworkResult != networkResponseHeaderTimeout && sample.NetworkResult != networkRequestTimeout && sample.NetworkResult != networkParentCancelled {
		t.Fatalf("header stall result: %+v", sample)
	}
}

func TestDoHBodyStall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/dns-message")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	}))
	t.Cleanup(func() { server.CloseClientConnections(); server.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	sample := probeDoH(ctx, "direct-doh", server.URL)
	if sample.Success {
		t.Fatalf("body stall succeeded: %+v", sample)
	}
	if sample.NetworkResult != networkResponseReadTimeout && sample.NetworkResult != networkRequestTimeout && sample.NetworkResult != networkParentCancelled {
		t.Fatalf("body stall result: %+v", sample)
	}
}

func TestDoHParentCancel(t *testing.T) {
	startedDial := make(chan struct{})
	withDoHClient(t, &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(startedDial)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		DisableKeepAlives: true,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan Sample, 1)
	go func() { done <- probeDoH(ctx, "direct-doh", "https://192.0.2.1/dns-query") }()
	<-startedDial
	cancel()
	sample := <-done
	if confirmedNetworkFailure(sample) {
		t.Fatalf("parent cancel counted as network failure: %+v", sample)
	}
	if sample.NetworkResult != networkParentCancelled && sample.NetworkResult != networkUnknown {
		t.Fatalf("parent cancel result: %+v", sample)
	}
	if sample.ProbeControl != probeCancelledCleanly {
		t.Fatalf("control: %+v", sample)
	}
}

func TestDoHProbeDeadline(t *testing.T) {
	withDoHClient(t, blockingDialClient())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	sample := probeDoH(ctx, "direct-doh", "https://192.0.2.1/dns-query")
	if time.Since(started) > 300*time.Millisecond {
		t.Fatalf("deadline ignored: %v", time.Since(started))
	}
	if sample.ProbeControl == probeCancellationTimeout {
		t.Fatalf("waiter timeout leaked into direct probe: %+v", sample)
	}
	if sample.NetworkResult != networkTCPConnectTimeout && sample.NetworkResult != networkRequestTimeout {
		t.Fatalf("deadline result: %+v", sample)
	}
}

func TestDoHCancelCompletesPromptly(t *testing.T) {
	startedDial := make(chan struct{})
	withDoHClient(t, &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			close(startedDial)
			<-ctx.Done()
			return nil, ctx.Err()
		},
		DisableKeepAlives: true,
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = probeDoH(ctx, "direct-doh", "https://192.0.2.1/dns-query")
		close(done)
	}()
	<-startedDial
	started := time.Now()
	cancel()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cancel did not complete promptly")
	}
	if time.Since(started) > 200*time.Millisecond {
		t.Fatalf("slow cancel: %v", time.Since(started))
	}
}

func TestDoHBrokenRoundTripperIsLifecycleNotNetwork(t *testing.T) {
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	withDoHClient(t, &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
		<-block
		return nil, errors.New("ignored cancel")
	})})
	result := runConcurrentProbes(context.Background(), 40*time.Millisecond, []probeFunc{{
		ProbeType: "doh", Target: "direct-doh",
		Run: func(ctx context.Context) Sample { return probeDoH(ctx, "direct-doh", "https://example.test/dns-query") },
	}})
	if len(result) != 1 || result[0].ProbeControl != probeCancellationTimeout {
		t.Fatalf("lifecycle: %+v", result)
	}
	if confirmedNetworkFailure(result[0]) {
		t.Fatalf("broken transport counted as network failure: %+v", result[0])
	}
	if result[0].NetworkResult != networkUnknown {
		t.Fatalf("network result: %+v", result[0])
	}
}

func TestDoHLifecycleNotNetworkIncident(t *testing.T) {
	a := newTestApp(t)
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Info, Success: true},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Info, Success: true},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true},
		{ProbeType: "doh", Target: "direct-doh", Severity: Warning, Success: false, Message: "probe did not terminate after cancellation", NetworkResult: networkUnknown, ProbeControl: probeCancellationTimeout},
		{ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Info, Success: true},
		{ProbeType: "http", Target: "http", Severity: Info, Success: true},
	}
	aggregate, issues, _ := a.diagnoseSamples(samples)
	if !aggregate.Success || aggregate.Severity == Error || aggregate.Severity == Critical {
		t.Fatalf("aggregate: %+v", aggregate)
	}
	var path, health bool
	for _, issue := range issues {
		if issue.Target == "direct_doh_path" {
			path = true
		}
		if issue.Target == "probe_health" {
			health = true
		}
	}
	if path {
		t.Fatalf("lifecycle became DoH path incident: %+v", issues)
	}
	if !health {
		t.Fatalf("missing probe_health: %+v", issues)
	}
}

func TestDoHNetworkTimeoutAndCleanupFailurePreservesBoth(t *testing.T) {
	a := newTestApp(t)
	samples := []Sample{
		{ProbeType: "dns", Target: "pihole", Severity: Info, Success: true},
		{ProbeType: "dns", Target: "pihole-udp", Severity: Info, Success: true},
		{ProbeType: "dns", Target: "public-dns", Severity: Info, Success: true},
		{ProbeType: "doh", Target: "direct-doh", Severity: Error, Success: false, Message: "timeout", NetworkResult: networkRequestTimeout, ProbeControl: probeCancellationTimeout, ProbeStage: stageConnect},
		{ProbeType: "tcp", Target: "tcp:cloudflare", Severity: Info, Success: true},
	}
	_, issues, _ := a.diagnoseSamples(samples)
	var path, health bool
	for _, issue := range issues {
		if issue.Target == "direct_doh_path" {
			path = true
		}
		if issue.Target == "probe_health" {
			health = true
		}
	}
	if !path || !health {
		t.Fatalf("expected both results: %+v", issues)
	}
}

func TestDoHRepeatedBrokenTransportDoesNotHangWaiter(t *testing.T) {
	for i := 0; i < 20; i++ {
		block := make(chan struct{})
		finished := make(chan struct{})
		old := sharedDoHClient
		sharedDoHClient = &http.Client{Transport: roundTripperFunc(func(*http.Request) (*http.Response, error) {
			defer close(finished)
			<-block
			return nil, errors.New("ignored cancel")
		})}
		started := time.Now()
		result := runConcurrentProbes(context.Background(), 30*time.Millisecond, []probeFunc{{
			ProbeType: "doh", Target: "direct-doh",
			Run: func(ctx context.Context) Sample { return probeDoH(ctx, "direct-doh", "https://example.test/dns-query") },
		}})
		close(block)
		<-finished
		sharedDoHClient = old
		if time.Since(started) > 200*time.Millisecond {
			t.Fatalf("waiter hung on iteration %d: %v", i, time.Since(started))
		}
		if len(result) != 1 || result[0].ProbeControl != probeCancellationTimeout {
			t.Fatalf("iteration %d: %+v", i, result)
		}
	}
}

func TestDoHReportStatsSeparateMonitorFailures(t *testing.T) {
	a := newTestApp(t)
	now := time.Now()
	if err := insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "doh", Target: "direct-doh", Severity: Info, Success: true, DurationMS: 10, NetworkResult: networkSuccess, ProbeControl: probeCompleted}); err != nil {
		t.Fatal(err)
	}
	if err := insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "doh", Target: "direct-doh", Severity: Error, Success: false, DurationMS: 20, NetworkResult: networkRequestTimeout, ProbeControl: probeCompleted}); err != nil {
		t.Fatal(err)
	}
	if err := insertSample(context.Background(), a.db, Sample{CreatedAt: now, ProbeType: "doh", Target: "direct-doh", Severity: Warning, Success: false, DurationMS: 30, NetworkResult: networkUnknown, ProbeControl: probeCancellationTimeout}); err != nil {
		t.Fatal(err)
	}
	tx, err := a.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	summaries, err := loadDNSPathSummaries(context.Background(), tx, dbTime(now.Add(-time.Minute)), dbTime(now.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 1 || summaries[0].Target != "direct-doh" {
		t.Fatalf("summaries: %+v", summaries)
	}
	if summaries[0].Samples != 2 || summaries[0].Successes != 1 {
		t.Fatalf("network stats inflated by monitor failure: %+v", summaries[0])
	}
	if summaries[0].MonitorFailures != 1 {
		t.Fatalf("monitor failures: %+v", summaries[0])
	}
}

func TestDoHBodyClosedOnSuccess(t *testing.T) {
	closed := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query, _ := io.ReadAll(r.Body)
		response := negativeDNSResponse(t, query, dnsmessage.RCodeNameError)
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(response)
	}))
	defer server.Close()
	old := sharedDoHClient
	sharedDoHClient = &http.Client{Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := old.Transport.RoundTrip(req)
		if err != nil {
			return resp, err
		}
		resp.Body = &notifyCloser{ReadCloser: resp.Body, done: closed}
		return resp, nil
	})}
	t.Cleanup(func() { sharedDoHClient = old })
	sample := probeDoH(context.Background(), "direct-doh", server.URL)
	if !sample.Success {
		t.Fatalf("expected success: %+v", sample)
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("response body not closed")
	}
}

type notifyCloser struct {
	io.ReadCloser
	done chan struct{}
}

func (c *notifyCloser) Close() error {
	err := c.ReadCloser.Close()
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return err
}
