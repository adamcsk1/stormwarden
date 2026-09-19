package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	teltonikaPollInterval = 5 * time.Minute
	teltonikaHTTPTimeout  = 5 * time.Second
	ubusEmptySession      = "00000000000000000000000000000000"
)

var modemEvidenceCategories = map[string]bool{
	"internet_outage":        true,
	"wan_or_isp_packet_loss": true,
	"dns_resolution_failure": true,
	"external_dns":           true,
}

type ModemSample struct {
	ID          int64
	CreatedAt   time.Time
	RSSI        *float64
	RSRP        *float64
	RSRQ        *float64
	SINR        *float64
	RSCP        *float64
	EcIo        *float64
	CACount     int
	Band        string
	CABands     string
	Operator    string
	NetworkType string
	CellID      string
	Message     string
}

type teltonikaClient struct {
	baseURL  string
	user     string
	password string
	http     *http.Client
	mu       sync.Mutex
	session  string
	until    time.Time
	rpcID    int
}

func (c Config) teltonikaEnabled() bool {
	return c.TeltonikaURL != "" && c.TeltonikaPassword != ""
}

func newTeltonikaClient(cfg Config) *teltonikaClient {
	parsed, _ := url.Parse(cfg.TeltonikaURL)
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.TeltonikaInsecureSkipVerify}
	if parsed != nil {
		tlsCfg.ServerName = parsed.Hostname()
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsCfg
	return &teltonikaClient{
		baseURL:  strings.TrimRight(cfg.TeltonikaURL, "/"),
		user:     cfg.TeltonikaUser,
		password: cfg.TeltonikaPassword,
		http: &http.Client{
			Timeout:   teltonikaHTTPTimeout,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (c *teltonikaClient) fetch(ctx context.Context) (ModemSample, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureSession(ctx); err != nil {
		return ModemSample{}, err
	}
	sample, err := c.readStats(ctx)
	if err != nil && isTeltonikaAuthErr(err) {
		c.session, c.until = "", time.Time{}
		if loginErr := c.ensureSession(ctx); loginErr != nil {
			return ModemSample{}, loginErr
		}
		sample, err = c.readStats(ctx)
	}
	return sample, err
}

func (c *teltonikaClient) ensureSession(ctx context.Context) error {
	if c.session != "" && time.Now().Before(c.until) {
		return nil
	}
	payload, err := c.call(ctx, ubusEmptySession, "session", "login", map[string]any{
		"username": c.user,
		"password": c.password,
	})
	if err != nil {
		return err
	}
	var login struct {
		Session string `json:"ubus_rpc_session"`
		Timeout int    `json:"timeout"`
		Expires int    `json:"expires"`
	}
	if err := json.Unmarshal(payload, &login); err != nil || login.Session == "" {
		return errors.New("teltonika login did not return a session")
	}
	ttl := login.Expires
	if ttl <= 0 {
		ttl = login.Timeout
	}
	if ttl <= 0 {
		ttl = 300
	}
	c.session = login.Session
	d := time.Duration(ttl) * time.Second
	if d > 30*time.Second {
		d -= 30 * time.Second
	} else {
		d /= 2
	}
	if d < time.Second {
		d = time.Second
	}
	c.until = time.Now().Add(d)
	return nil
}

func isTeltonikaAuthErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "status 6") || strings.Contains(msg, "HTTP 401") || strings.Contains(msg, "HTTP 403") || strings.Contains(msg, "Access denied")
}

func (c *teltonikaClient) readStats(ctx context.Context) (ModemSample, error) {
	var last error
	for _, object := range []string{"gsm.modem0", "gsm.modem1"} {
		for _, method := range []string{"get_live_stats", "info", "status"} {
			if err := ctx.Err(); err != nil {
				return ModemSample{}, err
			}
			payload, err := c.call(ctx, c.session, object, method, map[string]any{})
			if err != nil {
				last = err
				continue
			}
			var data any
			if err := json.Unmarshal(payload, &data); err != nil {
				last = err
				continue
			}
			sample := parseModemStats(data)
			if sample.hasRadio() {
				return sample, nil
			}
			last = errors.New("teltonika response had no radio metrics")
		}
	}
	if last == nil {
		last = errors.New("teltonika modem stats unavailable")
	}
	return ModemSample{}, last
}

type ubusRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (c *teltonikaClient) call(ctx context.Context, session, object, method string, args map[string]any) (json.RawMessage, error) {
	c.rpcID++
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      c.rpcID,
		"method":  "call",
		"params":  []any{session, object, method, args},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/ubus", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("teltonika ubus HTTP %d", resp.StatusCode)
	}
	var envelope struct {
		Error  *ubusRPCError   `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("teltonika rpc: %s", envelope.Error.Message)
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(envelope.Result, &parts); err != nil || len(parts) == 0 {
		return nil, errors.New("teltonika ubus result malformed")
	}
	var status int
	if err := json.Unmarshal(parts[0], &status); err != nil {
		return nil, err
	}
	if status != 0 {
		return nil, fmt.Errorf("ubus %s.%s status %d", object, method, status)
	}
	if len(parts) < 2 {
		return json.RawMessage(`{}`), nil
	}
	return parts[1], nil
}

func (s ModemSample) hasRadio() bool {
	return s.RSSI != nil || s.RSRP != nil || s.RSRQ != nil || s.SINR != nil || s.RSCP != nil
}

func (s ModemSample) evidenceLine() string {
	if !s.hasRadio() && s.Operator == "" && s.NetworkType == "" {
		return ""
	}
	parts := []string{"modem"}
	if s.RSRP != nil {
		parts = append(parts, fmt.Sprintf("rsrp=%.0fdBm", *s.RSRP))
	}
	if s.RSRQ != nil {
		parts = append(parts, fmt.Sprintf("rsrq=%.0fdB", *s.RSRQ))
	}
	if s.SINR != nil {
		parts = append(parts, fmt.Sprintf("sinr=%.1fdB", *s.SINR))
	}
	if s.RSSI != nil {
		parts = append(parts, fmt.Sprintf("rssi=%.0fdBm", *s.RSSI))
	}
	if s.Band != "" {
		parts = append(parts, "band="+s.Band)
	}
	if s.CACount > 0 {
		ca := fmt.Sprintf("ca=%d", s.CACount)
		if s.CABands != "" {
			ca += "(" + s.CABands + ")"
		}
		parts = append(parts, ca)
	}
	if s.Operator != "" {
		parts = append(parts, "operator="+s.Operator)
	}
	if s.NetworkType != "" {
		parts = append(parts, "type="+s.NetworkType)
	}
	if s.CellID != "" {
		parts = append(parts, "cell="+s.CellID)
	}
	return strings.Join(parts, " ")
}

func parseModemStats(v any) ModemSample {
	s := ModemSample{
		RSSI:        findFloat(v, "rssi"),
		RSRP:        findFloat(v, "rsrp"),
		RSRQ:        findFloat(v, "rsrq"),
		SINR:        findFloat(v, "sinr"),
		RSCP:        findFloat(v, "rscp"),
		EcIo:        findFloat(v, "ecio", "ec/io", "ec_io"),
		Operator:    findString(v, "operator", "oper", "opern"),
		NetworkType: findString(v, "conntype", "conn_type", "nettype", "network", "mode", "nw"),
		Band:        findString(v, "band", "lte_band", "nr_band"),
		CellID:      findString(v, "cell_id", "cellid", "cid"),
	}
	if s.CellID == "" {
		if pci := findString(v, "pci"); pci != "" {
			s.CellID = "pci " + pci
		}
	}
	if n := findFloat(v, "ca_count", "scc_count", "ca"); n != nil && *n >= 1 && *n <= 16 {
		s.CACount = int(*n)
	}
	s.CABands = joinCABands(v)
	if s.Band != "" && s.CABands != "" && !hasCABand(s.CABands, s.Band) {
		s.CABands = s.Band + "+" + s.CABands
	}
	if s.CACount == 0 && s.CABands != "" {
		s.CACount = 1 + strings.Count(s.CABands, "+")
	}
	s.Message = s.evidenceLine()
	return s
}

func joinCABands(v any) string {
	if s := findString(v, "ca_bands", "scc_bands"); s != "" {
		return strings.ReplaceAll(s, ",", "+")
	}
	var bands []string
	walkJSON(v, 0, func(key string, val any, depth int) bool {
		lk := strings.ToLower(key)
		if lk != "scc" && lk != "ca" && lk != "carriers" {
			return true
		}
		switch items := val.(type) {
		case []any:
			for _, item := range items {
				if b := findString(item, "band", "lte_band", "nr_band"); b != "" {
					bands = append(bands, b)
				}
			}
		}
		return true
	})
	return strings.Join(uniqueStrings(bands), "+")
}

func hasCABand(list, band string) bool {
	for _, b := range strings.Split(list, "+") {
		if b == band {
			return true
		}
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

func findFloat(v any, names ...string) *float64 {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	bestDepth := 99
	var found *float64
	walkJSON(v, 0, func(key string, val any, depth int) bool {
		if !want[strings.ToLower(key)] || depth >= bestDepth {
			return true
		}
		if n, ok := asFloat(val); ok {
			n := n
			found = &n
			bestDepth = depth
		}
		return true
	})
	return found
}

func findString(v any, names ...string) string {
	want := map[string]bool{}
	for _, n := range names {
		want[strings.ToLower(n)] = true
	}
	bestDepth, found := 99, ""
	walkJSON(v, 0, func(key string, val any, depth int) bool {
		if !want[strings.ToLower(key)] || depth >= bestDepth {
			return true
		}
		switch t := val.(type) {
		case string:
			s := strings.TrimSpace(t)
			if s != "" {
				found, bestDepth = s, depth
			}
		case float64:
			found, bestDepth = strconv.FormatFloat(t, 'f', -1, 64), depth
		}
		return true
	})
	return found
}

func asFloat(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		n, err := t.Float64()
		return n, err == nil
	case string:
		s := strings.TrimSpace(t)
		s = strings.TrimSuffix(s, "dBm")
		s = strings.TrimSuffix(s, "dB")
		s = strings.TrimSpace(s)
		n, err := strconv.ParseFloat(s, 64)
		return n, err == nil
	case int:
		return float64(t), true
	default:
		return 0, false
	}
}

func walkJSON(v any, depth int, fn func(key string, val any, depth int) bool) bool {
	switch t := v.(type) {
	case map[string]any:
		for key, val := range t {
			if !fn(key, val, depth) {
				return false
			}
			if !walkJSON(val, depth+1, fn) {
				return false
			}
		}
	case []any:
		for _, val := range t {
			if !walkJSON(val, depth+1, fn) {
				return false
			}
		}
	}
	return true
}

func (a *App) modemLoop(ctx context.Context) {
	if a.teltonika == nil {
		return
	}
	a.pollModem(ctx)
	ticker := time.NewTicker(teltonikaPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.pollModem(ctx)
		}
	}
}

func (a *App) pollModem(ctx context.Context) {
	if a.teltonika == nil {
		return
	}
	if !a.modemMu.TryLock() {
		return
	}
	defer a.modemMu.Unlock()
	if !a.lastModemAttempt.IsZero() && time.Since(a.lastModemAttempt) < teltonikaPollInterval {
		return
	}
	a.lastModemAttempt = time.Now()
	pollCtx, cancel := context.WithTimeout(ctx, teltonikaHTTPTimeout)
	defer cancel()
	sample, err := a.teltonika.fetch(pollCtx)
	if err != nil {
		a.logger.Error("teltonika modem poll failed", "error", redactSMTPErr(err, a.cfg.TeltonikaPassword))
		return
	}
	sample.CreatedAt = time.Now()
	if err := insertModemSample(ctx, a.db, sample); err != nil {
		a.logger.Error("modem sample persistence failed", "error", err)
	}
}

func wantsModemEvidence(issue Sample) bool {
	if modemEvidenceCategories[issue.Target] {
		return true
	}
	return issue.diagnosis != nil && modemEvidenceCategories[issue.diagnosis.Classification]
}

func (a *App) attachModemEvidence(ctx context.Context, issue *Sample) {
	if issue == nil || !wantsModemEvidence(*issue) {
		return
	}
	line := a.modemEvidenceLine(ctx)
	if line == "" {
		return
	}
	if issue.incidentContext == "" {
		issue.incidentContext = line
		return
	}
	if !strings.Contains(issue.incidentContext, line) {
		issue.incidentContext += "\n" + line
	}
}

func (a *App) modemEvidenceLine(ctx context.Context) string {
	sample, err := latestModemSample(ctx, a.db)
	if err != nil || sample == nil {
		return ""
	}
	return sample.evidenceLine()
}
