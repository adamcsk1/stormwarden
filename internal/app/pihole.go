package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const piHoleCorrelationCooldown = 5 * time.Minute

type piHoleAPIClient struct {
	baseURL      string
	password     string
	httpClient   *http.Client
	mu           sync.Mutex
	lastAttempt  time.Time
	blockedUntil time.Time
}

type piHoleAuthResponse struct {
	Session struct {
		Valid bool   `json:"valid"`
		SID   string `json:"sid"`
	} `json:"session"`
}

type piHoleQueriesResponse struct {
	Queries []struct {
		Domain   string `json:"domain"`
		Status   string `json:"status"`
		Upstream string `json:"upstream"`
		Reply    struct {
			Type string  `json:"type"`
			Time float64 `json:"time"`
		} `json:"reply"`
	} `json:"queries"`
}

type piHoleMessagesResponse struct {
	Messages []struct {
		Timestamp float64 `json:"timestamp"`
		Type      string  `json:"type"`
	} `json:"messages"`
}

func newPiHoleAPIClient(baseURL, password string) *piHoleAPIClient {
	return &piHoleAPIClient{
		baseURL:  strings.TrimRight(baseURL, "/"),
		password: password,
		httpClient: &http.Client{
			Timeout:       2 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

func (c *piHoleAPIClient) correlate(ctx context.Context, probeTime time.Time, queryName string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if now.Before(c.blockedUntil) || (!c.lastAttempt.IsZero() && now.Sub(c.lastAttempt) < piHoleCorrelationCooldown) {
		return "", nil
	}
	c.lastAttempt = now

	sid, err := c.authenticate(ctx)
	if err != nil {
		c.blockedUntil = now.Add(30 * time.Minute)
		return "pihole_api unavailable", err
	}

	parts := make([]string, 0, 2)
	queryText, queryErr := c.queryEvidence(ctx, sid, probeTime, queryName)
	parts = append(parts, queryText)
	messageText, messageErr := c.messageEvidence(ctx, sid, probeTime)
	if messageText != "" {
		parts = append(parts, messageText)
	}
	var logoutErr error
	if sid != "" {
		logoutErr = c.logout(sid)
		if logoutErr != nil {
			c.blockedUntil = now.Add(30 * time.Minute)
		}
	}
	return strings.Join(parts, "\n"), errors.Join(queryErr, messageErr, logoutErr)
}

func (c *piHoleAPIClient) authenticate(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{"password": c.password})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/auth", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authenticate: %w", err)
	}
	defer response.Body.Close()
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 64*1024+1))
	if len(body) > 64*1024 {
		readErr = errors.New("response too large")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if sid := partialPiHoleSID(body); sid != "" {
			_ = c.logout(sid)
		}
		return "", fmt.Errorf("authenticate: HTTP %d", response.StatusCode)
	}
	var authResponse piHoleAuthResponse
	decodeErr := json.Unmarshal(body, &authResponse)
	if readErr != nil || decodeErr != nil {
		sid := authResponse.Session.SID
		if sid == "" {
			sid = partialPiHoleSID(body)
		}
		if sid != "" {
			_ = c.logout(sid)
		}
		return "", fmt.Errorf("authenticate: %w", errors.Join(readErr, decodeErr))
	}
	if !authResponse.Session.Valid {
		if authResponse.Session.SID != "" {
			_ = c.logout(authResponse.Session.SID)
		}
		return "", errors.New("authenticate: invalid session response")
	}
	if authResponse.Session.SID == "" {
		return "", nil
	}
	return authResponse.Session.SID, nil
}

func partialPiHoleSID(body []byte) string {
	index := bytes.Index(body, []byte(`"sid"`))
	if index < 0 {
		return ""
	}
	remainder := body[index+len(`"sid"`):]
	colon := bytes.IndexByte(remainder, ':')
	if colon < 0 {
		return ""
	}
	var sid string
	if json.NewDecoder(bytes.NewReader(remainder[colon+1:])).Decode(&sid) != nil {
		return ""
	}
	return sid
}

func (c *piHoleAPIClient) logout(sid string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+"/auth", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-FTL-SID", sid)
	response, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("logout: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if (response.StatusCode < 200 || response.StatusCode >= 300) && response.StatusCode != http.StatusNotFound {
		return fmt.Errorf("logout: HTTP %d", response.StatusCode)
	}
	return nil
}

func (c *piHoleAPIClient) queryEvidence(ctx context.Context, sid string, probeTime time.Time, queryName string) (string, error) {
	if queryName == "" {
		return "pihole_api query=unknown", errors.New("query name unavailable")
	}
	values := url.Values{
		"domain": {queryName},
		"from":   {fmt.Sprintf("%.3f", float64(probeTime.Add(-5*time.Second).UnixMilli())/1000)},
		"until":  {fmt.Sprintf("%.3f", float64(time.Now().Add(5*time.Second).UnixMilli())/1000)},
		"length": {"5"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/queries?"+values.Encode(), nil)
	if err != nil {
		return "pihole_api query=unavailable", err
	}
	setPiHoleSID(req, sid)
	var response piHoleQueriesResponse
	if err := c.doJSON(req, &response); err != nil {
		return "pihole_api query=unavailable", fmt.Errorf("queries: %w", err)
	}
	for _, query := range response.Queries {
		if query.Domain != queryName {
			continue
		}
		return fmt.Sprintf("pihole_api query=observed status=%s upstream=%s reply=%s reply_time=%.1fms", evidenceValue(query.Status), evidenceValue(query.Upstream), evidenceValue(query.Reply.Type), query.Reply.Time), nil
	}
	return "pihole_api query=not_observed", nil
}

func (c *piHoleAPIClient) messageEvidence(ctx context.Context, sid string, probeTime time.Time) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/info/messages", nil)
	if err != nil {
		return "", err
	}
	setPiHoleSID(req, sid)
	var response piHoleMessagesResponse
	if err := c.doJSON(req, &response); err != nil {
		return "", fmt.Errorf("messages: %w", err)
	}
	var messageTypes []string
	seenTypes := make(map[string]bool)
	for _, message := range response.Messages {
		at := time.UnixMilli(int64(message.Timestamp * 1000))
		if at.Before(probeTime.Add(-5*time.Minute)) || at.After(time.Now().Add(time.Minute)) {
			continue
		}
		messageType := evidenceValue(message.Type)
		if seenTypes[messageType] {
			continue
		}
		seenTypes[messageType] = true
		messageTypes = append(messageTypes, messageType)
		if len(messageTypes) == 3 {
			break
		}
	}
	if len(messageTypes) == 0 {
		return "", nil
	}
	return "pihole_api diagnostic_types=" + strings.Join(messageTypes, ","), nil
}

func setPiHoleSID(req *http.Request, sid string) {
	if sid != "" {
		req.Header.Set("X-FTL-SID", sid)
	}
}

func (c *piHoleAPIClient) doJSON(req *http.Request, target any) error {
	response, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(target); err != nil {
		return err
	}
	return nil
}

func evidenceValue(value string) string {
	value = strings.Join(strings.Fields(value), "_")
	if value == "" {
		return "none"
	}
	return truncateEvidence(value, 200)
}

func truncateEvidence(value string, limit int) string {
	value = strings.Join(strings.Fields(value), " ")
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit]) + "..."
}
