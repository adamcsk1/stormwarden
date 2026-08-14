package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const maxDNSMessageSize = 65535

var sharedDoHClient = &http.Client{Transport: &http.Transport{
	MaxIdleConns:        4,
	MaxIdleConnsPerHost: 2,
	IdleConnTimeout:     90 * time.Second,
	TLSHandshakeTimeout: 4 * time.Second,
}}

type connectionTrace struct {
	mu        sync.Mutex
	started   map[string]time.Time
	success   float64
	failed    float64
	connected bool
}

func newConnectionTrace() *connectionTrace {
	return &connectionTrace{started: make(map[string]time.Time)}
}

func (t *connectionTrace) start(network, address string) {
	t.mu.Lock()
	t.started[network+"\x00"+address] = time.Now()
	t.mu.Unlock()
}

func (t *connectionTrace) done(network, address string, err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := network + "\x00" + address
	started := t.started[key]
	delete(t.started, key)
	if started.IsZero() {
		return
	}
	duration := ms(time.Since(started))
	if err == nil {
		t.success = duration
		t.connected = true
	} else if duration > t.failed {
		t.failed = duration
	}
}

func (t *connectionTrace) duration() float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.connected {
		return t.success
	}
	return t.failed
}

func probeTCP(ctx context.Context, name, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "tcp", Target: name, Severity: Info}
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", address)
	s.DurationMS = ms(time.Since(started))
	s.ConnectMS = s.DurationMS
	if err != nil {
		s.Severity, s.Message = Error, fmt.Sprintf("TCP %s: %v", address, err)
		return s
	}
	_ = conn.Close()
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "TCP connection")
	if s.Severity == Info {
		s.Message = fmt.Sprintf("TCP %s connected", address)
	} else {
		s.Message += " to " + address
	}
	return s
}

func probeDNS(ctx context.Context, target, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "dns", Target: target, Severity: Info}
	id, query, err := newDNSQuery()
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	response, err := exchangeDNS(ctx, "udp", address, query)
	if err != nil {
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.DurationMS, s.DNSMS = ms(time.Since(started)), ms(time.Since(started))
	if err := validateDNSResponse(response, query, id); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "DNS response")
	if s.Severity == Info {
		s.Message = dnsSuccessMessage(response, "udp")
	}
	return s
}

func probeDNSTCP(ctx context.Context, target, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "dns", Target: target, Severity: Info}
	id, query, err := newDNSQuery()
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	response, err := exchangeDNS(ctx, "tcp", address, query)
	s.DurationMS, s.DNSMS = ms(time.Since(started)), ms(time.Since(started))
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	if err := validateDNSResponse(response, query, id); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "DNS response")
	if s.Severity == Info {
		s.Message = dnsSuccessMessage(response, "tcp")
	}
	return s
}

func probeDoH(ctx context.Context, target, endpoint string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "doh", Target: target, Severity: Info}
	id, query, err := newDNSQuery()
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	connections := newConnectionTrace()
	var tlsStart, wroteRequest time.Time
	trace := &httptrace.ClientTrace{
		ConnectStart:      connections.start,
		ConnectDone:       connections.done,
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				s.TLSMS = ms(time.Since(tlsStart))
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest = time.Now() },
		GotFirstResponseByte: func() {
			if wroteRequest.IsZero() {
				s.TTFBMS = ms(time.Since(started))
			} else {
				s.TTFBMS = ms(time.Since(wroteRequest))
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodPost, endpoint, bytes.NewReader(query))
	if err != nil {
		s.Severity, s.Message = Error, redactHTTPError(err, endpoint)
		return s
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("User-Agent", "stormwarden/1.0")
	resp, err := sharedDoHClient.Do(req)
	s.ConnectMS = connections.duration()
	if err != nil {
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, redactHTTPError(err, endpoint)
		return s
	}
	defer resp.Body.Close()
	s.DurationMS, s.DNSMS = ms(time.Since(started)), ms(time.Since(started))
	s.StatusCode = resp.StatusCode
	if resp.StatusCode != http.StatusOK {
		s.Severity, s.Message = Error, fmt.Sprintf("unexpected DoH status %d", resp.StatusCode)
		return s
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/dns-message" {
		s.Severity, s.Message = Error, "invalid DoH content type"
		return s
	}
	response, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessageSize+1))
	s.DurationMS, s.DNSMS = ms(time.Since(started)), ms(time.Since(started))
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	if len(response) > maxDNSMessageSize {
		s.Severity, s.Message = Error, "oversized DoH response"
		return s
	}
	if err := validateDNSResponse(response, query, id); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "DoH response")
	if s.Severity == Info {
		s.Message = dnsSuccessMessage(response, "doh")
	}
	return s
}

func exchangeDNS(ctx context.Context, network, address string, query []byte) ([]byte, error) {
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)
	if network == "udp" {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		response := make([]byte, 4096)
		n, err := conn.Read(response)
		return response[:n], err
	}
	packet := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(query)))
	copy(packet[2:], query)
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(conn)
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return nil, err
	}
	response := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
	_, err = io.ReadFull(reader, response)
	return response, err
}

func validateDNSResponse(response, query []byte, id uint16) error {
	var queryMessage, responseMessage dnsmessage.Message
	if err := queryMessage.Unpack(query); err != nil {
		return fmt.Errorf("invalid DNS query: %w", err)
	}
	if err := responseMessage.Unpack(response); err != nil {
		return fmt.Errorf("invalid DNS response: %w", err)
	}
	if !responseMessage.Header.Response || responseMessage.Header.OpCode != 0 {
		return errors.New("invalid DNS response flags")
	}
	if responseMessage.Header.ID != id {
		return errors.New("DNS response ID mismatch")
	}
	if responseMessage.Header.Truncated {
		return errors.New("DNS response was truncated")
	}
	if !responseMessage.Header.RecursionAvailable {
		return errors.New("DNS recursion unavailable")
	}
	if len(queryMessage.Questions) != 1 || len(responseMessage.Questions) != 1 {
		return errors.New("DNS response question count mismatch")
	}
	want, got := queryMessage.Questions[0], responseMessage.Questions[0]
	if want.Name.String() != got.Name.String() || want.Type != got.Type || want.Class != got.Class {
		return errors.New("DNS response question mismatch")
	}
	if responseMessage.Header.RCode != dnsmessage.RCodeSuccess && responseMessage.Header.RCode != dnsmessage.RCodeNameError {
		return fmt.Errorf("DNS response code %d", responseMessage.Header.RCode)
	}
	if len(responseMessage.Answers) > 0 {
		return nil
	}
	for _, authority := range responseMessage.Authorities {
		if authority.Header.Type == dnsmessage.TypeSOA {
			if _, ok := authority.Body.(*dnsmessage.SOAResource); ok {
				return nil
			}
		}
	}
	return errors.New("DNS negative response lacks SOA authority")
}

func newDNSQuery() (uint16, []byte, error) {
	random := make([]byte, 10)
	if _, err := rand.Read(random); err != nil {
		return 0, nil, err
	}
	id := binary.BigEndian.Uint16(random[:2])
	domain := hex.EncodeToString(random[2:]) + ".example.com"
	return id, dnsQuery(id, domain), nil
}

func dnsSuccessMessage(response []byte, transport string) string {
	if len(response) >= 4 && response[3]&0x0f == 3 {
		return "healthy uncached NXDOMAIN over " + transport
	}
	if len(response) >= 8 && binary.BigEndian.Uint16(response[6:8]) == 0 {
		return "healthy uncached NODATA over " + transport
	}
	return "healthy uncached answer over " + transport
}

func dnsQuery(id uint16, domain string) []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[0:2], id)
	binary.BigEndian.PutUint16(packet[2:4], 0x0100)
	binary.BigEndian.PutUint16(packet[4:6], 1)
	for _, label := range strings.Split(domain, ".") {
		packet = append(packet, byte(len(label)))
		packet = append(packet, label...)
	}
	packet = append(packet, 0, 0, 1, 0, 1)
	return packet
}

func probeHTTP(ctx context.Context, probeType, url string, limit int64) Sample {
	return probeHTTPStatus(ctx, probeType, url, limit, 0)
}

func probeHTTPStatus(ctx context.Context, probeType, url string, limit int64, expectedStatus int) Sample {
	return probeHTTPStatusResolver(ctx, probeType, url, limit, expectedStatus, "")
}

func probeHTTPStatusResolver(ctx context.Context, probeType, url string, limit int64, expectedStatus int, dnsAddress string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: probeType, Target: redactURL(url), Severity: Info}
	connections := newConnectionTrace()
	var dnsStart, tlsStart, wroteRequest time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				s.DNSMS = ms(time.Since(dnsStart))
			}
		},
		ConnectStart:      connections.start,
		ConnectDone:       connections.done,
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				s.TLSMS = ms(time.Since(tlsStart))
			}
		},
		WroteRequest: func(httptrace.WroteRequestInfo) { wroteRequest = time.Now() },
		GotFirstResponseByte: func() {
			if wroteRequest.IsZero() {
				s.TTFBMS = ms(time.Since(started))
			} else {
				s.TTFBMS = ms(time.Since(wroteRequest))
			}
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, nil)
	if err != nil {
		s.Severity, s.Message = Error, redactHTTPError(err, url)
		return s
	}
	req.Header.Set("User-Agent", "stormwarden/1.0")
	dialer := &net.Dialer{}
	if dnsAddress != "" {
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(resolveCtx context.Context, network, _ string) (net.Conn, error) {
			if strings.HasPrefix(network, "udp") {
				network = "udp"
			} else {
				network = "tcp"
			}
			return (&net.Dialer{}).DialContext(resolveCtx, network, dnsAddress)
		}}
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second, DialContext: dialer.DialContext}}
	resp, err := client.Do(req)
	s.ConnectMS = connections.duration()
	if err != nil {
		s.connectFailed = isTCPConnectFailure(err)
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, redactHTTPError(err, url)
		return s
	}
	defer resp.Body.Close()
	s.DurationMS = ms(time.Since(started))
	s.StatusCode = resp.StatusCode
	statusInvalid := expectedStatus > 0 && resp.StatusCode != expectedStatus
	if expectedStatus == 0 {
		statusInvalid = resp.StatusCode < 200 || resp.StatusCode >= 400
	}
	if statusInvalid {
		s.Severity, s.Message = Error, fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		return s
	}
	bodyReadStarted := time.Now()
	s.Bytes, err = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	s.DurationMS = ms(time.Since(started))
	bodyDuration := time.Since(bodyReadStarted)
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.Success = true
	if (probeType == "transfer" || probeType == "asset") && s.Bytes > 0 {
		if bodyDuration <= 0 {
			bodyDuration = time.Microsecond
		}
		s.Mbps = float64(s.Bytes*8) / bodyDuration.Seconds() / 1_000_000
	}
	if probeType == "transfer" {
		if s.Bytes != limit {
			s.Success, s.Severity, s.Message = false, Error, fmt.Sprintf("short transfer: received %d of %d bytes", s.Bytes, limit)
			return s
		}
		if s.Mbps < 1 {
			s.Severity, s.Message = Error, "transfer below 1 Mbps"
			return s
		}
		if s.Mbps < 5 {
			s.Severity, s.Message = Warning, "transfer below 5 Mbps"
			return s
		}
	}
	if s.TTFBMS > 3000 {
		s.Severity, s.Message = Error, "TTFB above 3 seconds"
		return s
	}
	if s.TTFBMS > 1000 {
		s.Severity, s.Message = Warning, "TTFB above 1 second"
		return s
	}
	s.Severity, s.Message = Info, "healthy"
	return s
}

func isTCPConnectFailure(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return false
	}
	var networkErr *net.OpError
	return errors.As(err, &networkErr) && networkErr.Op == "dial"
}

func classifyLatency(value float64, label string) (Severity, string) {
	if value > 3000 {
		return Error, fmt.Sprintf("%s above 3 seconds", label)
	}
	if value > 250 {
		return Warning, fmt.Sprintf("%s above 250 ms", label)
	}
	return Info, "healthy"
}

func ms(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }

func transferURL(configured string, bytes int64) string {
	parsed, err := url.Parse(configured)
	if err != nil {
		return configured
	}
	query := parsed.Query()
	query.Set("bytes", fmt.Sprintf("%d", bytes))
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func redactURL(value string) string {
	parsed, err := url.Parse(value)
	if err != nil {
		return "invalid-url"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

func redactHTTPError(err error, rawURL string) string {
	var urlError *url.Error
	if errors.As(err, &urlError) {
		return urlError.Op + ": " + urlError.Err.Error()
	}
	return strings.ReplaceAll(err.Error(), rawURL, redactURL(rawURL))
}
