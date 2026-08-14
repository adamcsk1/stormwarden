package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

func probeTCP(ctx context.Context, name, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "tcp", Target: name, Severity: Info}
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", address)
	s.DurationMS = ms(time.Since(started))
	s.ConnectMS = s.DurationMS
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	_ = conn.Close()
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "TCP connection")
	return s
}

func probeDNS(ctx context.Context, target, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "dns", Target: target, Severity: Info}
	conn, err := (&net.Dialer{Timeout: 4 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	defer conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	_ = conn.SetDeadline(deadline)

	idBytes := make([]byte, 2)
	_, _ = rand.Read(idBytes)
	id := binary.BigEndian.Uint16(idBytes)
	query := dnsQuery(id, "example.com")
	packet := make([]byte, len(query)+2)
	binary.BigEndian.PutUint16(packet, uint16(len(query)))
	copy(packet[2:], query)
	if _, err = conn.Write(packet); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	reader := bufio.NewReader(conn)
	lengthBytes := make([]byte, 2)
	if _, err = io.ReadFull(reader, lengthBytes); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	response := make([]byte, int(binary.BigEndian.Uint16(lengthBytes)))
	if _, err = io.ReadFull(reader, response); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	s.DurationMS, s.DNSMS = ms(time.Since(started)), ms(time.Since(started))
	if len(response) < 12 || binary.BigEndian.Uint16(response[:2]) != id || response[3]&0x0f != 0 {
		s.Severity, s.Message = Error, "invalid DNS response"
		return s
	}
	s.Success = true
	s.Severity, s.Message = classifyLatency(s.DurationMS, "DNS response")
	return s
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
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: probeType, Target: url, Severity: Info}
	var dnsStart, connectStart, tlsStart, wroteRequest time.Time
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				s.DNSMS = ms(time.Since(dnsStart))
			}
		},
		ConnectStart: func(_, _ string) { connectStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connectStart.IsZero() {
				s.ConnectMS = ms(time.Since(connectStart))
			}
		},
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
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	req.Header.Set("User-Agent", "stormwarden/1.0")
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second}}
	resp, err := client.Do(req)
	if err != nil {
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	defer resp.Body.Close()
	s.StatusCode = resp.StatusCode
	bodyReadStarted := time.Now()
	s.Bytes, err = io.Copy(io.Discard, io.LimitReader(resp.Body, limit))
	s.DurationMS = ms(time.Since(started))
	bodyDuration := time.Since(bodyReadStarted)
	if err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	statusInvalid := expectedStatus > 0 && resp.StatusCode != expectedStatus
	if expectedStatus == 0 {
		statusInvalid = resp.StatusCode < 200 || resp.StatusCode >= 400
	}
	if statusInvalid {
		s.Severity, s.Message = Error, fmt.Sprintf("unexpected HTTP status %d", resp.StatusCode)
		return s
	}
	s.Success = true
	if probeType == "transfer" {
		if s.Bytes != limit {
			s.Success, s.Severity, s.Message = false, Error, fmt.Sprintf("short transfer: received %d of %d bytes", s.Bytes, limit)
			return s
		}
		if bodyDuration <= 0 {
			bodyDuration = time.Microsecond
		}
		s.Mbps = float64(s.Bytes*8) / bodyDuration.Seconds() / 1_000_000
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
