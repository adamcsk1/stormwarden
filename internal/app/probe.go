package app

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
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
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	id := binary.BigEndian.Uint16(idBytes)
	query := dnsQuery(id, "example.com")
	response, err := exchangeDNS(ctx, "udp", address, query)
	transport := "udp"
	if err == nil && len(response) >= 4 && response[2]&0x02 != 0 {
		response, err = exchangeDNS(ctx, "tcp", address, query)
		transport = "tcp"
	}
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
		s.Message = "healthy over " + transport
	}
	return s
}

func probeDNSTCP(ctx context.Context, target, address string) Sample {
	started := time.Now()
	s := Sample{CreatedAt: started, ProbeType: "dns", Target: target, Severity: Info}
	idBytes := make([]byte, 2)
	if _, err := rand.Read(idBytes); err != nil {
		s.Severity, s.Message = Error, err.Error()
		return s
	}
	id := binary.BigEndian.Uint16(idBytes)
	query := dnsQuery(id, "example.com")
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
		s.Message = "healthy over tcp"
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
	questionLength := len(query) - 12
	if len(response) < 12+questionLength {
		return errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(response[:2]) != id {
		return errors.New("DNS response ID mismatch")
	}
	if response[2]&0x80 == 0 || response[2]&0x78 != 0 {
		return errors.New("invalid DNS response flags")
	}
	if response[3]&0x0f != 0 {
		return fmt.Errorf("DNS response code %d", response[3]&0x0f)
	}
	if binary.BigEndian.Uint16(response[4:6]) != 1 || binary.BigEndian.Uint16(response[6:8]) == 0 {
		return errors.New("DNS response has no answer")
	}
	if !bytes.Equal(response[12:12+questionLength], query[12:]) {
		return errors.New("DNS response question mismatch")
	}
	if !validDNSAnswer(response, 12+questionLength) {
		return errors.New("malformed DNS answer")
	}
	return nil
}

func validDNSAnswer(response []byte, offset int) bool {
	if offset >= len(response) {
		return false
	}
	if response[offset]&0xc0 == 0xc0 {
		offset += 2
	} else {
		for {
			if offset >= len(response) {
				return false
			}
			length := int(response[offset])
			offset++
			if length == 0 {
				break
			}
			if length > 63 || offset+length > len(response) {
				return false
			}
			offset += length
		}
	}
	if offset+10 > len(response) {
		return false
	}
	rdLength := int(binary.BigEndian.Uint16(response[offset+8 : offset+10]))
	return offset+10+rdLength <= len(response)
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
		s.Severity, s.Message = Error, redactHTTPError(err, url)
		return s
	}
	req.Header.Set("User-Agent", "stormwarden/1.0")
	dialer := &net.Dialer{}
	if dnsAddress != "" {
		dialer.Resolver = &net.Resolver{PreferGo: true, Dial: func(resolveCtx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(resolveCtx, "tcp", dnsAddress)
		}}
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true, TLSHandshakeTimeout: 4 * time.Second, DialContext: dialer.DialContext}}
	resp, err := client.Do(req)
	if err != nil {
		s.DurationMS = ms(time.Since(started))
		s.Severity, s.Message = Error, redactHTTPError(err, url)
		return s
	}
	defer resp.Body.Close()
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
