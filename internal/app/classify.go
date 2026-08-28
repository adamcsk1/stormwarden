package app

import (
	"fmt"
	"math"
	"strings"
)

const retransmissionWindowMS = 150

func retransmissionSuspected(ms float64) bool {
	if ms <= 0 {
		return false
	}
	for _, center := range []float64{1000, 2000, 3000} {
		if math.Abs(ms-center) <= retransmissionWindowMS {
			return true
		}
	}
	return ms >= 3850
}

func retransmissionNote() string {
	return "TCP connection timing is consistent with SYN/SYN-ACK retransmission behavior."
}

type Snapshot struct {
	Samples  []Sample
	Baseline *Baseline
}

type extracted struct {
	byTarget                                   map[string]Sample
	tcp                                        []Sample
	http                                       Sample
	hasHTTP                                    bool
	bursts                                     map[string]Sample
	nic                                        *Sample
	baseline                                   *Baseline
	pihole, piholeUDP                          Sample
	publicDNS, doh                             Sample
	hasPihole, hasPiholeUDP, hasPublic, hasDoH bool
}

func extract(s Snapshot) extracted {
	e := extracted{byTarget: map[string]Sample{}, bursts: map[string]Sample{}, baseline: s.Baseline}
	for _, sample := range s.Samples {
		e.byTarget[sample.Target] = sample
		switch sample.ProbeType {
		case "tcp":
			e.tcp = append(e.tcp, sample)
		case "http":
			e.http, e.hasHTTP = sample, true
		case "icmp-burst":
			e.bursts[strings.TrimPrefix(sample.Target, "icmp:")] = sample
		case "nic":
			copy := sample
			e.nic = &copy
		}
	}
	e.pihole, e.hasPihole = e.byTarget["pihole"]
	e.piholeUDP, e.hasPiholeUDP = e.byTarget["pihole-udp"]
	e.publicDNS, e.hasPublic = e.byTarget["public-dns"]
	e.doh, e.hasDoH = e.byTarget["direct-doh"]
	return e
}

func classify(s Snapshot) Diagnosis {
	e := extract(s)
	d := Diagnosis{Classification: "unknown", Confidence: "low", Severity: Warning, Summary: "Insufficient evidence to locate the failure."}

	if e.nicRising() && e.loss("gateway") > 0 && e.loss("pihole") > 0 {
		return e.finish(Diagnosis{
			Classification: "host_or_nic", Confidence: "high", Severity: Error,
			Evidence: e.collect("NIC counters increased during this incident", "gateway packet loss "+e.lossText("gateway"), "pihole packet loss "+e.lossText("pihole")),
			Summary:  "Local NIC or host path likely: interface error/drop counters rose while LAN pings also lost packets.",
		})
	}
	if e.nicRising() {
		return e.finish(Diagnosis{
			Classification: "host_or_nic", Confidence: "medium", Severity: Error,
			Evidence: e.collect(e.nic.Message),
			Summary:  "Local NIC counters increased. Host, cable, or driver problem possible; LAN vs NIC not fully separable.",
		})
	}

	if e.hasPihole && e.hasPiholeUDP && !e.pihole.Success && !e.piholeUDP.Success && e.publicOK() && e.dohOK() {
		conf, extra := "medium", []string{}
		if e.layerOK("gateway") && e.layerOK("internet") {
			conf = "high"
		}
		if !e.layerOK("gateway") && e.hasBurst("gateway") {
			extra = append(extra, "gateway probe was not healthy")
		}
		return e.finish(Diagnosis{
			Classification: "local_dns", Confidence: conf, Severity: Error,
			Evidence:       e.collect("Pi-hole TCP failed", "Pi-hole UDP failed", "external DNS controls succeeded"),
			Contradictions: extra,
			Summary:        "Pi-hole DNS failed while public DNS and DoH succeeded.",
		})
	}

	if e.tcpIPHealthy() && e.layerOKOrUnknown("internet") && e.dnsFailed() {
		return e.finish(Diagnosis{
			Classification: "dns_resolution_failure", Confidence: "high", Severity: Error,
			Evidence: e.collect("TCP-to-IP controls succeeded", "DNS controls failed"),
			Summary:  "IP connectivity works; DNS resolution failed.",
		})
	}

	if e.hasBurst("gateway") && e.hasBurst("pihole") && e.loss("gateway") > 0 && e.loss("pihole") > 0 {
		return e.finish(Diagnosis{
			Classification: "local_network_or_host", Confidence: "high", Severity: Error,
			Evidence: e.collect("gateway packet loss "+e.lossText("gateway"), "pihole packet loss "+e.lossText("pihole")),
			Summary:  "Packet loss to both gateway and Pi-hole. Host, cable, or LAN switching likely. Not distinguished further.",
		})
	}

	if e.hasBurst("gateway") && e.loss("gateway") >= 100 {
		return e.finish(Diagnosis{
			Classification: "gateway_or_router", Confidence: "medium", Severity: Critical,
			Evidence:       e.collect("gateway unreachable (100% packet loss)"),
			Contradictions: e.contradictIf(e.layerOK("pihole"), "Pi-hole ping remained healthy"),
			Summary:        "Default gateway did not answer ICMP. ICMP can be blocked; treat as supporting evidence only.",
		})
	}

	if e.hasBurst("gateway") && e.loss("gateway") > 0 && e.layerOK("pihole") {
		return e.finish(Diagnosis{
			Classification: "gateway_or_router", Confidence: "medium", Severity: Error,
			Evidence: e.collect("gateway packet loss "+e.lossText("gateway"), "pihole ping healthy"),
			Summary:  "Gateway ICMP loss with a healthy Pi-hole ping. Router or WAN-facing LAN port possible. ICMP is not proof.",
		})
	}

	badTCP, goodTCP, retransTCP := e.tcpCounts()
	if badTCP == 1 && goodTCP >= 1 && e.layerOKOrUnknown("gateway") && e.dnsMostlyOK() {
		var badName string
		for _, t := range e.tcp {
			if t.Severity != Info {
				badName = t.Target
				break
			}
		}
		return e.finish(Diagnosis{
			Classification: "destination_or_route_specific", Confidence: "high", Severity: Warning,
			Evidence: e.collect(fmt.Sprintf("1/%d TCP controls degraded (%s)", badTCP+goodTCP, badName), fmt.Sprintf("%d independent TCP controls healthy", goodTCP)),
			Summary:  "One TCP control failed while others stayed healthy. Destination or path-specific, not a general outage.",
		})
	}

	if e.httpTLSOnly() {
		return e.finish(Diagnosis{
			Classification: "tls_or_remote_service", Confidence: "high", Severity: Warning,
			Evidence: e.collect("DNS healthy", "TCP connect healthy", fmt.Sprintf("TLS handshake %.0fms", e.http.TLSMS)),
			Summary:  "TLS handshake was slow or failed after a healthy TCP connect. Remote service or TLS path more likely than local WAN loss.",
		})
	}

	if e.httpServerOnly() {
		return e.finish(Diagnosis{
			Classification: "http_or_server", Confidence: "medium", Severity: Warning,
			Evidence: e.collect("TCP connect healthy", "TLS healthy", fmt.Sprintf("TTFB %.0fms status %d", e.http.TTFBMS, e.http.StatusCode)),
			Summary:  "HTTP application timing or status failed after healthy connect and TLS.",
		})
	}

	upstreamLoss := e.upstreamLoss()
	gatewayHealthy := e.layerOKOrUnknown("gateway")
	piholeHealthy := e.piholeHealthy()
	if gatewayHealthy && piholeHealthy && (upstreamLoss > 0 || (badTCP >= 2 && retransTCP >= 1) || (badTCP >= 1 && retransTCP >= 1 && e.httpConnectSlow() && goodTCP == 0)) {
		conf := "medium"
		if upstreamLoss > 0 && badTCP >= 2 {
			conf = "high"
		}
		if upstreamLoss > 0 && retransTCP >= 1 {
			conf = "high"
		}
		ev := e.collect("gateway packet loss "+e.lossTextOr("gateway", "not sampled"), "pihole remained healthy")
		if upstreamLoss > 0 {
			ev = append(ev, fmt.Sprintf("internet/ISP target packet loss %.0f%%", upstreamLoss))
		}
		if badTCP > 0 {
			ev = append(ev, fmt.Sprintf("%d/%d tcp controls exceeded threshold", badTCP, badTCP+goodTCP))
		}
		if retransTCP > 0 {
			ev = append(ev, "tcp connect times clustered near retransmission intervals")
		}
		if e.dnsMostlyOK() {
			ev = append(ev, "dns controls remained healthy")
		}
		contra := []string{}
		if e.layerOK("isp_hop") && upstreamLoss > 0 && e.loss("internet") > 0 {
			contra = append(contra, "isp first-hop probe remained healthy")
		}
		if !e.hasBurst("internet") && !e.hasBurst("isp_hop") {
			contra = append(contra, "no ICMP burst yet; WAN/ISP inferred from TCP timing only")
		}
		sev := Warning
		if badTCP >= 2 || upstreamLoss >= 20 || retransTCP >= 2 {
			sev = Error
		}
		return e.finish(Diagnosis{
			Classification: "wan_or_isp_packet_loss", Confidence: conf, Severity: sev,
			Evidence: ev, Contradictions: contra,
			Summary: "LAN DNS and gateway look healthy. Multiple outbound TCP paths show retransmission-like delays" + icmpClause(upstreamLoss) + ".",
		})
	}

	if retransTCP > 0 && e.dnsMostlyOK() {
		return e.finish(Diagnosis{
			Classification: "tcp_connect_establishment", Confidence: "medium", Severity: Warning,
			Evidence:       e.collect("tcp connect times clustered near retransmission intervals", "dns controls remained healthy"),
			Contradictions: e.contradictIf(!e.hasBurst("internet"), "no upstream ICMP burst to confirm packet loss"),
			Summary:        retransmissionNote() + " Independent ICMP evidence was not enough to name WAN vs destination.",
		})
	}

	if badTCP > 0 && e.dnsMostlyOK() {
		return e.finish(Diagnosis{
			Classification: "tcp_connect_establishment", Confidence: "low", Severity: Warning,
			Evidence: e.collect(fmt.Sprintf("%d TCP control(s) degraded", badTCP)),
			Summary:  "TCP connection degraded. Not enough independent evidence to locate the layer.",
		})
	}

	return e.finish(d)
}

func icmpClause(loss float64) string {
	if loss > 0 {
		return fmt.Sprintf("; upstream ICMP loss %.0f%%", loss)
	}
	return ""
}

func (e extracted) finish(d Diagnosis) Diagnosis {
	if e.baseline != nil && d.Classification != "unknown" {
		if note := e.baseline.note(e); note != "" {
			d.Evidence = append(d.Evidence, note)
		}
	}
	if d.Summary == "" {
		d.Summary = d.Classification
	}
	return d
}

func (e extracted) collect(parts ...string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (e extracted) contradictIf(cond bool, text string) []string {
	if cond {
		return []string{text}
	}
	return nil
}

func (e extracted) hasBurst(name string) bool {
	s, ok := e.bursts[name]
	return ok && !strings.Contains(s.Message, "icmp_unavailable")
}

func (e extracted) loss(name string) float64 {
	s, ok := e.bursts[name]
	if !ok || strings.Contains(s.Message, "icmp_unavailable") {
		return 0
	}
	return s.Mbps
}

func (e extracted) lossText(name string) string {
	return fmt.Sprintf("%.0f%%", e.loss(name))
}

func (e extracted) lossTextOr(name, missing string) string {
	if !e.hasBurst(name) {
		return missing
	}
	return e.lossText(name)
}

func (e extracted) layerOK(name string) bool {
	return e.hasBurst(name) && e.loss(name) == 0 && e.bursts[name].Success
}

func (e extracted) layerOKOrUnknown(name string) bool {
	if !e.hasBurst(name) {
		return true
	}
	return e.layerOK(name)
}

func (e extracted) upstreamLoss() float64 {
	return max(e.loss("internet"), e.loss("isp_hop"))
}

func (e extracted) publicOK() bool { return e.hasPublic && e.publicDNS.Success }
func (e extracted) dohOK() bool    { return e.hasDoH && e.doh.Success }

func (e extracted) dnsMostlyOK() bool {
	ok := 0
	n := 0
	for _, pair := range []struct {
		has bool
		s   Sample
	}{{e.hasPihole, e.pihole}, {e.hasPiholeUDP, e.piholeUDP}, {e.hasPublic, e.publicDNS}, {e.hasDoH, e.doh}} {
		if !pair.has {
			continue
		}
		n++
		if pair.s.Success && pair.s.Severity != Error {
			ok++
		}
	}
	return n > 0 && ok*2 >= n
}

func (e extracted) dnsFailed() bool {
	fails := 0
	n := 0
	for _, pair := range []struct {
		has bool
		s   Sample
	}{{e.hasPihole, e.pihole}, {e.hasPiholeUDP, e.piholeUDP}, {e.hasPublic, e.publicDNS}, {e.hasDoH, e.doh}} {
		if !pair.has {
			continue
		}
		n++
		if !pair.s.Success {
			fails++
		}
	}
	return n > 0 && fails*2 >= n
}

func (e extracted) piholeHealthy() bool {
	if e.hasBurst("pihole") {
		return e.layerOK("pihole")
	}
	return (!e.hasPihole || e.pihole.Success) && (!e.hasPiholeUDP || e.piholeUDP.Success)
}

func (e extracted) tcpIPHealthy() bool {
	if len(e.tcp) == 0 {
		return false
	}
	for _, t := range e.tcp {
		if !t.Success || t.Severity == Error {
			return false
		}
	}
	return true
}

func (e extracted) tcpCounts() (bad, good, retrans int) {
	for _, t := range e.tcp {
		if t.Severity == Info && t.Success {
			good++
			continue
		}
		bad++
		if retransmissionSuspected(t.ConnectMS) || retransmissionSuspected(t.DurationMS) {
			retrans++
		}
	}
	return
}

func (e extracted) httpConnectSlow() bool {
	return e.hasHTTP && (e.http.connectFailed || e.http.ConnectMS > 250)
}

func (e extracted) httpTLSOnly() bool {
	if !e.hasHTTP || e.http.Severity == Info {
		return false
	}
	connectOK := e.http.ConnectMS > 0 && e.http.ConnectMS <= 250 && !e.http.connectFailed
	return connectOK && e.http.TLSMS > 1500 && e.dnsMostlyOK()
}

func (e extracted) httpServerOnly() bool {
	if !e.hasHTTP || e.http.Severity == Info {
		return false
	}
	connectOK := e.http.ConnectMS > 0 && e.http.ConnectMS <= 250 && !e.http.connectFailed
	tlsOK := e.http.TLSMS <= 1500
	return connectOK && tlsOK && e.dnsMostlyOK() && (e.http.TTFBMS > 1000 || e.http.StatusCode >= 400 || !e.http.Success)
}

func (e extracted) nicRising() bool {
	return e.nic != nil && (e.nic.Bytes > 0 || e.nic.StatusCode > 0 || e.nic.DNSMS > 0 || e.nic.ConnectMS > 0)
}
