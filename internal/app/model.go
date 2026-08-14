package app

import "time"

type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Error    Severity = "error"
	Critical Severity = "critical"
)

type Sample struct {
	ID              int64     `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	ProbeType       string    `json:"probe_type"`
	Target          string    `json:"target"`
	Severity        Severity  `json:"severity"`
	Success         bool      `json:"success"`
	DurationMS      float64   `json:"duration_ms"`
	DNSMS           float64   `json:"dns_ms,omitempty"`
	ConnectMS       float64   `json:"connect_ms,omitempty"`
	TLSMS           float64   `json:"tls_ms,omitempty"`
	TTFBMS          float64   `json:"ttfb_ms,omitempty"`
	Bytes           int64     `json:"bytes,omitempty"`
	Mbps            float64   `json:"mbps,omitempty"`
	StatusCode      int       `json:"status_code,omitempty"`
	Message         string    `json:"message,omitempty"`
	connectFailed   bool
	dnsQueryName    string
	dnsQueryAt      time.Time
	incidentContext string
}

type Incident struct {
	ID        int64      `json:"id"`
	StartedAt time.Time  `json:"started_at"`
	EndedAt   *time.Time `json:"ended_at,omitempty"`
	Severity  Severity   `json:"severity"`
	Category  string     `json:"category"`
	Summary   string     `json:"summary"`
	Evidence  string     `json:"evidence"`
}

type DashboardSummary struct {
	Severity       Severity
	Status         string
	LastSampleAt   time.Time
	Availability24 float64
	Warnings24     int
	Errors24       int
	Critical24     int
	ActiveIncident *Incident
}
