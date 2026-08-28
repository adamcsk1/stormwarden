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
	diagnosis       *Diagnosis
}

type Incident struct {
	ID             int64      `json:"id"`
	StartedAt      time.Time  `json:"started_at"`
	EndedAt        *time.Time `json:"ended_at,omitempty"`
	Severity       Severity   `json:"severity"`
	Category       string     `json:"category"`
	Summary        string     `json:"summary"`
	Evidence       string     `json:"evidence"`
	Confidence     string     `json:"confidence,omitempty"`
	Contradictions string     `json:"contradictions,omitempty"`
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

type Diagnosis struct {
	Classification string   `json:"classification"`
	Confidence     string   `json:"confidence"`
	Severity       Severity `json:"severity"`
	Evidence       []string `json:"evidence"`
	Contradictions []string `json:"contradictions,omitempty"`
	Summary        string   `json:"summary"`
}

type incidentEvidenceDoc struct {
	Classification string   `json:"classification,omitempty"`
	Confidence     string   `json:"confidence,omitempty"`
	Evidence       []string `json:"evidence,omitempty"`
	Contradictions []string `json:"contradictions,omitempty"`
	Events         []string `json:"events,omitempty"`
}

type Annotation struct {
	ID        int64     `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Note      string    `json:"note"`
}

type NetInfo struct {
	ContainerIP      string `json:"container_ip,omitempty"`
	DockerGateway    string `json:"docker_gateway,omitempty"`
	DefaultGateway   string `json:"default_gateway,omitempty"`
	LANGateway       string `json:"lan_gateway,omitempty"`
	LANGatewaySource string `json:"lan_gateway_source,omitempty"`
	ISPHop           string `json:"isp_hop,omitempty"`
	HostNetwork      bool   `json:"host_network"`
	DefaultIface     string `json:"default_iface,omitempty"`
	Note             string `json:"note,omitempty"`
}
