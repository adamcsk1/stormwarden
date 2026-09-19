package app

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type TCPControl struct {
	Name    string
	Address string
}

type Config struct {
	ListenAddr             string
	Password               string
	DataPath               string
	ExportDir              string
	PiHoleAddr             string
	PiHoleAPIURL           string
	PiHoleAPIPassword      string
	PublicDNS              string
	DoHURL                 string
	AssetTargets           string
	HTTPURL                string
	HTTPDNSAddr            string
	TransferURL            string
	HTTPExpectedStatus     int
	Timezone               *time.Location
	CookieSecure           bool
	PingEnabled            bool
	PingPiholeAddr         string
	GatewayAddr            string
	ISPHopAddr             string
	ISPHopAuto             bool
	PingInternetAddr       string
	BurstCount             int
	BurstInterval          time.Duration
	BurstCooldown          time.Duration
	BurstTimeout           time.Duration
	TCPControls            []TCPControl
	TracerouteEnabled      bool
	TracerouteMaxHops      int
	TracerouteCooldown     time.Duration
	NICStatsEnabled        bool
	SMTPHost               string
	SMTPPort               int
	SMTPUser               string
	SMTPPassword           string
	SMTPFrom               string
	SMTPTo                 string
	SMTPStartTLS           bool
	SMTPSSL                bool
	SMTPInsecureSkipVerify bool
}

var defaultTCPControls = []TCPControl{
	{Name: "cloudflare", Address: "1.1.1.1:443"},
	{Name: "google", Address: "8.8.8.8:443"},
	{Name: "quad9", Address: "9.9.9.9:443"},
}

func LoadConfig() (Config, error) {
	password := os.Getenv("APP_PASSWORD")
	if password == "" {
		return Config{}, errors.New("APP_PASSWORD is required")
	}
	location, err := time.LoadLocation(env("APP_TIMEZONE", "Europe/Budapest"))
	if err != nil {
		return Config{}, err
	}
	secure, err := strconv.ParseBool(env("APP_COOKIE_SECURE", "false"))
	if err != nil {
		return Config{}, errors.New("APP_COOKIE_SECURE must be true or false")
	}
	allowInsecurePiHoleAPI, err := strconv.ParseBool(env("PIHOLE_API_ALLOW_INSECURE_HTTP", "false"))
	if err != nil {
		return Config{}, errors.New("PIHOLE_API_ALLOW_INSECURE_HTTP must be true or false")
	}
	expectedStatus, err := strconv.Atoi(env("HTTP_EXPECTED_STATUS", "204"))
	if err != nil || expectedStatus < 0 || expectedStatus > 599 || (expectedStatus > 0 && expectedStatus < 100) {
		return Config{}, errors.New("HTTP_EXPECTED_STATUS must be 0 or a valid HTTP status")
	}
	piholeAddr := env("PIHOLE_DNS_ADDR", "127.0.0.1:53")
	assetTargets := env("ASSET_PROBES", defaultAssetTargets)
	if _, err := parseAssetTargets(assetTargets); err != nil {
		return Config{}, err
	}
	piholeAPIURL := strings.TrimRight(os.Getenv("PIHOLE_API_URL"), "/")
	piholeAPIPassword := os.Getenv("PIHOLE_API_PASSWORD")
	if (piholeAPIURL == "") != (piholeAPIPassword == "") {
		return Config{}, errors.New("PIHOLE_API_URL and PIHOLE_API_PASSWORD must be set together")
	}
	if piholeAPIURL != "" {
		parsed, err := url.Parse(piholeAPIURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return Config{}, errors.New("PIHOLE_API_URL must be an HTTP(S) URL without credentials, query, or fragment")
		}
		if parsed.Scheme == "http" && !allowInsecurePiHoleAPI {
			return Config{}, errors.New("HTTP PIHOLE_API_URL requires PIHOLE_API_ALLOW_INSECURE_HTTP=true")
		}
	}
	controls, err := parseTCPControls(env("TCP_CONTROLS", "cloudflare|1.1.1.1:443;google|8.8.8.8:443;quad9|9.9.9.9:443"))
	if err != nil {
		return Config{}, err
	}
	pingEnabled, err := envBool("PING_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	ispAuto, err := envBool("ISP_HOP_AUTO", true)
	if err != nil {
		return Config{}, err
	}
	traceEnabled, err := envBool("TRACEROUTE_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	nicEnabled, err := envBool("NIC_STATS_ENABLED", true)
	if err != nil {
		return Config{}, err
	}
	burstCount, err := envInt("DIAG_BURST_COUNT", 10)
	if err != nil || burstCount < 1 || burstCount > 20 {
		return Config{}, errors.New("DIAG_BURST_COUNT must be 1-20")
	}
	burstIntervalMS, err := envInt("DIAG_BURST_INTERVAL_MS", 150)
	if err != nil || burstIntervalMS < 50 || burstIntervalMS > 1000 {
		return Config{}, errors.New("DIAG_BURST_INTERVAL_MS must be 50-1000")
	}
	burstCooldown, err := envDuration("DIAG_BURST_COOLDOWN", "2m")
	if err != nil {
		return Config{}, errors.New("DIAG_BURST_COOLDOWN must be a duration")
	}
	burstTimeout, err := envDuration("DIAG_BURST_TIMEOUT", "8s")
	if err != nil {
		return Config{}, errors.New("DIAG_BURST_TIMEOUT must be a duration")
	}
	traceHops, err := envInt("TRACEROUTE_MAX_HOPS", 15)
	if err != nil || traceHops < 3 || traceHops > 30 {
		return Config{}, errors.New("TRACEROUTE_MAX_HOPS must be 3-30")
	}
	traceCooldown, err := envDuration("TRACEROUTE_COOLDOWN", "10m")
	if err != nil {
		return Config{}, errors.New("TRACEROUTE_COOLDOWN must be a duration")
	}
	smtpHost := strings.TrimSpace(os.Getenv("SMTP_HOST"))
	smtpTo := strings.TrimSpace(os.Getenv("SMTP_TO"))
	if (smtpHost == "") != (smtpTo == "") {
		return Config{}, errors.New("SMTP_HOST and SMTP_TO must be set together")
	}
	if smtpTo != "" && len(smtpRecipients(smtpTo)) == 0 {
		return Config{}, errors.New("SMTP_TO must list at least one recipient")
	}
	smtpPort, err := envInt("SMTP_PORT", 587)
	if err != nil || smtpPort < 1 || smtpPort > 65535 {
		return Config{}, errors.New("SMTP_PORT must be between 1 and 65535")
	}
	smtpStartTLS, err := envBool("SMTP_STARTTLS", true)
	if err != nil {
		return Config{}, err
	}
	smtpSSL, err := envBool("SMTP_SSL", false)
	if err != nil {
		return Config{}, err
	}
	smtpInsecure, err := envBool("SMTP_INSECURESKIPVERIFY", false)
	if err != nil {
		return Config{}, err
	}
	return Config{
		ListenAddr:             env("APP_LISTEN_ADDR", ":8080"),
		Password:               password,
		DataPath:               env("DATA_PATH", "data/stormwarden.db"),
		ExportDir:              env("EXPORT_DIR", "data/exports"),
		PiHoleAddr:             piholeAddr,
		PiHoleAPIURL:           piholeAPIURL,
		PiHoleAPIPassword:      piholeAPIPassword,
		PublicDNS:              env("PUBLIC_DNS_ADDR", "1.1.1.1:53"),
		DoHURL:                 env("DOH_PROBE_URL", "https://1.1.1.1/dns-query"),
		AssetTargets:           assetTargets,
		HTTPURL:                env("HTTP_PROBE_URL", "https://www.google.com/generate_204"),
		HTTPDNSAddr:            env("HTTP_DNS_ADDR", piholeAddr),
		TransferURL:            env("TRANSFER_PROBE_URL", "https://speed.cloudflare.com/__down?bytes=262144"),
		HTTPExpectedStatus:     expectedStatus,
		Timezone:               location,
		CookieSecure:           secure,
		PingEnabled:            pingEnabled,
		PingPiholeAddr:         env("PING_PIHOLE_ADDR", hostOnly(piholeAddr)),
		GatewayAddr:            os.Getenv("GATEWAY_ADDR"),
		ISPHopAddr:             os.Getenv("ISP_HOP_ADDR"),
		ISPHopAuto:             ispAuto,
		PingInternetAddr:       env("PING_INTERNET_ADDR", "1.1.1.1"),
		BurstCount:             burstCount,
		BurstInterval:          time.Duration(burstIntervalMS) * time.Millisecond,
		BurstCooldown:          burstCooldown,
		BurstTimeout:           burstTimeout,
		TCPControls:            controls,
		TracerouteEnabled:      traceEnabled,
		TracerouteMaxHops:      traceHops,
		TracerouteCooldown:     traceCooldown,
		NICStatsEnabled:        nicEnabled,
		SMTPHost:               smtpHost,
		SMTPPort:               smtpPort,
		SMTPUser:               os.Getenv("SMTP_USER"),
		SMTPPassword:           os.Getenv("SMTP_PASSWORD"),
		SMTPFrom:               strings.TrimSpace(os.Getenv("SMTP_FROM")),
		SMTPTo:                 smtpTo,
		SMTPStartTLS:           smtpStartTLS,
		SMTPSSL:                smtpSSL,
		SMTPInsecureSkipVerify: smtpInsecure,
	}, nil
}

func (c Config) tcpControls() []TCPControl {
	if len(c.TCPControls) > 0 {
		return c.TCPControls
	}
	return defaultTCPControls
}

func parseTCPControls(value string) ([]TCPControl, error) {
	var controls []TCPControl
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, address, ok := strings.Cut(part, "|")
		name, address = strings.TrimSpace(name), strings.TrimSpace(address)
		if !ok || name == "" || address == "" {
			return nil, errors.New("TCP_CONTROLS entries must be name|host:port")
		}
		if _, _, err := net.SplitHostPort(address); err != nil {
			return nil, errors.New("TCP_CONTROLS address must be host:port")
		}
		controls = append(controls, TCPControl{Name: name, Address: address})
	}
	if len(controls) == 0 {
		return nil, errors.New("TCP_CONTROLS must list at least one target")
	}
	if len(controls) > 6 {
		return nil, errors.New("TCP_CONTROLS supports at most 6 targets")
	}
	return controls, nil
}

func tcpSampleTarget(name string) string { return "tcp:" + name }

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envBool(key string, fallback bool) (bool, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, errors.New(key + " must be true or false")
	}
	return parsed, nil
}

func envInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	return strconv.Atoi(value)
}

func envDuration(key, fallback string) (time.Duration, error) {
	return time.ParseDuration(env(key, fallback))
}
