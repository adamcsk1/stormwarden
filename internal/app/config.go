package app

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	ListenAddr         string
	Password           string
	DataPath           string
	ExportDir          string
	PiHoleAddr         string
	PublicDNS          string
	DoHURL             string
	AssetTargets       string
	HTTPURL            string
	HTTPDNSAddr        string
	TransferURL        string
	HTTPExpectedStatus int
	Timezone           *time.Location
	CookieSecure       bool
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
	expectedStatus, err := strconv.Atoi(env("HTTP_EXPECTED_STATUS", "204"))
	if err != nil || expectedStatus < 0 || expectedStatus > 599 || (expectedStatus > 0 && expectedStatus < 100) {
		return Config{}, errors.New("HTTP_EXPECTED_STATUS must be 0 or a valid HTTP status")
	}
	piholeAddr := env("PIHOLE_DNS_ADDR", "127.0.0.1:53")
	assetTargets := env("ASSET_PROBES", defaultAssetTargets)
	if _, err := parseAssetTargets(assetTargets); err != nil {
		return Config{}, err
	}
	return Config{
		ListenAddr:         env("APP_LISTEN_ADDR", ":8080"),
		Password:           password,
		DataPath:           env("DATA_PATH", "data/stormwarden.db"),
		ExportDir:          env("EXPORT_DIR", "data/exports"),
		PiHoleAddr:         piholeAddr,
		PublicDNS:          env("PUBLIC_DNS_ADDR", "1.1.1.1:53"),
		DoHURL:             env("DOH_PROBE_URL", "https://1.1.1.1/dns-query"),
		AssetTargets:       assetTargets,
		HTTPURL:            env("HTTP_PROBE_URL", "https://www.google.com/generate_204"),
		HTTPDNSAddr:        env("HTTP_DNS_ADDR", piholeAddr),
		TransferURL:        env("TRANSFER_PROBE_URL", "https://speed.cloudflare.com/__down?bytes=262144"),
		HTTPExpectedStatus: expectedStatus,
		Timezone:           location,
		CookieSecure:       secure,
	}, nil
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
