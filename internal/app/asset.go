package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	defaultAssetTargets = "YouTube thumbnail|https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
	assetDownloadLimit  = 512 * 1024
	maxAssetTargets     = 8
)

type AssetTarget struct {
	Name string
	URL  string
}

func parseAssetTargets(value string) ([]AssetTarget, error) {
	value = strings.ReplaceAll(value, ";", "\n")
	lines := strings.Split(value, "\n")
	result := make([]AssetTarget, 0, len(lines))
	seen := make(map[string]bool)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			return nil, errors.New("asset probes must use Name|URL format")
		}
		name, rawURL := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if name == "" || len(name) > 60 {
			return nil, errors.New("asset probe name must contain 1-60 characters")
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate asset probe name %q", name)
		}
		parsed, err := url.Parse(rawURL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
			return nil, fmt.Errorf("invalid asset URL for %q", name)
		}
		if parsed.User != nil {
			return nil, fmt.Errorf("asset URL for %q must not contain credentials", name)
		}
		seen[name] = true
		result = append(result, AssetTarget{Name: name, URL: rawURL})
		if len(result) > maxAssetTargets {
			return nil, errors.New("at most 8 asset probes are allowed")
		}
	}
	return result, nil
}

func assetSampleTarget(target AssetTarget) string {
	return "asset:" + target.Name + "|" + redactURL(target.URL)
}
func assetIncidentCategory(name string) string { return "asset_path:" + name }

func assetSampleName(target string) string {
	name, _, _ := strings.Cut(strings.TrimPrefix(target, "asset:"), "|")
	return name
}

func probeAsset(ctx context.Context, target AssetTarget, dnsAddress string) Sample {
	sample := probeHTTPStatusResolver(ctx, "asset", target.URL, assetDownloadLimit, 0, dnsAddress)
	sample.Target = assetSampleTarget(target)
	if sample.Success {
		if sample.Bytes == 0 {
			sample.Success, sample.Severity, sample.Message = false, Error, "asset response was empty"
		} else if sample.DurationMS > 5000 {
			sample.Severity, sample.Message = Error, "asset load exceeded 5 seconds"
		} else if sample.DurationMS > 2000 {
			sample.Severity, sample.Message = Warning, "asset load exceeded 2 seconds"
		}
	}
	return sample
}

func assetProbeTimeout() time.Duration { return 15 * time.Second }
