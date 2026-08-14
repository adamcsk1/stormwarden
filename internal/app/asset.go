package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	legacyDefaultAssetTargets = "YouTube thumbnail|https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg"
	defaultAssetTargets       = legacyDefaultAssetTargets + ";Cloudflare cache-busted|cache-bust|https://speed.cloudflare.com/__down?bytes=32768"
	assetDownloadLimit        = 512 * 1024
	maxAssetTargets           = 8
	fixedAssetInterval        = 30 * time.Second
	cacheBustInterval         = 5 * time.Minute
)

type AssetTarget struct {
	Name      string
	URL       string
	CacheBust bool
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
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 2 {
			if len(parts) != 3 || strings.TrimSpace(parts[1]) != "cache-bust" {
				parts = strings.SplitN(line, "|", 2)
			}
		}
		if len(parts) < 2 {
			return nil, errors.New("asset probes must use Name|URL or Name|cache-bust|URL format")
		}
		name, rawURL, cacheBust := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), false
		if len(parts) == 3 && rawURL == "cache-bust" {
			rawURL, cacheBust = strings.TrimSpace(parts[2]), true
		}
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
		result = append(result, AssetTarget{Name: name, URL: rawURL, CacheBust: cacheBust})
		if len(result) > maxAssetTargets {
			return nil, errors.New("at most 8 asset probes are allowed")
		}
	}
	return result, nil
}

func assetSampleTarget(target AssetTarget) string {
	if target.CacheBust {
		return "asset-cache-bust:" + target.Name + "|" + redactURL(target.URL)
	}
	return "asset:" + target.Name + "|" + redactURL(target.URL)
}
func assetIncidentCategory(target AssetTarget) string {
	if target.CacheBust {
		return "asset_cache_bust:" + target.Name
	}
	return "asset_path:" + target.Name
}

func isAssetIncidentCategory(category string) bool {
	return strings.HasPrefix(category, "asset_path:") || strings.HasPrefix(category, "asset_cache_bust:")
}

func assetSampleName(target string) string {
	target = strings.TrimPrefix(target, "asset-cache-bust:")
	target = strings.TrimPrefix(target, "asset:")
	name, _, _ := strings.Cut(target, "|")
	return name
}

func probeAsset(ctx context.Context, target AssetTarget, dnsAddress string) Sample {
	probeURL := target.URL
	if target.CacheBust {
		probeURL = cacheBustedAssetURL(probeURL, strconv.FormatInt(time.Now().UnixNano(), 36))
	}
	sample := probeHTTPStatusResolver(ctx, "asset", probeURL, assetDownloadLimit, 0, dnsAddress)
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

func cacheBustedAssetURL(rawURL, nonce string) string {
	parsed, _ := url.Parse(rawURL)
	query := parsed.Query()
	query.Set("stormwarden", nonce)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func assetProbeTimeout() time.Duration { return 15 * time.Second }
