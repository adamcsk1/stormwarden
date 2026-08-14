# Stormwarden

Dockerized Go service for recording intermittent DNS and internet performance problems. It compares Pi-hole TCP DNS with public DNS, measures TCP connectivity and HTTP phases, records incidents, and provides password-protected HTMX reports.

## Measurements

- Uncached Pi-hole TCP and UDP checks on standard port `53`
- Direct Cloudflare UDP and DNS-over-HTTPS control checks
- Independent TCP internet connectivity
- HTTP DNS, connect, TLS, time-to-first-byte, total duration, and status
- Optional bounded transfer-speed test
- Configurable fixed asset loads every 30 seconds and cache-busted loads every 5 minutes, capped at 512 KiB each
- Correlated warning, error, and critical incidents
- Optional Pi-hole v6 query and FTL diagnostic correlation for Pi-hole-specific incidents

Probe traffic profiles are selectable in UI:

| Profile | Transfer probe | Estimated traffic |
| --- | --- | --- |
| Minimal | Disabled | Very low |
| Low | 256 KiB every 15 minutes | About 0.75 GB/month |
| Detailed | 5 MiB every 15 minutes | About 15 GB/month |

Asset traffic is separate from the selected profile. Configure up to eight targets in Probe settings. `Name|URL` runs every 30 seconds. `Name|cache-bust|URL` adds a random query and runs every 5 minutes. Downloads stop after 512 KiB. The defaults use a fixed 21 KiB YouTube thumbnail and a cache-busted 32 KiB Cloudflare test response, totaling about 2.1 GB/month.

## Run

Compose publishes the web interface on port `8080` by default. Set `APP_PORT` in `.env` to use another host port.

```sh
cp .env.example .env
# Edit APP_PASSWORD and PIHOLE_DNS_ADDR.
mkdir -p data
sudo chown -R 100:101 data
docker compose up -d --build
```

Open `http://HOST-IP:8080`.

Persistent database and generated reports are stored in the project-local `data/` directory.

For HTTPS behind reverse proxy, set `APP_COOKIE_SECURE=true`. Do not expose plain HTTP UI directly to internet.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_PASSWORD` | required | UI password |
| `PIHOLE_DNS_ADDR` | `127.0.0.1:53` | Pi-hole UDP endpoint with TCP fallback for truncated replies |
| `PIHOLE_API_URL` | disabled | Pi-hole v6 API base URL, such as `https://192.168.1.2/api` |
| `PIHOLE_API_PASSWORD` | disabled | Pi-hole v6 application password; must be set with `PIHOLE_API_URL` |
| `PIHOLE_API_ALLOW_INSECURE_HTTP` | `false` | Explicitly allow API credentials over HTTP on a trusted private network |
| `PUBLIC_DNS_ADDR` | `1.1.1.1:53` | Control DNS endpoint |
| `DOH_PROBE_URL` | Cloudflare DoH | DNS-over-HTTPS control endpoint |
| `HTTP_PROBE_URL` | Google 204 endpoint | Small HTTP timing target |
| `HTTP_DNS_ADDR` | `PIHOLE_DNS_ADDR` | Explicit resolver used by HTTP probes |
| `HTTP_EXPECTED_STATUS` | `204` | Required probe response; use `0` for any 2xx/3xx |
| `TRANSFER_PROBE_URL` | Cloudflare speed endpoint | Bounded transfer target |
| `ASSET_PROBES` | YouTube + Cloudflare test | Initial asset targets separated by semicolons; use `Name|cache-bust|URL` for five-minute randomized queries |
| `APP_TIMEZONE` | `Europe/Budapest` | Display timezone |
| `APP_COOKIE_SECURE` | `false` | Require HTTPS session cookies |
| `APP_PORT` | `8080` | Host port published by Docker Compose |
| `DATA_PATH` | `/data/stormwarden.db` | SQLite location in image |
| `EXPORT_DIR` | `/data/exports` | Generated reports |

## Diagnostic Reports

Dashboard generates last-day or last-week ZIP reports. Each report contains:

- `summary.md`: concise interpretation and aggregate counts
- `measurements.jsonl`: raw machine-readable probes
- `incidents.jsonl`: correlated problem log
- `settings-redacted.json`: diagnostic configuration without secrets
- `system-info.json`: runtime context

Raw asset measurements and rollups are included. `settings-redacted.json` lists configured asset names and URLs without credentials, query strings, or fragments.

Generated reports run through one background worker and expire after 7 days. Raw measurements retain 30 days; compact 15-minute, hourly, and daily rollups plus incident history remain available. Reports support day, week, month, custom, and all-history ranges. Cleanup runs daily.

Report targets remove URL credentials, query strings, and fragments before persistence. Rollups preserve resolver target plus DNS, connection, TLS, TTFB, and transfer measurements.

Pi-hole should continue listening on its standard LAN port `53`. A local dnsproxy listener such as `127.0.0.1:5053` is an internal Pi-hole upstream and must not be configured as Stormwarden's Pi-hole address.

For optional Pi-hole v6 incident correlation, create a dedicated application password in Pi-hole and set both `PIHOLE_API_URL` and `PIHOLE_API_PASSWORD`. Use HTTPS when possible. HTTP requires `PIHOLE_API_ALLOW_INSECURE_HTTP=true` and should only be used on a trusted private network because it exposes the application password and session ID in transit. Stormwarden does not poll the authenticated API continuously. The first Pi-hole-specific bad cycle opens one temporary API session, fetches the exact randomized probe query and recent FTL diagnosis types, logs out immediately, and then waits at least five minutes before another attempt. If logout cannot be confirmed, another login is blocked for 30 minutes, matching Pi-hole's default session lifetime. Generic TCP and HTTP incidents never contact the Pi-hole API. API failures remain supplemental evidence and do not affect availability or incident severity. FTL message text, client identifiers, unrelated query history, application passwords, and session IDs are never persisted or included in reports.

## Development

HTMX is committed as local static asset so UI remains functional during internet outages. Refresh pinned asset after dependency changes:

```sh
npm install
npm run vendor
go test ./...
go run ./cmd/stormwarden
```

`APP_PASSWORD` must be set for local execution.

## Current Limits

- No modem/router radio metrics yet. Weather or 4G/5G signal causation needs RSRP, RSRQ, SINR, band, and cell data from router API.
- No ICMP packet-loss or jitter probe yet. Current release diagnoses TCP, DNS, TLS, TTFB, and transfer behavior.
- In-memory sessions expire on application restart, requiring login again.
