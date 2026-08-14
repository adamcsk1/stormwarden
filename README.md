# Stormwarden

Dockerized Go service for recording intermittent DNS and internet performance problems. It compares Pi-hole TCP DNS with public DNS, measures TCP connectivity and HTTP phases, records incidents, and provides password-protected HTMX reports.

## Measurements

- Uncached Pi-hole TCP and UDP checks on standard port `53`
- Direct Cloudflare UDP and DNS-over-HTTPS control checks
- Independent TCP internet connectivity
- HTTP DNS, connect, TLS, time-to-first-byte, total duration, and status
- Optional bounded transfer-speed test
- Correlated warning, error, and critical incidents

Probe traffic profiles are selectable in UI:

| Profile | Transfer probe | Estimated traffic |
| --- | --- | --- |
| Minimal | Disabled | Very low |
| Low | 256 KiB every 15 minutes | About 0.75 GB/month |
| Detailed | 5 MiB every 15 minutes | About 15 GB/month |

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
| `PUBLIC_DNS_ADDR` | `1.1.1.1:53` | Control DNS endpoint |
| `DOH_PROBE_URL` | Cloudflare DoH | DNS-over-HTTPS control endpoint |
| `HTTP_PROBE_URL` | Google 204 endpoint | Small HTTP timing target |
| `HTTP_DNS_ADDR` | `PIHOLE_DNS_ADDR` | Explicit resolver used by HTTP probes |
| `HTTP_EXPECTED_STATUS` | `204` | Required probe response; use `0` for any 2xx/3xx |
| `TRANSFER_PROBE_URL` | Cloudflare speed endpoint | Bounded transfer target |
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

Generated reports run through one background worker and expire after 7 days. Raw measurements retain 30 days; compact 15-minute, hourly, and daily rollups plus incident history remain available. Reports support day, week, month, custom, and all-history ranges. Cleanup runs daily.

Report targets remove URL credentials, query strings, and fragments before persistence. Rollups preserve resolver target plus DNS, connection, TLS, TTFB, and transfer measurements.

Pi-hole should continue listening on its standard LAN port `53`. A local dnsproxy listener such as `127.0.0.1:5053` is an internal Pi-hole upstream and must not be configured as Stormwarden's Pi-hole address.

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
