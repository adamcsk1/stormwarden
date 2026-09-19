# Stormwarden

Dockerized Go service for diagnosing intermittent DNS and internet problems on a home network. It compares independent probes at each layer, classifies incidents with evidence and a confidence level, and serves password-protected HTMX reports.

## Diagnostic architecture

Stormwarden finds the lowest layer that is demonstrably healthy, then estimates where failure begins.

```
Stormwarden (host network)
     |
     +---- Pi-hole ICMP + uncached TCP/UDP DNS
     |
     +---- LAN Gateway ICMP
     |
     +---- ISP first hop ICMP (optional / auto)
     |
     +---- Public ICMP target
     |
     +---- TCP Target A (IP)
     +---- TCP Target B (IP)
     +---- TCP Target C (IP)
     |
     +---- HTTP/HTTPS probes (DNS + TCP-after-DNS + TLS + TTFB)
```

TCP-to-IP, hostname DNS, and TCP-after-DNS are recorded separately so a DNS failure cannot contaminate an IP TCP test.

Normal polling stays lightweight (15s DNS/TCP/HTTP). ICMP bursts and traceroute run only after an anomaly, with cooldowns.

## Measurements

- Uncached Pi-hole TCP and UDP checks on standard port `53`
- Direct public UDP and DNS-over-HTTPS control checks
- Multiple independent TCP-to-IP controls (default Cloudflare, Google, Quad9)
- HTTP DNS, connect, TLS, time-to-first-byte, total duration, and status
- Optional bounded transfer-speed test
- Configurable fixed asset loads every 30 seconds and cache-busted loads every 5 minutes, capped at 512 KiB each
- On-anomaly ICMP bursts to Pi-hole, gateway, ISP hop, and a public target
- Optional bounded traceroute after repeated upstream loss
- Optional NIC error/drop deltas during bursts
- Evidence-based incident classification with confidence and contradictions
- Optional Pi-hole v6 query and FTL diagnostic correlation for Pi-hole-specific incidents
- Manual annotations for network changes (`stormwarden annotate "..."`)

Probe traffic profiles are selectable in UI:

| Profile | Transfer probe | Estimated traffic |
| --- | --- | --- |
| Minimal | Disabled | Very low |
| Low | 256 KiB every 15 minutes | About 0.75 GB/month |
| Detailed | 5 MiB every 15 minutes | About 15 GB/month |

Asset traffic is separate from the selected profile. Configure up to eight targets in Probe settings. `Name|URL` runs every 30 seconds. `Name|cache-bust|URL` adds a random query and runs every 5 minutes. Downloads stop after 512 KiB. The defaults use a fixed 21 KiB YouTube thumbnail and a cache-busted 32 KiB Cloudflare test response, totaling about 2.1 GB/month.

## Run

Compose publishes the UI on `APP_PORT` (default `8080`) and adds `NET_RAW` for ICMP. Set `GATEWAY_ADDR` to the LAN router; the container default route is the Docker bridge.

```sh
cp .env.example .env
# Edit APP_PASSWORD and PIHOLE_DNS_ADDR. Set GATEWAY_ADDR if auto-detect is wrong.
mkdir -p data
sudo chown -R 100:101 data
docker compose up -d --build
```

Open `http://HOST-IP:8080`.

Rebuild on the NAS after pulling:

```sh
git pull
docker compose build
docker compose up -d
```

`docker compose up -d --build` does the same in one shot.

For HTTPS behind reverse proxy, set `APP_COOKIE_SECURE=true`. Do not expose the UI to the internet.

Annotate a network change:

```sh
docker compose exec stormwarden stormwarden annotate "Disabled Omada IDS/IPS"
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_PASSWORD` | required | UI password |
| `APP_PORT` | `8080` | Host port published for the UI |
| `PIHOLE_DNS_ADDR` | `127.0.0.1:53` | Pi-hole DNS endpoint |
| `PIHOLE_API_URL` | disabled | Pi-hole v6 API base URL |
| `PIHOLE_API_PASSWORD` | disabled | Pi-hole v6 application password |
| `PIHOLE_API_ALLOW_INSECURE_HTTP` | `false` | Allow API credentials over HTTP on a trusted LAN |
| `PUBLIC_DNS_ADDR` | `1.1.1.1:53` | Control DNS endpoint |
| `DOH_PROBE_URL` | Cloudflare DoH | DNS-over-HTTPS control endpoint |
| `HTTP_PROBE_URL` | Google 204 endpoint | Small HTTP timing target |
| `HTTP_DNS_ADDR` | `PIHOLE_DNS_ADDR` | Resolver used by HTTP probes |
| `HTTP_EXPECTED_STATUS` | `204` | Required probe response; `0` = any 2xx/3xx |
| `TRANSFER_PROBE_URL` | Cloudflare speed endpoint | Bounded transfer target |
| `ASSET_PROBES` | YouTube + Cloudflare test | Initial asset targets |
| `TCP_CONTROLS` | CF/Google/Quad9 `:443` | Independent TCP-to-IP controls `name\|host:port;...` |
| `GATEWAY_ADDR` | auto | LAN router IP. Set this if discovery is wrong. |
| `ISP_HOP_ADDR` | auto | ISP first hop. Empty + `ISP_HOP_AUTO=true` discovers it. |
| `ISP_HOP_AUTO` | `true` | Traceroute hop after the LAN gateway, cached hourly |
| `PING_ENABLED` | `true` | Anomaly ICMP bursts |
| `PING_PIHOLE_ADDR` | host of `PIHOLE_DNS_ADDR` | Pi-hole ICMP target |
| `PING_INTERNET_ADDR` | `1.1.1.1` | Public ICMP target |
| `DIAG_BURST_COUNT` | `10` | Pings per burst target |
| `DIAG_BURST_INTERVAL_MS` | `150` | Spacing between burst pings |
| `DIAG_BURST_COOLDOWN` | `2m` | Minimum time between bursts |
| `TRACEROUTE_ENABLED` | `true` | Incident-only traceroute |
| `TRACEROUTE_MAX_HOPS` | `15` | Traceroute cap |
| `TRACEROUTE_COOLDOWN` | `10m` | Minimum time between traces |
| `NIC_STATS_ENABLED` | `true` | Optional `/sys/class/net` error deltas |
| `APP_TIMEZONE` | `Europe/Budapest` | Display timezone |
| `APP_COOKIE_SECURE` | `false` | Require HTTPS session cookies |
| `DATA_PATH` | `/data/stormwarden.db` | SQLite location in image |
| `EXPORT_DIR` | `/data/exports` | Generated reports |
| `SMTP_HOST` | empty (off) | SMTP server. Set with `SMTP_TO` to enable mail |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USER` | | SMTP login |
| `SMTP_PASSWORD` | | SMTP password |
| `SMTP_FROM` | | From address (falls back to user / first To) |
| `SMTP_TO` | | Recipient(s), comma-separated |
| `SMTP_STARTTLS` | `1` | STARTTLS on 587 |
| `SMTP_SSL` | `0` | SMTPS (port 465); set `SMTP_STARTTLS=0` with this |
| `SMTP_INSECURESKIPVERIFY` | `false` | Skip TLS cert verify (self-signed SMTP) |
| `TELTONIKA_URL` | empty (off) | Router WebUI origin, e.g. `https://192.168.1.1` |
| `TELTONIKA_USER` | `admin` | WebUI user. Prefer a read-only `user`-group account |
| `TELTONIKA_PASSWORD` | | WebUI password (required with URL) |
| `TELTONIKA_ALLOW_INSECURE_HTTP` | `false` | Allow `http://` on a trusted LAN |
| `TELTONIKA_INSECURESKIPVERIFY` | `false` | Skip TLS cert verify (self-signed HTTPS) |

## Email alerts

Optional. Set `SMTP_HOST` and `SMTP_TO` (same names as elprotector). Empty = no mail.

Mail is sent for **error** and **critical** incidents in:

- `internet_outage`
- `wan_or_isp_packet_loss`
- `host_or_nic`
- `local_network_or_host`
- `external_dns`
- `dns_resolution_failure`
- `local_dns`
- `radio_poor` (Teltonika 4G/5G Poor: RSRQ ≤ -20 dB, SINR ≤ 0 dB, or RSRP < -100 dBm; two 5-minute samples)

Warnings, gateway ICMP, single-path DNS, assets, HTTP/TLS remote, and probe-health events are not mailed.

Per category, not per poll (same cadence as elprotector):

1. First opened
2. Still open 8 hours after first seen
3. Still open 4 hours after that
4. Then once a day until it is gone

Gone → cadence resets. No all-clear mail. A failed SMTP send does not advance the counter and does not stop probing. Failed attempts wait 15 minutes before retry. SMTP runs in the background with a 30s timeout so a dead WAN cannot stall health checks.

## Teltonika mobile radio

Optional. Stormwarden polls RutOS Web API (`POST /api/login`, `GET /api/modems/status`) every 5 minutes for RSSI, RSRP, RSRQ, SINR, band, cell, operator, and carrier aggregation. Opening a WAN/DNS incident also fetches once, unless a poll already ran in that 5-minute window. One in-flight request, 5s timeout. Failures are logged and never change probe severity.

Self-signed HTTPS:

```
TELTONIKA_URL=https://192.168.1.1
TELTONIKA_USER=stormwarden
TELTONIKA_PASSWORD=...
TELTONIKA_INSECURESKIPVERIFY=true
```

### Read-only WebUI user

Do not use `admin` / `root`. On the router:

1. **System → Administration → User Settings → System Users**
2. Add a user, group **`user`**. No SSH.
3. Edit the **`user`** group:
   - **Hide sensitive information:** on
   - **Write action:** Deny
   - **Read action:** Allow
    - **Read access** (paths after `#` in the WebUI URL):

| Path | Page |
| --- | --- |
| `status/network` | **Status → Network** (Mobile: RSSI, RSRP, RSRQ, SINR, CA, cell) |
| `status/overview` | **Status → Overview** (login landing; needed so the user can open WebUI) |

Also allow **API read** for `/modems/*` (or `/modems/status`). Stormwarden uses `GET /api/modems/status`, not WebUI JSON-RPC.

If a path 404s in group settings, open that page as admin and copy the URL starting at `#`. Example: `https://192.168.1.1/#/status/network` → `status/network`.

Default `user` cannot read Network or the modem API. Without `/modems/status` read, the health check returns HTTP 403.

## Probe hierarchy and classification

| Classification | Typical evidence | Confidence |
| --- | --- | --- |
| `local_dns` | Pi-hole TCP+UDP fail; public DNS and DoH succeed | high when LAN ICMP is healthy |
| `dns_resolution_failure` | TCP-to-IP works; DNS controls fail | high |
| `local_network_or_host` | Packet loss to both gateway and Pi-hole | high |
| `host_or_nic` | NIC RX/TX errors or drops rose during the incident | high with counter deltas |
| `gateway_or_router` | Gateway ICMP loss; Pi-hole ping healthy | medium (ICMP can be blocked) |
| `wan_or_isp_packet_loss` | Gateway 0% loss; upstream ICMP loss and/or several TCP controls in retransmission-like windows | high when ICMP and TCP agree |
| `destination_or_route_specific` | One TCP IP bad; others healthy | high |
| `tcp_connect_establishment` | Retransmission-like TCP timing; not enough to name WAN vs destination | medium |
| `tls_or_remote_service` | Connect healthy; TLS slow/fail | high |
| `http_or_server` | Connect+TLS healthy; TTFB/status bad | medium |
| `internet_outage` | DNS+TCP+HTTP failed for consecutive cycles | high |
| `unknown` | Contradictory or thin evidence | low |

TCP connect times near 1s / 2s / 3s / 4s timeout are tagged as consistent with SYN/SYN-ACK retransmission. That is not a claim that packet loss occurred.

## Docker networking

Default compose publishes the UI and adds `NET_RAW` for ICMP. The container default route is the Docker bridge; set `GATEWAY_ADDR` to the LAN router.

- `NET_RAW`: unprivileged ICMP ping/traceroute.
- Without it, ICMP samples record `icmp_unavailable`; TCP/DNS/HTTP classification still runs.
- Do not run privileged. Interface stats use `/sys/class/net`.

## ISP-hop discovery

When `ISP_HOP_ADDR` is empty and `ISP_HOP_AUTO=true`, Stormwarden traceroutes the public ICMP target, skips the LAN gateway hop, and caches the next responding hop. Intermediate `*` hops are ignored. Override with `ISP_HOP_ADDR` if discovery picks the wrong router.

## Interpretation limits

- ICMP failed ≠ internet down. Many networks block ping.
- Traceroute hop did not reply ≠ that router is broken.
- TCP took ~1 second ≠ packet loss as fact.
- Host vs switch vs cable is only claimed when NIC counters move.
- Reports state requested period, available data period, coverage percentage, and monitoring gaps. A "30-day" export with 6 days of samples is labeled as such.

## Diagnostic reports

Dashboard generates ZIP reports (day, week, month, custom, all). Each report contains:

- `summary.md`: coverage, classification counts, day-over-day TCP anomalies, A/B vs the previous equal window, annotations
- `measurements.jsonl`: raw probes
- `incidents.jsonl`: classified problem log with evidence and contradictions
- `annotations.json`: manual network-change markers
- `settings-redacted.json`: diagnostic configuration without secrets
- `system-info.json`: runtime and discovered network context

Raw measurements retain 30 days; rollups and incidents remain. Cleanup runs daily.

Pi-hole should continue listening on its standard LAN port `53`. A local dnsproxy listener such as `127.0.0.1:5053` is an internal Pi-hole upstream and must not be configured as Stormwarden's Pi-hole address.

For optional Pi-hole v6 incident correlation, create a dedicated application password in Pi-hole and set both `PIHOLE_API_URL` and `PIHOLE_API_PASSWORD`. Use HTTPS when possible. HTTP requires `PIHOLE_API_ALLOW_INSECURE_HTTP=true` and should only be used on a trusted private network. Stormwarden does not poll the authenticated API continuously. The first Pi-hole-specific bad cycle opens one temporary API session, fetches the exact randomized probe query and recent FTL diagnosis types, logs out immediately, and then waits at least five minutes before another attempt. API failures remain supplemental evidence and do not affect availability or incident severity.

## Development

HTMX is committed as a local static asset so the UI remains functional during internet outages. Refresh the pinned asset after dependency changes:

```sh
npm install
npm run vendor
go test ./...
go run ./cmd/stormwarden
```

`APP_PASSWORD` must be set for local execution.

## Current Limits

- ICMP and traceroute need `NET_RAW`. Set `GATEWAY_ADDR` when running on the Docker bridge.
- In-memory sessions expire on application restart, requiring login again.
