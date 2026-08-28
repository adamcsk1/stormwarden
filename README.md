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

Compose uses `network_mode: host` and `cap_add: NET_RAW` so ICMP, traceroute, and LAN-gateway discovery see the real home network instead of the Docker bridge.

Host networking ignores published ports. Open `http://LINUX-HOST-IP:8080` (the machine's LAN address). Do not use an old `172.x` container IP.

```sh
cp .env.example .env
# Edit APP_PASSWORD and PIHOLE_DNS_ADDR. Set GATEWAY_ADDR if auto-detect is wrong.
mkdir -p data
sudo chown -R 100:101 data
docker compose up -d --build
```

Open `http://HOST-IP:8080`.

Linux Docker is the supported ICMP path. Docker Desktop on Windows/Mac does not provide equivalent host networking.

For HTTPS behind reverse proxy, set `APP_COOKIE_SECURE=true`. Do not expose the UI to the internet.

Annotate a network change:

```sh
docker compose exec stormwarden stormwarden annotate "Disabled Omada IDS/IPS"
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `APP_PASSWORD` | required | UI password |
| `APP_PORT` | `8080` | UI listen port on the host (host network) |
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

Default compose is host network plus `NET_RAW`.

- Host network: default route is the LAN gateway, not `docker0`.
- `NET_RAW`: unprivileged ICMP ping/traceroute.
- Without those, ICMP samples record `icmp_unavailable` and classification continues from TCP/DNS/HTTP only.
- Do not run privileged. Interface stats use `/sys/class/net` and do not need extra capabilities.

If the UI shows a 172.16/12 default gateway, Stormwarden is still on a Docker bridge. Set `GATEWAY_ADDR` to the LAN router and use host networking.

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

- No modem/router radio metrics yet. Weather or 4G/5G signal causation needs RSRP, RSRQ, SINR, band, and cell data from a router API.
- ICMP and traceroute need Linux host networking plus `NET_RAW`.
- In-memory sessions expire on application restart, requiring login again.
