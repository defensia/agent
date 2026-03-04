# Defensia Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)](https://github.com/defensia/agent)
[![Version](https://img.shields.io/badge/version-v0.9.15-brightgreen)](https://github.com/defensia/agent/releases)
[![Dashboard](https://img.shields.io/badge/Dashboard-defensia.cloud-0D1B2A)](https://defensia.cloud)

**Your server is being attacked right now. You just don't know it.**

The average Linux VPS receives its first automated attack within 4 minutes of going online — SSH brute force, port scans, web exploits. Most developers find out when it's already too late.

Defensia is a lightweight Go agent that shows you every attack in real time and blocks them automatically.

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

→ **[Get your token at defensia.cloud](https://defensia.cloud)**
→ First attack visible in your dashboard in under 15 minutes.

---

## Why Defensia

| | fail2ban | CrowdSec | Defensia |
|--|---------|---------|---------|
| Real-time dashboard | ❌ | Partial | ✅ |
| One-command install | ❌ | ❌ | ✅ |
| WAF (15 OWASP types) | ❌ | Partial | ✅ |
| Network ban sharing | ❌ | ✅ | ✅ |
| Zero configuration | ❌ | ❌ | ✅ |
| Community hub required | ❌ | ✅ | ❌ |

- **fail2ban** blocks after the fact. Defensia shows you while it's happening.
- **CrowdSec** requires a community hub and complex setup. Defensia is one agent, one dashboard.
- You'll see your first blocked attack within 15 minutes of installing.

---

## What it detects

**SSH & brute force** — monitors `auth.log` for failed login attempts, auto-bans via iptables

**Web Application Firewall (WAF)** — 15 OWASP attack types across Nginx/Apache logs:

| Attack type | Mode |
|-------------|------|
| SQL injection | Instant ban |
| XSS attempt | Instant ban |
| Path traversal | Instant ban |
| RCE attempt (incl. Log4Shell) | Instant ban |
| Web shell access | Instant ban |
| SSRF attempt | Instant ban |
| ShellShock (CVE-2014-6271) | Instant ban |
| `.env` / config probing | Instant ban |
| Header injection | Instant ban |
| Generic web exploits | Instant ban |
| WordPress brute force | Threshold (10 req / 2 min) |
| xmlrpc abuse | Threshold (5 req / 1 min) |
| Scanner bots | Threshold (5 req / 5 min) |
| 404 flood | Threshold (30 req / 5 min) |
| Known scanner User-Agents (sqlmap, nikto, nmap...) | Instant ban |

**GeoIP blocking** — block entire countries from the dashboard
**Network propagation** — bans detected on one server instantly applied to all your servers
**Security scanner** — detects vulnerable software versions and misconfigurations
**System metrics** — CPU, memory, disk, network reported to the dashboard

---

## Install

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

**Uninstall:**
```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --uninstall
```

**Supported systems:** Ubuntu 20+, Debian 11+, CentOS 7+, RHEL 8+, Amazon Linux 2023

**Requirements:** `iptables`, `systemd` (or upstart/sysvinit), root access

---

## How it works

```
auth.log / web access logs
    │
    ▼
Watcher goroutines
    │  Detect brute force, SQLi, XSS, SSRF, path traversal, web shells...
    │  Instant-ban or threshold (configurable per type from dashboard)
    ▼
BanIP → iptables -I INPUT 1 -s <IP> -j DROP
    │   (with IP safety checks + detect-only mode support)
    │
    ├──► POST /api/v1/agent/bans → server logs + propagates to org
    │
    └──► WebSocket receives ban.created from other servers → BanIP instantly

Heartbeat:  POST /api/v1/agent/heartbeat  every 60s
Sync:       GET  /api/v1/agent/sync        every 5min (includes WAF config)
```

---

## IP Safety

The agent will **never** ban:

| Category | Examples | How |
|----------|----------|-----|
| Reserved IPs | `127.0.0.1`, `10.x`, `192.168.x`, `169.254.x` | `isReservedIP()` |
| Server's own IPs | All local interface addresses | `isLocalIP()` via `net.InterfaceAddrs()` |
| Defensia API | IP of the configured `server_url` | `AddProtectedIPs()` at startup |

These checks run in `BanIP()` and during rule import, so even if the backend sends a bad ban, the agent refuses to apply it.

---

## Per-server WAF configuration *(v0.9.3+)*

Each attack type can be independently configured from the dashboard (Server → Settings → WAF). Changes sync within 60 seconds.

- **Enable/disable types** — disable rules irrelevant to your stack (e.g. `wp_bruteforce` on a non-WordPress server)
- **Detect-only mode** — record events without banning. Useful for audit-only policies or monitoring before enabling enforcement
- **Custom thresholds** — override defaults for `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`

```json
{
  "enabled_types": ["sql_injection", "xss_attempt", "path_traversal"],
  "detect_only_types": ["404_flood", "scanner_detected"],
  "thresholds": {
    "wp_bruteforce": 5,
    "404_flood": 10
  }
}
```

`null` → all 15 types active, no detect-only, default thresholds (backward compatible).

---

## Config

Stored at `/etc/defensia/config.json` (mode 0600):

```json
{
  "server_url": "https://defensia.cloud",
  "agent_token": "64-char-token",
  "agent_id": 1,
  "reverb_url": "wss://ws.defensia.cloud/app/KEY",
  "reverb_app_key": "KEY",
  "auth_endpoint": "https://defensia.cloud/api/v1/agent/broadcasting/auth"
}
```

**Environment overrides:**

| Variable | Description | Default |
|----------|-------------|---------|
| `DEFENSIA_CONFIG` | Config file path | `/etc/defensia/config.json` |
| `AUTH_LOG_PATH` | Auth log path | `/var/log/auth.log` (`/var/log/secure` on RHEL) |
| `WEB_LOG_PATH` | Web access log path(s), comma-separated | Auto-detected |
| `GEOIP_DB_PATH` | GeoLite2 database path | — |
| `AGENT_IP` | Manual IP override for NAT/multi-NIC | Auto-detected |

---

## WAF with Dockerized web servers

If your web server runs inside Docker, bind-mount the log directory to the host:

```yaml
services:
  nginx:
    image: nginx
    volumes:
      - /var/log/nginx:/var/log/nginx   # ← required for WAF detection
```

The agent automatically discovers logs via `nginx -T` inside the container, maps them to host paths via the bind-mount table, and starts tailing them. No additional configuration needed.

To verify which logs are being monitored:

```bash
journalctl -u defensia-agent | grep webwatcher
# [webwatcher] watching /var/log/nginx/app.access.log (app.example.com)
# [webwatcher] docker: watching /var/log/nginx/api.access.log from container nginx
# [webwatcher] monitoring 2 log file(s) covering 3 domain(s)
```

---

## Auto-Update

The agent self-updates without manual intervention:

1. Admin sets `latest_agent_version` + `agent_download_base_url` in the panel
2. Each heartbeat response (every 60s) includes these values
3. Agent compares versions; if newer → downloads binary + SHA256 checksum
4. Verifies checksum → runs preflight check (`<binary> check` must print `OK`)
5. Backs up current binary to `.bak`, atomically renames new binary into place
6. Restarts via systemd — if systemd kills the process during restart, this is treated as success (the new binary is already running)
7. If restart fails or new binary crashes within 15s → atomic rollback + failure report

**File layout:**

| File | Purpose |
|------|---------|
| `/usr/local/bin/defensia-agent` | Active binary |
| `/usr/local/bin/defensia-agent.bak` | Backup for rollback |
| `/usr/local/bin/defensia-agent.new` | Staging during update |
| `/usr/local/bin/defensia-agent.rollback` | Staging during rollback |

---

## Agent Recovery

If an agent shows **203/EXEC** in the dashboard (binary missing or not executable):

```bash
cd /usr/local/bin
ls -la defensia-agent*

# If .bak exists and is ~6 MB, restore from it:
cp defensia-agent.bak defensia-agent
chmod 755 defensia-agent
systemctl reset-failed defensia-agent
systemctl start defensia-agent
```

If `systemctl start` fails with `start-limit-hit`:

```bash
grep -q StartLimitIntervalSec /etc/systemd/system/defensia-agent.service || \
  sed -i '/^\[Unit\]/a StartLimitIntervalSec=0' /etc/systemd/system/defensia-agent.service
systemctl daemon-reload
systemctl reset-failed defensia-agent
systemctl start defensia-agent
```

---

## Architecture

```
cmd/defensia-agent/
└── main.go              # Entry point, heartbeat/sync loops, UpdateWAFConfig on sync

internal/
├── api/client.go        # HTTP client; SyncConfig includes WAFConfig struct
├── collector/metrics.go # System metrics (CPU, memory, disk, network)
├── config/config.go     # Config file reader/writer
├── firewall/iptables.go # iptables management + IP safety
├── geoip/geoip.go       # GeoIP country lookups
├── monitor/zombies.go   # Zombie process scanner
├── scanner/             # Security vulnerability scanner
├── updater/updater.go   # Auto-update with backup + rollback
├── watcher/authlog.go   # auth.log brute-force detection
├── watcher/weblog.go    # WAF: 15 attack patterns, UpdateWAFConfig(), detect-only support
└── ws/client.go         # WebSocket client (Laravel Reverb)
```

---

## Development

```bash
# Run locally
DEFENSIA_CONFIG=./dev-config.json AUTH_LOG_PATH=./test-auth.log \
  go run ./cmd/defensia-agent start

# Build
make build

# Cross-compile
make build-linux      # amd64
make build-linux-arm  # arm64
```

## Release

```bash
git tag v0.9.15
git push --tags
# → Builds linux/amd64 + linux/arm64 + SHA256 checksums → GitHub Release
```

---

## FAQ

### `"Peer's Certificate issuer is not recognized"` during install

Affects CentOS 7, RHEL 7, and systems with `ca-certificates` not updated since 2024.

**Fix:**

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem \
  -o /tmp/isrg-root-x1.pem
export CURL_CA_BUNDLE=/tmp/isrg-root-x1.pem
curl -fsSL https://defensia.cloud/install.sh | bash -s -- --token <YOUR_TOKEN>
```

See [full explanation in the docs](https://defensia.cloud/docs/troubleshooting).

---

## Changelog

| Version | Changes |
|---------|---------|
| v0.9.15 | Fix: false rollback on `"signal: terminated"` — systemd kills the calling process on restart, now correctly treated as success. Added `CleanupStagingFiles()` at startup |
| v0.9.14 | Fix: removed `updateServiceFile()` from updater — caused a regression loop on every update |
| v0.9.13 | Fix: `StartLimitIntervalSec=0` moved to `[Unit]` section to prevent start-limit-hit |
| v0.9.12 | Improved updater diagnostics; `recent_logs` in failure event payloads |
| v0.9.10 | Fix: health-check window extended; stale ban cleanup on sync |
| v0.9.9 | Fix: cross-device rename failure in updater |
| v0.9.8 | Fix: preflight check uses `check` subcommand; atomic rollback |
| v0.9.7 | Docker container log detection via bind-mounts |
| v0.9.6 | Added `web_exploit` detection (Spring4Shell, Log4Shell, Struts OGNL...) |
| v0.9.5 | Atomic binary replacement + 15s post-restart health check; rollback on crash |
| v0.9.4 | Fix: double URL-decode bypass; lower 404-flood threshold |
| v0.9.3 | Per-server WAF config: enable/disable types, detect-only mode, custom thresholds |
| v0.9.2 | XSS, SSRF, web shell, header injection detection |
| v0.9.0 | Initial WAF: SQLi, path traversal, RCE, shellshock, env/config probe, wp_bruteforce, xmlrpc, 404_flood, scanner |
| v0.6.x | Brute-force detection, GeoIP, zombie processes, auto-update, IP safety |

---

## License

MIT — see [LICENSE](LICENSE)
