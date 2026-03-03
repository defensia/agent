# Defensia Agent

Lightweight Go agent for Linux servers. Monitors logs, detects threats, manages firewall rules via `iptables`, and communicates with [Defensia](https://defensia.cloud) in real time.

## Features

- **Brute-force detection** — Monitors `auth.log` for failed SSH/login attempts, auto-bans via iptables
- **Web Application Firewall (WAF)** — Watches Nginx/Apache access logs for 15 OWASP attack types with instant-ban and threshold-based detection
- **Per-server WAF configuration** — Enable/disable attack types, detect-only mode, and custom thresholds configurable from the dashboard
- **Real-time firewall** — Apply block/allow rules from the dashboard instantly via WebSocket
- **Network ban propagation** — Bans detected on one server are shared with all servers in the organization
- **IP safety system** — Prevents banning reserved IPs, the server itself, org siblings, or the Defensia API
- **Auto-update** — Agents update themselves from the admin panel with backup, preflight check, and rollback
- **Security scanner** — Detects vulnerable software versions and web server misconfigurations
- **Software audit** — Collects installed packages and key software versions
- **GeoIP blocking** — Block traffic by country (requires GeoLite2 database)
- **System metrics** — Reports CPU, memory, disk, load, and network stats
- **Zombie process detection** — Scans for zombie processes

## Requirements

- Linux (Ubuntu 20+, Debian 11+, CentOS 8+, RHEL 8+, Amazon Linux 2023)
- `iptables`
- `systemd` (or upstart/sysvinit)
- Root access

## Install

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

**Uninstall:**
```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --uninstall
```

## Commands

```bash
# Register (handled by install script)
defensia-agent register https://defensia.cloud my-server <token>

# Start (foreground)
defensia-agent start

# Via systemd
systemctl status defensia-agent
systemctl restart defensia-agent
journalctl -u defensia-agent -f
```

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

## IP Safety

The agent will **never** ban:

| Category | Examples | How |
|----------|----------|-----|
| Reserved IPs | `127.0.0.1`, `10.x`, `192.168.x`, `169.254.x` | `isReservedIP()` |
| Server's own IPs | All local interface addresses | `isLocalIP()` via `net.InterfaceAddrs()` |
| Defensia API | IP of the configured `server_url` | `AddProtectedIPs()` at startup |

These checks run in `BanIP()` and during rule import, so even if the backend sends a bad ban, the agent refuses to apply it.

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
| `AUTH_LOG_PATH` | Auth log path | `/var/log/auth.log` (`/var/log/secure` for RHEL) |
| `WEB_LOG_PATH` | Web access log path(s), comma-separated. Overrides auto-detection. | Auto-detected |
| `GEOIP_DB_PATH` | GeoLite2 database path | — |
| `AGENT_IP` | Manual IP override for NAT/multi-NIC | Auto-detected |

## Auto-Update

The agent self-updates without manual intervention. The full pipeline:

1. Admin sets `latest_agent_version` + `agent_download_base_url` in the panel settings
2. Each heartbeat response (every 60 s) includes these values
3. Agent compares versions with semver; if newer → begins update
4. Downloads SHA256 checksum file, then binary to a temp file
5. Verifies checksum — aborts + reports failure if mismatch
6. Runs preflight check: `<tmp-binary> check` must print `OK` — aborts if not
7. Copies current binary to `/usr/local/bin/defensia-agent.bak` (backup)
8. Copies temp binary to `/usr/local/bin/defensia-agent.new` (staging), then **atomically renames** it to `/usr/local/bin/defensia-agent` — the target is never in an absent state
9. Restarts via systemd (`systemctl restart defensia-agent`) — which sends SIGTERM to the calling process as part of the stop sequence
10. If `restartService()` returns `"signal: terminated"` or `"signal: killed"`, that means **systemd killed us as part of the restart** — this is normal, NOT a failure. The update is reported as success and the process exits cleanly. The new binary is already running.
11. If restart genuinely fails (e.g. no init system), rolls back atomically via a `.rollback` staging file, then reports failure with recent journal logs
12. If restart succeeds but service crashes within 15 s (`systemctl is-active` check), rolls back and reports `post_restart_crash`

**Startup cleanup:** At every start, `CleanupStagingFiles()` removes any leftover `.new` or `.rollback` staging files from an interrupted previous update or rollback — these are harmless but noisy.

**File layout on disk:**

| File | Purpose |
|------|---------|
| `/usr/local/bin/defensia-agent` | Active binary |
| `/usr/local/bin/defensia-agent.bak` | Backup of previous version (used for rollback) |
| `/usr/local/bin/defensia-agent.new` | Staging file during update (renamed atomically, then removed) |
| `/usr/local/bin/defensia-agent.rollback` | Staging file during rollback (renamed atomically, then removed) |

**Panel requirements:** Both `latest_agent_version` and `agent_download_base_url` **must** be updated together via `SettingsService::set()` (or manually followed by a `Cache::forget()` for both keys). Updating the DB directly without clearing the Redis cache leaves agents on the old version for up to 1 hour.

## Agent Recovery (Operational Runbook)

If an agent shows **203/EXEC** in the dashboard (binary missing or not executable):

```bash
# On the affected server:
cd /usr/local/bin

# Check what's there
ls -la defensia-agent*

# If .bak exists and is ~6 MB, restore from it:
cp defensia-agent.bak defensia-agent
chmod 755 defensia-agent
systemctl reset-failed defensia-agent
systemctl start defensia-agent

# Verify
systemctl status defensia-agent
journalctl -u defensia-agent -n 20
```

The agent will auto-update to the current `latest_agent_version` within a few seconds of its first heartbeat.

**If `systemctl start` fails with start-limit-hit:**
```bash
# Add StartLimitIntervalSec=0 to [Unit] section if missing:
grep -q StartLimitIntervalSec /etc/systemd/system/defensia-agent.service || \
  sed -i '/^\[Unit\]/a StartLimitIntervalSec=0' /etc/systemd/system/defensia-agent.service
systemctl daemon-reload
systemctl reset-failed defensia-agent
systemctl start defensia-agent
```

## Web Application Firewall (WAF)

Monitors Nginx/Apache access logs for 15 OWASP attack types across two detection modes:

### Instant-ban attacks

A single matching request triggers an immediate IP ban.

| Type | What it detects |
|------|----------------|
| `sql_injection` | UNION SELECT, OR 1=1, sleep(), benchmark(), information_schema |
| `xss_attempt` | `<script>`, `javascript:`, `onerror=`, `onload=` in URLs/headers |
| `ssrf_attempt` | Requests targeting `169.254.169.254`, `localhost`, `127.0.0.1` |
| `web_shell` | Access to known shell paths (`/shell.php`, `/c99.php`, `/r57.php`, etc.) |
| `path_traversal` | `../`, `etc/passwd`, `proc/self`, URL-encoded variants |
| `rce_attempt` | `eval(`, `exec(`, `system(`, `php://filter`, `${jndi:` (Log4Shell) |
| `shellshock` | `() {` in Referer or User-Agent headers (CVE-2014-6271) |
| `env_probe` | Requests to `/.env`, `/.env.local`, `/.env.production`, etc. |
| `config_probe` | `wp-config.php`, `.git/config`, `web.config`, `/.htpasswd` |
| `header_injection` | PHP execution functions in User-Agent; XSS in Referer; spoofed X-Forwarded-For |
| `web_exploit` | Generic exploit patterns not covered by other rules |

### Threshold-ban attacks

Multiple requests within a time window trigger a ban.

| Type | Default threshold | Window |
|------|-------------------|--------|
| `wp_bruteforce` | 10 failed logins | 2 min |
| `xmlrpc_abuse` | 5 requests | 1 min |
| `scanner_detected` | 5 plugin probes (404s on `wp-content/plugins/`) | 5 min |
| `404_flood` | 30 not-found responses | 5 min |

Scanner User-Agents (instant-ban): `sqlmap`, `nikto`, `nmap`, `masscan`, `dirbuster`, `wpscan`, `gobuster`, `nuclei`, `acunetix`, `nessus`, `openvas`, and more.

### Log auto-detection *(v0.9.7+)*

The agent automatically discovers web server log files at startup and every 5 minutes (hot-reload):

1. `$WEB_LOG_PATH` env var — explicit override, comma-separated paths
2. `nginx -T` on the host — finds all vhosts with their `access_log` paths and `server_name` values
3. Apache config files — reads `/etc/apache2/sites-enabled/*.conf` for `CustomLog` + `ServerName`
4. **Docker containers** — inspects running containers with nginx/apache/httpd/caddy/openresty images
5. Well-known static paths — fallback (`/var/log/nginx/access.log`, etc.)

Each log file is tailed in its own goroutine. Domain names are captured from the web server config and attached to every WAF event for filtering in the dashboard.

#### WAF with Dockerized web servers

If your web server runs inside Docker, the agent can monitor its logs **as long as the log directory is bind-mounted to the host**:

```yaml
# docker-compose.yml
services:
  nginx:
    image: nginx
    volumes:
      - /var/log/nginx:/var/log/nginx   # ← required for WAF detection
```

With this mount in place, no additional configuration is needed — the agent automatically runs `nginx -T` inside the container, finds the `access_log` paths, maps them to host paths via the bind-mount table, and starts tailing them.

If the log directory is **not** mounted to the host, use `WEB_LOG_PATH` in the agent's systemd unit to point directly at the container log paths (only works if the agent somehow has access, e.g. via a shared volume):

```bash
# /etc/systemd/system/defensia-agent.service
[Service]
Environment="WEB_LOG_PATH=/var/log/nginx/access.log"
```

To verify which logs the agent is currently monitoring:

```bash
journalctl -u defensia-agent | grep webwatcher
# [webwatcher] watching /var/log/nginx/app.access.log (app.example.com)
# [webwatcher] docker: watching /var/log/nginx/api.access.log from container nginx
# [webwatcher] monitoring 2 log file(s) covering 3 domain(s)
```

### Per-server WAF configuration *(v0.9.3+)*

Each attack type can be independently configured from the Defensia dashboard (Server → WAF tab). Changes sync to the agent within 60 seconds via `GET /api/v1/agent/sync`.

**Enable/disable types:** Disable rules irrelevant to your stack (e.g. `wp_bruteforce` on a non-WordPress server).

**Detect-only mode:** Records the event in the dashboard without banning the IP. Useful for monitoring before enabling enforcement, or for audit-only policies.

**Custom thresholds:** Override the default threshold for `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, and `404_flood`.

```json
// waf_config in sync response
{
  "enabled_types": ["sql_injection", "xss_attempt", "path_traversal"],
  "detect_only_types": ["404_flood", "scanner_detected"],
  "thresholds": {
    "wp_bruteforce": 5,
    "404_flood": 10
  }
}
```

- `null` → all 15 types active, no detect-only, default thresholds (backward compatible)
- Agents < v0.9.3 ignore `waf_config` (unknown JSON field) — keep default behavior

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

Tag push triggers GitHub Actions:

```bash
git tag v0.9.3
git push --tags
# → Builds linux/amd64 + linux/arm64 + SHA256 checksums → GitHub Release
```

## Changelog

| Version | Changes |
|---------|---------|
| v0.9.15 | Fix: false rollback on `"signal: terminated"` — when systemd restarts the agent it sends SIGTERM to the running process; `isRestartInProgress()` now detects this and treats it as success instead of triggering a rollback. Added `CleanupStagingFiles()` at startup to remove leftover `.new`/`.rollback` staging files from any interrupted previous update |
| v0.9.14 | Fix: removed `updateServiceFile()` from updater and `ExecStartPre` from service file template — these caused a regression loop where every update rewrote the service file and triggered a second restart. Also silenced iptables "rule already exists" noise in logs |
| v0.9.13 | Fix: `StartLimitIntervalSec=0` moved to `[Unit]` section (systemd ignores it in `[Service]`) to prevent start-limit-hit after rapid successive updates |
| v0.9.12 | Internal: improved updater diagnostics; added `recent_logs` to failure event payloads |
| v0.9.11 | Updater: service file patching via `updateServiceFile()` (reverted in v0.9.14) |
| v0.9.10 | Fix: health-check window extended; stale ban cleanup on sync |
| v0.9.9 | Fix: cross-device rename failure — updater now stages new binary on the same filesystem before atomic rename |
| v0.9.8 | Fix: updater preflight check uses `check` subcommand; rollback uses atomic stage-then-rename |
| v0.9.7 | Docker container log detection: auto-discovers nginx/apache logs inside Docker via bind-mounts |
| v0.9.6 | Added `web_exploit` detection (Spring4Shell, JBoss/Tomcat consoles, Struts OGNL, ThinkPHP RCE, Drupalgeddon2) |
| v0.9.5 | Fix: atomic binary replacement + 15 s post-restart health check in auto-updater; rollback on crash |
| v0.9.4 | Fix: double URL-decode bypass; lower 404-flood threshold |
| v0.9.3 | Per-server WAF config from panel: enable/disable types, detect-only mode, custom thresholds |
| v0.9.2 | +XSS, +SSRF, +web shell, +header injection detection |
| v0.9.1 | Bug fixes |
| v0.9.0 | Initial WAF: SQLi, path traversal, RCE, shellshock, env/config probe, wp_bruteforce, xmlrpc, 404_flood, scanner |
| v0.6.x | Brute-force detection, GeoIP, zombie processes, auto-update, IP safety |

## FAQ

### "`Peer's Certificate issuer is not recognized`" during install

**Affected systems:** CentOS 7, RHEL 7, and any Linux with `ca-certificates` not updated since 2024.

**Why it happens — three layered reasons:**

1. **Let's Encrypt changed intermediates in 2024.** The new intermediates (R10–R13 RSA, E5–E8 ECDSA) are not present in CA bundles shipped before 2024. Even updating to RSA (R13) doesn't help if the root isn't trusted.

2. **`curl` on CentOS 7 is compiled against NSS, not OpenSSL.** NSS (Network Security Services) maintains its own certificate database independent of the system OpenSSL bundle. Running `update-ca-trust` updates the OpenSSL bundle but has no effect on what `curl` actually uses on CentOS 7.

3. **CentOS 7 reached EOL in June 2024.** Its official YUM mirrors are dead, so `yum update ca-certificates` fails without first pointing to `vault.centos.org`. Even then, the update may not propagate to NSS.

**Fix — one-time bootstrap:**

```bash
# 1. Download the Let's Encrypt root CA (using -k since curl can't verify LE yet)
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem \
  -o /etc/pki/ca-trust/source/anchors/isrg-root-x1.pem

# 2. Tell curl to use it for this session
export CURL_CA_BUNDLE=/etc/pki/ca-trust/source/anchors/isrg-root-x1.pem

# 3. Run the install normally
curl -fsSL https://defensia.cloud/install.sh | bash -s -- --token <YOUR_TOKEN>
```

**Why `CURL_CA_BUNDLE` works:** This environment variable is supported by all `curl` versions since 7.10 (2002) and is respected regardless of whether curl is compiled against NSS or OpenSSL. It overrides the trust database entirely for that session.

**Why the `-k` on step 1 is safe:** We're only downloading a CA certificate (public data, not a secret), and we're verifying its identity immediately after — the downloaded cert is used as the trust anchor for the actual install. An attacker intercepting step 1 would give you a bogus root cert, which curl would then use to verify defensia.cloud — and that verification would fail since they don't control our TLS certificate. The real risk window is effectively zero.

**Permanent fix on the server:**

```bash
# Add ISRG Root X1 to the system trust store permanently
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem \
  -o /etc/pki/ca-trust/source/anchors/isrg-root-x1.pem
update-ca-trust force-enable
update-ca-trust extract

# For NSS-linked curl, also update the NSS database:
certutil -d /etc/pki/nssdb -A -t "CT,," -n "ISRG Root X1" \
  -i /etc/pki/ca-trust/source/anchors/isrg-root-x1.pem
```

After this, `CURL_CA_BUNDLE` is no longer needed — curl will trust Let's Encrypt globally on that server.

---

## License

MIT
