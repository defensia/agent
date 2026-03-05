# Defensia Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white)](https://github.com/defensia/agent)
[![Version](https://img.shields.io/badge/version-v0.9.23-brightgreen)](https://github.com/defensia/agent/releases)
[![Dashboard](https://img.shields.io/badge/Dashboard-defensia.cloud-0D1B2A)](https://defensia.cloud)

**Your server is being attacked right now. You just don't know it.**

The average Linux VPS receives its first automated attack within 4 minutes of going online — SSH brute force, port scans, web exploits. Most developers find out when it's already too late.

Defensia is a lightweight Go agent that detects every attack in real time and blocks them automatically. One command to install, zero configuration.

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

## Dashboard

![Dashboard](docs/01-dashboard.png)

<details>
<summary>Events feed & WAF analytics</summary>

![Events](docs/02-events.png)
![WAF](docs/04-waf.png)

</details>

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

**Docker-aware** — auto-detects web servers inside Docker containers, reads logs via bind mounts, volumes, or container stdout

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
auth.log / web access logs / Docker container logs
    │
    ▼
Log auto-detection
    │  nginx -T / apachectl -S / docker inspect / docker logs
    │  Resolves bind mounts, volumes, symlinks, relative paths
    ▼
Watcher goroutines
    │  Detect brute force, SQLi, XSS, SSRF, path traversal, web shells...
    │  Instant-ban or threshold (configurable per type from dashboard)
    ▼
BanIP → iptables -I INPUT 1 -s <IP> -j DROP
    │
    ├──► POST /api/v1/agent/bans → dashboard + propagates to all your servers
    │
    └──► WebSocket receives ban.created from other servers → BanIP instantly
```

The agent never bans reserved IPs (`127.x`, `10.x`, `192.168.x`), your own server's IPs, or the Defensia API endpoint — even if the backend somehow sends a bad rule.

---

## Per-server WAF configuration *(v0.9.3+)*

Each attack type can be independently configured from the dashboard (Server → Settings → WAF). Changes sync within 60 seconds.

- **Enable/disable types** — disable rules irrelevant to your stack (e.g. `wp_bruteforce` on a non-WordPress server)
- **Detect-only mode** — record events without banning. Useful for audit-only policies or testing before enforcement
- **Custom thresholds** — override defaults for `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`

`null` WAF config → all 15 types active, default thresholds (fully backward compatible).

---

## Docker support *(v0.9.20+)*

The agent **automatically detects Docker** and reports all running containers to the dashboard. Web containers (nginx, apache, caddy, or any container exposing ports 80/443/8080) get special treatment:

1. Runs `nginx -T` or `apachectl -S` **inside** the container to discover log paths and domain names
2. Maps container log paths to host paths via bind mounts and Docker volumes
3. Falls back to scanning mount directories for `*access*.log` files
4. Last resort: reads container stdout via `docker logs -f` if logs go to stdout (common with official nginx image)

**Best practice** — bind-mount the log directory to the host for fastest detection:

```yaml
services:
  nginx:
    image: nginx
    volumes:
      - /var/log/nginx:/var/log/nginx
```

**Dashboard** — the server detail page shows a dedicated Docker tab with all containers, web detection status, and the WAF tab shows which log sources are being monitored.

```bash
journalctl -u defensia-agent | grep webwatcher
# [webwatcher] docker: watching /var/log/nginx/access.log from container my-nginx
# [webwatcher] detected 3 access log(s), 5 domain(s)
```

---

## Manual log path configuration

If auto-detection doesn't find your logs (custom paths, piped logs, non-standard setups), set the `WEB_LOG_PATH` environment variable:

```bash
sudo systemctl edit defensia-agent
```

Add:

```ini
[Service]
Environment="WEB_LOG_PATH=/var/log/httpd/access_log,/var/log/nginx/custom-access.log"
```

Then restart:

```bash
sudo systemctl restart defensia-agent
```

`WEB_LOG_PATH` overrides all auto-detection. Multiple paths are comma-separated.

---

## FAQ

### `"Peer's Certificate issuer is not recognized"` during install

Affects CentOS 7, RHEL 7, and systems with `ca-certificates` not updated since 2024.

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem \
  -o /tmp/isrg-root-x1.pem
export CURL_CA_BUNDLE=/tmp/isrg-root-x1.pem
curl -fsSL https://defensia.cloud/install.sh | bash -s -- --token <YOUR_TOKEN>
```

### Agent shows `203/EXEC` in the dashboard

Binary missing or not executable. Restore from backup:

```bash
cp /usr/local/bin/defensia-agent.bak /usr/local/bin/defensia-agent
chmod 755 /usr/local/bin/defensia-agent
systemctl reset-failed defensia-agent && systemctl start defensia-agent
```

If `systemctl start` fails with `start-limit-hit`:

```bash
grep -q StartLimitIntervalSec /etc/systemd/system/defensia-agent.service || \
  sed -i '/^\[Unit\]/a StartLimitIntervalSec=0' /etc/systemd/system/defensia-agent.service
systemctl daemon-reload && systemctl reset-failed defensia-agent && systemctl start defensia-agent
```

---

## Changelog

| Version | Changes |
|---------|---------|
| v0.9.23 | Fix: nginx global `access_log` with `server_name` in server blocks now correctly associates domains with log paths |
| v0.9.22 | Improved Apache detection for CentOS/RHEL: ServerRoot resolution, symlink following, `apachectl -S` discovery, well-known RHEL paths fallback |
| v0.9.21 | Fix: web container detection matches container port (`->80/tcp`) not host port (`:80->`) |
| v0.9.20 | Docker container detection, stdout log reader, Docker info in heartbeat, bind mount + volume log discovery |
| v0.9.19 | Whitelisted IPs are detected (events reported) but never banned |
| v0.9.18 | Raw access log line included in event details for attack evidence |
| v0.9.17 | Fix: Apache `${APACHE_LOG_DIR}` resolution, monitored domains/log paths reported in heartbeat |
| v0.9.16 | Instant whitelist propagation via `sync.requested` WebSocket event |
| v0.9.15 | Fix: false rollback on `"signal: terminated"` — systemd kills the calling process on restart, now correctly treated as success |
| v0.9.14 | Fix: removed `updateServiceFile()` from updater — caused a regression loop on every update |
| v0.9.13 | Fix: `StartLimitIntervalSec=0` moved to `[Unit]` section to prevent start-limit-hit |
| v0.9.12 | Improved updater diagnostics; `recent_logs` in failure event payloads |
| v0.9.10 | Fix: health-check window extended; stale ban cleanup on sync |
| v0.9.9 | Fix: cross-device rename failure in updater |
| v0.9.8 | Fix: preflight check uses `check` subcommand; atomic rollback |
| v0.9.7 | Docker container log detection via bind-mounts |
| v0.9.6 | Added `web_exploit` detection (Spring4Shell, Log4Shell, Struts OGNL...) |
| v0.9.5 | Atomic binary replacement + 15s post-restart health check; rollback on crash |
| v0.9.3 | Per-server WAF config: enable/disable types, detect-only mode, custom thresholds |
| v0.9.2 | XSS, SSRF, web shell, header injection detection |
| v0.9.0 | Initial WAF: SQLi, path traversal, RCE, shellshock, env/config probe, wp_bruteforce, xmlrpc, 404_flood, scanner |
| v0.6.x | Brute-force detection, GeoIP, zombie processes, auto-update, IP safety |

---

## License

MIT — see [LICENSE](LICENSE)
