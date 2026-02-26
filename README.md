# Defensia Agent

Lightweight Go agent for Linux servers. Monitors logs, detects threats, manages firewall rules via `iptables`, and communicates with [Defensia](https://defensia.cloud) in real time.

## Features

- **Brute-force detection** — Monitors `auth.log` for failed SSH/login attempts, auto-bans via iptables
- **Web threat detection** — Watches Nginx/Apache access logs for SQL injection, path traversal, RCE attempts, scanner bots, WordPress exploits, and more
- **Real-time firewall** — Apply block/allow rules from the dashboard instantly via WebSocket
- **Network ban propagation** — Bans detected on one server are shared with all servers in the organization
- **IP safety system** — Prevents banning reserved IPs, the server itself, org siblings, or the Defensia API
- **Auto-update** — Agents update themselves from the admin panel with backup, preflight check, and rollback
- **Update failure reporting** — Failed updates are reported back to the server with diagnostic logs
- **Security scanner** — Detects vulnerable software versions and web server misconfigurations
- **Software audit** — Collects installed packages and key software versions
- **GeoIP blocking** — Block traffic by country (requires GeoLite2 database)
- **System metrics** — Reports CPU, memory, disk, load, and network stats
- **Zombie process detection** — Scans for zombie processes

## Requirements

- Linux (Ubuntu 20+, Debian 11+, CentOS 8+, RHEL 8+)
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
    │  Detect brute force, SQLi, path traversal, scanners, etc.
    │  Threshold: 5 attempts in 5 min window
    ▼
BanIP → iptables -I INPUT 1 -s <IP> -j DROP
    │   (with IP safety checks)
    │
    ├──► POST /api/v1/agent/bans → server logs + propagates to org
    │
    └──► WebSocket receives ban.created from other servers → BanIP instantly

Heartbeat:  POST /api/v1/agent/heartbeat  every 60s
Sync:       GET  /api/v1/agent/sync        every 5min (fallback)
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
| `GEOIP_DB_PATH` | GeoLite2 database path | — |
| `AGENT_IP` | Manual IP override for NAT/multi-NIC | Auto-detected |

## Auto-Update

1. Admin sets new version in the panel
2. Heartbeat response includes the new version + download URL
3. Agent downloads binary + SHA256 checksum, verifies integrity
4. Creates backup (`.bak`), runs preflight check on new binary
5. Replaces binary, restarts via systemd
6. On failure: rolls back to backup and reports failure with diagnostic logs

## Web Threat Detection

Monitors Nginx/Apache access logs for:

- SQL injection
- Path traversal (`../../etc/passwd`)
- Remote code execution (RCE)
- Shellshock exploits
- `.env` / config file probing
- WordPress brute-force (`wp-login.php`)
- XML-RPC abuse
- Scanner/bot fingerprints
- 404 flooding

Supports multi-vhost with automatic domain mapping from Nginx config.

## Architecture

```
cmd/defensia-agent/
└── main.go              # Entry point, heartbeat/sync loops

internal/
├── api/client.go        # HTTP client for all API calls
├── collector/metrics.go # System metrics (CPU, memory, disk, network)
├── config/config.go     # Config file reader/writer
├── firewall/iptables.go # iptables management + IP safety
├── geoip/geoip.go       # GeoIP country lookups
├── monitor/zombies.go   # Zombie process scanner
├── scanner/             # Security vulnerability scanner
├── updater/updater.go   # Auto-update with backup + rollback
├── watcher/authlog.go   # auth.log brute-force detection
├── watcher/weblog.go    # Web access log threat detection
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
git tag v0.9.0
git push --tags
# → Builds linux/amd64 + linux/arm64 + SHA256 checksums → GitHub Release
```

## License

MIT
