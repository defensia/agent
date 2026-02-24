# Defensia Agent

Go binary that runs on your Linux servers. Monitors `auth.log`, bans attackers via `iptables`, and communicates with the Defensia backend.

## Requirements

- Linux (Ubuntu 20+, Debian 11+, CentOS 8+)
- `iptables`
- `systemd`
- Root access

## Install (one-liner)

```bash
curl -fsSL https://get.defensia.com | bash
```

**Non-interactive (automation/Ansible):**
```bash
DEFENSIA_SERVER_URL=https://panel.example.com \
DEFENSIA_AGENT_NAME=web-01 \
curl -fsSL https://get.defensia.com | bash
```

**Uninstall:**
```bash
curl -fsSL https://get.defensia.com | bash -s -- --uninstall
```

---

## How it works

```
auth.log tail
    │
    ▼
Watcher goroutine
    │  "Failed password for root from 5.5.5.5"
    │  5 attempts in 5min window
    ▼
BanIP (iptables -I INPUT 1 -s 5.5.5.5 -j DROP)
    │
    └──► POST /api/v1/agent/bans  → server logs + broadcasts to other agents
         ↑
WebSocket (Reverb)
    │  ban.created event from server/panel
    └──► BanIP immediately — no 5min polling wait

Heartbeat: POST /api/v1/agent/heartbeat  every 60s
Sync:      GET  /api/v1/agent/sync       every 5min (fallback)
```

---

## Config

Stored at `/etc/defensia/config.json` (root-only, mode 0600):

```json
{
  "server_url":    "https://panel.example.com",
  "agent_token":   "64-char-token-from-registration",
  "agent_id":      1,
  "reverb_url":    "ws://panel.example.com:6001/app/APP_KEY",
  "reverb_app_key": "APP_KEY",
  "auth_endpoint": "https://panel.example.com/api/v1/agent/broadcasting/auth"
}
```

Override config path with `DEFENSIA_CONFIG` env var:
```bash
DEFENSIA_CONFIG=/tmp/test-config.json defensia-agent start
```

Override `auth.log` path with `AUTH_LOG_PATH` env var:
```bash
AUTH_LOG_PATH=/var/log/secure defensia-agent start  # RHEL/CentOS
```

---

## Commands

```bash
# Register (first boot)
defensia-agent register https://panel.example.com my-server-name

# Start agent (foreground)
defensia-agent start

# Via systemd
systemctl status defensia-agent
systemctl stop defensia-agent
journalctl -u defensia-agent -f
```

---

## Development

```bash
# Run locally (skips /etc/defensia — uses local config)
cd agent
DEFENSIA_CONFIG=./dev-config.json AUTH_LOG_PATH=./test-auth.log \
  go run ./cmd/defensia-agent start

# Build for current platform
make build

# Build all Linux targets + checksums
make release

# Cross-compile
make build-linux      # amd64
make build-linux-arm  # arm64
```

---

## Banning logic

| Parameter | Default | Override |
|---|---|---|
| Threshold | 5 failed attempts | — |
| Window | 5 minutes | — |
| Log file | `/var/log/auth.log` | `AUTH_LOG_PATH` env |
| Config | `/etc/defensia/config.json` | `DEFENSIA_CONFIG` env |

Once an IP is banned locally, it's also reported to the server via `POST /api/v1/agent/bans`. The server broadcasts `ban.created` to all other online agents via Reverb — they apply the ban instantly without waiting for their next sync.

---

## IP detection

On registration and every heartbeat, the agent detects and reports its outbound IP address. Detection uses three methods in order of priority:

1. **`AGENT_IP` env var** — Manual override, useful for NAT or multi-NIC setups
2. **UDP dial** — Opens a UDP socket to `1.1.1.1:80` (no traffic sent) and reads the local address the OS chooses. This returns the primary outbound IP on most servers
3. **Network interfaces** — Iterates all non-loopback interfaces and returns the first IPv4 address found
4. **Fallback** — Returns `0.0.0.0` only if all methods fail (e.g. completely isolated host)

The heartbeat sends the IP on every cycle (60s). If the server-side value is `0.0.0.0` or outdated, it gets corrected automatically — no manual intervention needed.

---

## Auto-update

Agents update themselves automatically from the admin panel. No SSH access required.

### How it works

```
Admin Panel → Settings → "Agent Auto-Update"
    │  Sets: latest_agent_version = "0.2.0"
    │  Sets: agent_download_base_url = "https://github.com/defensia/agent/releases/download/v0.2.0"
    │
    ▼
Heartbeat response (every 60s)
    │  { "latest_agent_version": "0.2.0", "agent_download_base_url": "..." }
    │
    ▼
Agent compares versions
    │  current: 0.1.0  →  latest: 0.2.0  →  update needed
    │
    ▼
Download + verify + replace
    1. Downloads: {base_url}/defensia-agent-linux-{amd64|arm64}
    2. Downloads: {base_url}/defensia-agent-linux-{arch}.sha256
    3. Verifies SHA256 checksum matches
    4. Replaces /usr/local/bin/defensia-agent
    5. Runs: systemctl restart defensia-agent
```

### Triggering an update

1. Create a new release on GitHub (tag push triggers CI):
   ```bash
   git tag v0.2.0
   git push --tags
   # → GitHub Actions builds binaries + checksums + publishes release
   ```

2. Go to **Admin Panel → Settings → Agent Auto-Update**:
   - **Latest Version**: `0.2.0`
   - **Download Base URL**: `https://github.com/defensia/agent/releases/download/v0.2.0`
   - Click **Save**

3. Within 60 seconds, all connected agents:
   - Receive the new version info via heartbeat response
   - Download and verify the new binary
   - Replace themselves and restart via systemd

### Update also via sync

The update info is also included in the sync response (`GET /api/v1/agent/sync`, every 5 minutes). This acts as a fallback in case heartbeats fail:

```json
{
  "agent_update": {
    "latest_version": "0.2.0",
    "download_base_url": "https://github.com/defensia/agent/releases/download/v0.2.0"
  }
}
```

### Security

- Binaries are verified via SHA256 checksum before replacing
- Download uses HTTPS only
- Only admins can set the version and URL in the panel
- The agent never executes downloaded code — it replaces the binary and restarts via systemd

---

## Heartbeat

The agent sends a heartbeat every 60 seconds:

```
POST /api/v1/agent/heartbeat
Authorization: Bearer {agent_token}

{
  "status": "online",
  "version": "0.1.0",
  "timestamp": "2026-02-24T12:00:00Z",
  "ip_address": "185.7.81.107",
  "zombie_count": 0,
  "web_server": "nginx",
  "web_server_version": "1.24.0"
}
```

The server responds with:

```json
{
  "status": "online",
  "last_seen_at": "2026-02-24T12:00:00Z",
  "latest_agent_version": "0.2.0",
  "agent_download_base_url": "https://github.com/defensia/agent/releases/download/v0.2.0"
}
```

The `latest_agent_version` and `agent_download_base_url` fields only appear when an admin has configured them. If the agent's current version is older, it triggers the auto-update process.

---

## Sync

Every 5 minutes the agent performs a full sync (`GET /api/v1/agent/sync`), which returns:

- Active firewall rules (block/allow)
- Whitelisted IPs (agent skips banning these)
- Agent update info (if a newer version is configured)

This is a fallback for WebSocket events — if a rule or ban was missed via Reverb, sync catches it.

---

## Architecture

```
agent/
├── cmd/defensia-agent/
│   └── main.go            # Entry point: register, start, heartbeat, sync loops
├── internal/
│   ├── api/
│   │   └── client.go      # HTTP client for all API calls
│   ├── config/
│   │   └── config.go      # /etc/defensia/config.json reader/writer
│   ├── firewall/
│   │   └── iptables.go    # iptables rule management (ban/unban/block/allow)
│   ├── geoip/
│   │   └── geoip.go       # GeoIP lookups for country-based blocking
│   ├── monitor/
│   │   └── zombie.go      # Zombie process scanner
│   ├── scanner/
│   │   └── scanner.go     # Security vulnerability scanner
│   ├── updater/
│   │   └── updater.go     # Auto-update: download, verify, replace binary
│   ├── watcher/
│   │   └── watcher.go     # auth.log tail + failed login pattern matching
│   └── ws/
│       └── ws.go          # WebSocket client (Reverb) for real-time events
├── Makefile
├── go.mod
└── go.sum
```

---

## Release

Releases are built automatically by GitHub Actions on tag push:

```bash
git tag agent/v0.2.0
git push --tags
# → GitHub Actions builds amd64 + arm64 + checksums + creates release
```

See [.github/workflows/release-agent.yml](../.github/workflows/release-agent.yml).
