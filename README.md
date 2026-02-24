# Defensia Agent

Open-source security agent for Linux servers. Monitors `auth.log`, blocks attackers via `iptables`, and syncs threat intelligence from [Defensia Cloud](https://defensia.cloud).

## Quick Install

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

Get your install token from [defensia.cloud/dashboard](https://defensia.cloud/dashboard) after creating an account.

## Requirements

- Linux (Ubuntu 20+, Debian 11+, CentOS 8+, RHEL 8+, Rocky 8+, AlmaLinux 8+)
- `iptables`
- `systemd`
- Root access

## How it works

```
auth.log tail
    |
    v
Watcher goroutine
    |  "Failed password for root from 5.5.5.5"
    |  5 attempts in 5min window
    v
BanIP (iptables -I INPUT 1 -s 5.5.5.5 -j DROP)
    |
    +---> POST /api/v1/agent/bans -> server logs + broadcasts to other agents
         ^
WebSocket (Reverb)
    |  ban.created event from server/panel
    +---> BanIP immediately -- no 5min polling wait

Heartbeat: POST /api/v1/agent/heartbeat  every 60s
Sync:      GET  /api/v1/agent/sync       every 5min (fallback)
```

## Non-interactive install (Ansible / CI)

```bash
DEFENSIA_SERVER_URL=https://defensia.cloud \
DEFENSIA_AGENT_NAME=web-01 \
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <TOKEN>
```

## Uninstall

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --uninstall
```

## Config

Stored at `/etc/defensia/config.json` (root-only, mode 0600):

```json
{
  "server_url":    "https://defensia.cloud",
  "agent_token":   "64-char-token-from-registration",
  "agent_id":      1,
  "reverb_url":    "wss://ws.defensia.cloud/app/APP_KEY",
  "reverb_app_key": "APP_KEY"
}
```

## Commands

```bash
# Via systemd (recommended)
systemctl status defensia-agent
systemctl stop defensia-agent
journalctl -u defensia-agent -f

# Manual start (foreground)
defensia-agent start
```

## Development

```bash
# Run locally
DEFENSIA_CONFIG=./dev-config.json AUTH_LOG_PATH=./test-auth.log \
  go run ./cmd/defensia-agent start

# Build
make build            # current platform
make build-linux      # Linux amd64
make build-linux-arm  # Linux arm64
```

## Banning logic

| Parameter | Default | Override |
|---|---|---|
| Threshold | 5 failed attempts | -- |
| Window | 5 minutes | -- |
| Log file | `/var/log/auth.log` | `AUTH_LOG_PATH` env |
| Config | `/etc/defensia/config.json` | `DEFENSIA_CONFIG` env |

## License

MIT License. See [LICENSE](LICENSE).
