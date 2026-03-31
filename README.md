<p align="center">
  <img src="https://defensia.cloud/img/logo.svg" alt="Defensia" width="200">
</p>

<h3 align="center">Server security that installs in 30 seconds</h3>

<p align="center">
  Lightweight Go agent that detects attacks in real time and blocks them automatically.<br>
  SSH brute force, WAF, bot management, Docker and Kubernetes — zero configuration.
</p>

<p align="center">
  <a href="https://github.com/defensia/agent/releases"><img src="https://img.shields.io/github/v/release/defensia/agent?label=version&color=brightgreen" alt="Version"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://go.dev"><img src="https://img.shields.io/badge/Go-1.26+-00ADD8?logo=go&logoColor=white" alt="Go"></a>
  <a href="https://github.com/defensia/agent"><img src="https://img.shields.io/badge/Platform-Linux-orange?logo=linux&logoColor=white" alt="Platform"></a>
  <a href="https://github.com/defensia/agent/pkgs/container/agent"><img src="https://img.shields.io/badge/Docker-ghcr.io-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://artifacthub.io/packages/helm/defensia/defensia-agent"><img src="https://img.shields.io/badge/Helm-Artifact_Hub-0F1689?logo=helm&logoColor=white" alt="Helm"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/defensia/agent"><img src="https://api.securityscorecards.dev/projects/github.com/defensia/agent/badge" alt="OpenSSF Scorecard"></a>
</p>

<p align="center">
  <a href="https://defensia.cloud">Website</a> ·
  <a href="https://defensia.cloud/docs">Docs</a> ·
  <a href="https://defensia.cloud/docs/installation">Install Guide</a> ·
  <a href="https://defensia.cloud/pricing">Pricing</a> ·
  <a href="https://github.com/defensia/agent/issues">Issues</a>
</p>

---

## The problem

The average Linux VPS receives its first automated attack **within 4 minutes** of going online. SSH brute force, web exploits, bot scraping, port scans.

Most developers find out when it's already too late — or never.

**fail2ban** blocks after the fact, with no visibility. **CrowdSec** requires complex setup. Enterprise tools cost $20-200+/host.

Defensia fills the gap: **one command to install, real-time dashboard, automatic blocking, €9/server**.

## Quick start

```bash
# Linux (one-liner)
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>

# Docker
docker run -d --name defensia-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -e DEFENSIA_TOKEN=<YOUR_TOKEN> \
  ghcr.io/defensia/agent:latest

# Kubernetes (Helm)
helm install defensia-agent \
  oci://ghcr.io/defensia/charts/defensia-agent \
  --set config.organizationApiKey=<YOUR_API_KEY> \
  --namespace defensia-system --create-namespace
```

> **[Get your token at defensia.cloud](https://defensia.cloud)** — free tier includes 1 server with full protection.

---

## Why Defensia

| | fail2ban | CrowdSec | BitNinja | **Defensia** |
|---|:---:|:---:|:---:|:---:|
| Real-time dashboard | — | Paid ($2K+/yr) | Yes | **Yes** |
| One-command install | — | — | cPanel only | **Yes** |
| SSH detection | Yes | Yes | Yes | **Yes (15 patterns)** |
| Web Application Firewall | — | Partial | Yes | **Yes (15 OWASP types)** |
| Bot management | — | — | Yes | **Yes (70+ fingerprints)** |
| Docker container awareness | — | — | — | **Yes** |
| Kubernetes / Helm | — | Yes | — | **Yes (DaemonSet)** |
| Monitor mode (detect only) | — | — | — | **Yes** |
| Works on any Linux | Yes | Yes | cPanel/Plesk | **Yes** |
| Price | Free | Free / $2K+ | €14-52/srv | **€9/srv** |

---

## What it detects

### SSH & brute force
15 detection patterns: failed passwords, invalid users, PAM failures, pre-auth scanning, protocol mismatches, kex negotiation drops. Patterns are synced from the dashboard — enable/disable per server without restarting the agent.

### Web Application Firewall

| Attack type | Score | Mode |
|---|:---:|---|
| RCE / Web shell / Shellshock | +50 | Score-based |
| Scanner UA (sqlmap, nikto, nmap, nuclei...) | +50 | Score-based |
| SQL injection / SSRF / Web exploit | +40 | Score-based |
| Honeypot trap (50+ decoy endpoints) | +40 | Score-based |
| Path traversal / Header injection | +30 | Score-based |
| WordPress brute force | +30 | Threshold (10 req / 2 min) |
| XSS / `.env` probe / XMLRPC | +25 | Score-based |
| Config probing / Scanner pattern | +20 | Score-based |
| 404 flood | +15 | Threshold (30 req / 5 min) |

Each detection adds points to a per-IP score. Scores decay at -5 pts/min. Action levels: **observe** (30) → **throttle** (60) → **block 1h** (80) → **blacklist 24h** (100+). All weights configurable per server.

### Bot management
70+ bot fingerprints (search engines, AI crawlers, SEO tools, scanners). Per-org policies: **allow** / **log** / **block**. Blocked bots are rejected at nginx/Apache level — connection closed before your app is reached.

### And more
- **Docker-aware** — auto-detects web containers, reads logs via bind mounts and volumes
- **GeoIP blocking** — block entire countries from the dashboard
- **Network ban propagation** — ban on one server applies to all your servers
- **Security scanner** — 30+ hardening checks with auto-remediation
- **Vulnerability scanning** — CVE matching via NVD + Exploit-DB, EPSS scoring
- **Monitor mode** — detect threats without blocking (new servers default to this)
- **System metrics** — CPU, memory, disk reported to dashboard

---

## How it works

```
auth.log / web access logs / Docker logs / K8s ingress logs
    │
    ▼
Log auto-detection
    │  nginx -T / apachectl -S / docker inspect / K8s API
    │  Resolves bind mounts, volumes, symlinks
    ▼
Watcher goroutines
    │  Detect brute force, SQLi, XSS, SSRF, path traversal, web shells...
    ▼
Bot Scoring Engine (per-IP, decaying)
    │
    ├─ < 30 pts  → observe (log only)
    ├─ ≥ 30 pts  → throttle
    ├─ ≥ 80 pts  → block 1h
    └─ ≥ 100 pts → blacklist 24h
            │
            ▼
    ipset add defensia-bans <IP>
            │  Falls back to iptables -I INPUT -s <IP> -j DROP
            │  ipset: 65K+ IPs  ·  iptables fallback: 500 (FIFO rotation)
            │
            ├──► POST /api/v1/agent/bans → dashboard
            └──► WebSocket propagates ban to all your servers
```

The agent **never bans** reserved IPs, your server's own IPs, or the Defensia API endpoint — even if the backend sends a bad rule.

---

## Install

### Linux (recommended)

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

**Supported:** Ubuntu 20+, Debian 11+, CentOS 7+, RHEL 8+, Rocky, Alma, Amazon Linux 2023, Fedora
**Requires:** `iptables`, `systemd`, root access · **Recommended:** `ipset` (increases ban capacity to 65K+)

### Docker

```bash
docker run -d --name defensia-agent --restart unless-stopped \
  --network host --pid host \
  -v /var/log:/var/log:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v defensia-config:/etc/defensia \
  -e DEFENSIA_TOKEN=<YOUR_TOKEN> \
  ghcr.io/defensia/agent:latest
```

**Image:** `ghcr.io/defensia/agent` — multi-arch (amd64 + arm64), ~40MB

<details>
<summary>Docker Compose</summary>

```yaml
services:
  defensia-agent:
    image: ghcr.io/defensia/agent:latest
    container_name: defensia-agent
    restart: unless-stopped
    privileged: true
    network_mode: host
    pid: host
    environment:
      - DEFENSIA_TOKEN=${DEFENSIA_TOKEN}
    volumes:
      - /var/log:/var/log:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - defensia-config:/etc/defensia

volumes:
  defensia-config:
```

```bash
DEFENSIA_TOKEN=<YOUR_TOKEN> docker compose up -d defensia-agent
```

</details>

<details>
<summary>Docker Swarm (global service)</summary>

```bash
# Store token as a Docker secret
echo "<YOUR_TOKEN>" | docker secret create defensia_token -

# Deploy 1 agent per node
docker stack deploy -c docker-compose.swarm.yml defensia
```

See [docker-compose.swarm.yml](docker-compose.swarm.yml) for the full stack definition.

</details>

### Kubernetes (Helm)

```bash
helm install defensia-agent \
  oci://ghcr.io/defensia/charts/defensia-agent \
  --set config.organizationApiKey=<YOUR_API_KEY> \
  --set config.serverUrl=https://defensia.cloud \
  --namespace defensia-system --create-namespace
```

Deploys a **DaemonSet** — one agent per node (including control-plane). RBAC, tolerations, and resource limits pre-configured.

<details>
<summary>Custom values.yaml</summary>

```yaml
config:
  organizationApiKey: "your-org-api-key"
  serverUrl: "https://defensia.cloud"
  clusterName: "production"    # auto-detected if omitted

resources:
  limits:
    cpu: 100m
    memory: 128Mi
  requests:
    cpu: 50m
    memory: 64Mi

tolerations:
  - operator: Exists           # run on all nodes
```

```bash
helm install defensia-agent \
  oci://ghcr.io/defensia/charts/defensia-agent \
  -f values.yaml -n defensia-system --create-namespace
```

</details>

**Chart:** [Artifact Hub](https://artifacthub.io/packages/helm/defensia/defensia-agent) · Images signed with [Cosign](https://github.com/sigstore/cosign) · Helm chart with GPG provenance

### Uninstall

```bash
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --uninstall
```

---

## Configuration

<details>
<summary><strong>Per-server WAF configuration</strong></summary>

Each attack type can be independently configured from the dashboard (Server → Web Protection). Changes sync within 60 seconds.

- **Enable/disable types** — disable rules irrelevant to your stack (e.g. `wp_bruteforce` on a non-WordPress server)
- **Detect-only mode** — record events without banning
- **Custom thresholds** — override defaults for `wp_bruteforce`, `xmlrpc_abuse`, `scanner_detected`, `404_flood`
- **Custom score weights** — adjust points per detection type

`null` WAF config → all 15 types active with default thresholds (fully backward compatible).

</details>

<details>
<summary><strong>Docker labels</strong></summary>

Configure monitoring per container via Docker labels — no agent restart needed:

```yaml
services:
  nginx:
    image: nginx
    labels:
      defensia.monitor: "true"
      defensia.log-path: "/var/log/nginx/access.log"
      defensia.domain: "example.com,api.example.com"
    volumes:
      - /var/log/nginx:/var/log/nginx
```

| Label | Values | Effect |
|---|---|---|
| `defensia.monitor` | `true` / `false` | Force-include or exclude a container |
| `defensia.log-path` | Host path(s), comma-separated | Explicit log path (skips auto-detection) |
| `defensia.domain` | Domain(s), comma-separated | Associate domain names with logs |
| `defensia.waf` | `true` / `false` | Informational (WAF is controlled from the panel) |

**Priority**: `defensia.log-path` label > `nginx -T` auto-detection > bind-mount scan > `docker logs`.

</details>

<details>
<summary><strong>Manual log path override</strong></summary>

If auto-detection doesn't find your logs, set `WEB_LOG_PATH`:

```bash
sudo systemctl edit defensia-agent
```

```ini
[Service]
Environment="WEB_LOG_PATH=/var/log/httpd/access_log,/var/log/nginx/custom.log"
```

```bash
sudo systemctl restart defensia-agent
```

</details>

<details>
<summary><strong>Environment variables</strong></summary>

Stored in `/etc/defensia/agent.conf`:

| Variable | Description | Default |
|---|---|---|
| `DEFENSIA_TOKEN` | Agent auth token | *(from registration)* |
| `DEFENSIA_SERVER` | Panel server URL | `https://defensia.cloud` |
| `DEFENSIA_LOG_PATH` | Auth log file path | *(auto-detected)* |
| `DEFENSIA_HEARTBEAT` | Heartbeat interval (seconds) | `30` |
| `DEFENSIA_BAN_THRESHOLD` | Failed attempts before ban | `5` |
| `DEFENSIA_WS_ENABLED` | Enable WebSocket | `true` |
| `DEFENSIA_GEOIP_ENABLED` | Enable GeoIP lookups | `true` |
| `WEB_LOG_PATH` | Override web log paths | *(auto-detected)* |

</details>

---

## Troubleshooting

<details>
<summary><code>"Peer's Certificate issuer is not recognized"</code> during install</summary>

Affects CentOS 7, RHEL 7, and systems with outdated `ca-certificates`:

```bash
curl -sk https://letsencrypt.org/certs/isrgrootx1.pem -o /tmp/isrg.pem
export CURL_CA_BUNDLE=/tmp/isrg.pem
curl -fsSL https://defensia.cloud/install.sh | sudo bash -s -- --token <YOUR_TOKEN>
```

</details>

<details>
<summary>Agent shows <code>203/EXEC</code> — service fails to start</summary>

Binary missing or corrupted. Restore from backup:

```bash
cp /usr/local/bin/defensia-agent.bak /usr/local/bin/defensia-agent
chmod 755 /usr/local/bin/defensia-agent
systemctl reset-failed defensia-agent && systemctl start defensia-agent
```

If `start-limit-hit`:

```bash
systemctl reset-failed defensia-agent
systemctl start defensia-agent
```

</details>

<details>
<summary>WAF not detecting attacks</summary>

Check which logs the agent is monitoring:

```bash
journalctl -u defensia-agent | grep webwatcher
```

If no logs found: your web server logs must be accessible on the host. For Docker web servers, bind-mount the log directory:

```yaml
volumes:
  - /var/log/nginx:/var/log/nginx
```

</details>

More troubleshooting at [defensia.cloud/docs/troubleshooting](https://defensia.cloud/docs/troubleshooting).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Defensia Cloud                        │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  │
│  │ Dashboard │  │ REST API │  │ WebSocket│  │ Threat │  │
│  │  (Vue 3) │  │ (Laravel)│  │ (Reverb) │  │  Intel │  │
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTPS + WSS
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   ┌─────────┐    ┌─────────┐    ┌─────────────┐
   │  Agent  │    │  Agent  │    │ Agent (K8s) │
   │  (VPS)  │    │(Docker) │    │ (DaemonSet) │
   └─────────┘    └─────────┘    └─────────────┘
   SSH + WAF      SSH + WAF +     Ingress WAF +
   + GeoIP        Docker detect   Pod events +
   + Metrics      + Container     API audit
                  inventory
```

The agent is a single static Go binary (~12MB). No dependencies, no runtime, no garbage. Runs as `systemd` service, Docker container, or Kubernetes DaemonSet.

**Resource usage:** <1% CPU, <30MB RAM on a typical server.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

Recent highlights:

| Version | Highlight |
|---|---|
| v0.9.80+ | Kubernetes DaemonSet support, Helm chart, ingress WAF |
| v0.9.63 | Docker Swarm global service, Docker secrets |
| v0.9.62 | Docker labels (`defensia.monitor`, `defensia.log-path`, `defensia.domain`) |
| v0.9.50+ | Cumulative per-IP WAF scoring engine with configurable weights |
| v0.9.44 | Dynamic detection rules from dashboard (SSH patterns per server) |
| v0.9.42 | Monitor mode (detect without blocking) |
| v0.9.40 | Bot management with allow/log/block policies |
| v0.9.33 | ipset firewall backend (65K+ ban capacity) |
| v0.9.27 | Security scanner (30+ hardening checks) |
| v0.9.20 | Docker container detection and log discovery |
| v0.9.0 | Initial WAF: 15 OWASP attack types |

---

## Contributing

Contributions are welcome. Please [open an issue](https://github.com/defensia/agent/issues) before submitting large changes.

```bash
# Build
go build -o defensia-agent ./cmd/defensia-agent

# Run locally
./defensia-agent start
```

---

## Blog

- [I analyzed 250,000 attacks on my Linux servers. Here's what I found.](https://dev.to/defensia/i-analyzed-250000-attacks-on-my-linux-servers-heres-what-i-found-20o8) — Real data from 14 production servers: SSH brute force, RCE, env probing, path traversal, and more.

---

## License

[MIT](LICENSE) — use it however you want.

---

<p align="center">
  <a href="https://defensia.cloud">defensia.cloud</a> · Built for developers who run their own servers
</p>
