# Changelog

All notable changes to the Defensia Agent.

## v0.9.80+
- Kubernetes DaemonSet support via Helm chart
- Ingress controller WAF monitoring
- Pod event collection (create, update, delete)
- K8s API audit log monitoring
- Organization API key registration for Helm deployments
- Cluster name auto-detection

## v0.9.63
- **Docker Swarm support**: `docker-compose.swarm.yml` with `deploy: mode: global` (1 agent per node)
- Docker secrets support (`DEFENSIA_TOKEN_FILE`) for secure multi-node deployments

## v0.9.62
- **Docker labels**: `defensia.monitor`, `defensia.log-path`, `defensia.domain`, `defensia.waf`
- Configure monitoring per container via Docker labels without agent restart

## v0.9.61
- **Docker image** published to GHCR (`ghcr.io/defensia/agent`): multi-arch (amd64+arm64)
- Auto-register via `DEFENSIA_TOKEN` env var, docker-compose snippet included
- Automated build+push on every release tag

## v0.9.60
- Threat feed blocking (Spamhaus DROP/EDROP, Feodo Tracker, CINS Army)
- Pre-emptive blocking of known-bad IPs

## v0.9.59
- Virtual patching: dynamic WAF rules from panel (regex patterns synced via heartbeat)

## v0.9.58
- Heartbeat reports `auth_watcher_method`, `firewall_mode`, `ban_capacity`, `active_bans_count`

## v0.9.57
- Fix: web log detection for Docker containers with non-standard log paths
- Improved Apache log discovery on cPanel servers

## v0.9.56
- Agent reports all bot actions (allow/log/block) as events

## v0.9.55
- UA bot blocking at web server level: nginx `map+include` / Apache `SetEnvIfNoCase`
- Zero app load, graceful reload on policy change

## v0.9.54
- `bot_unknown` events for unrecognized bot User-Agents

## v0.9.53
- Restore ipset firewall backend: `defensia-bans` hash:ip set (65K capacity)
- Automatic FIFO rotation at 500 bans when ipset absent
- Migrates existing DROP rules on first run

## v0.9.52
- Skip private/reserved IPs (Docker bridge, localhost) in SSH and WAF watchers

## v0.9.51
- Fix: deduplicate WAF scoring when same request appears in multiple log files

## v0.9.50
- Cumulative per-IP WAF scoring engine with configurable weights

## v0.9.49
- Fix: check WAF patterns against both raw and decoded URI
- Private IP filter

## v0.9.47
- Fix: connect WAF config from panel sync to web watcher

## v0.9.46
- Fix: remove duplicate EventFunc declaration

## v0.9.45
- User-Agent `DefensiaAgent/{version}` header
- Allowed bots reported as `bot_crawl` events

## v0.9.44
- Dynamic detection rules from panel sync
- SSH patterns configurable per server from dashboard

## v0.9.43
- Expanded SSH detection: 15 patterns (9 auth failures + 6 pre-auth scanning)

## v0.9.42
- Monitor mode: detect threats without blocking
- New servers default to monitor mode

## v0.9.41
- Bot fingerprint detection with pre-filter gate before WAF scoring

## v0.9.40
- Bot management: allow/log/block policies per fingerprint, synced from panel

## v0.9.39
- Regex support for dynamic WAF rules (OWASP CRS compatible)

## v0.9.38
- Fix: nil pointer crash in `syncAndApply` when WAF disabled and BotFingerprints non-empty

## v0.9.37
- Dynamic WAF rules synced from panel (Phase 1)

## v0.9.35
- Bot scoring engine replaced malware detection
- Per-IP cumulative scoring with decay

## v0.9.34
- Configurable score weights per server via WAF config

## v0.9.33
- ipset firewall backend (65K+ ban capacity) with iptables FIFO fallback (500 bans)
- Startup trim for existing rules exceeding capacity

## v0.9.32
- Malware detection: cryptominers, rootkits, web shells (60+ signatures)

## v0.9.31
- Bot scoring engine: 4 action levels (observe/throttle/block/blacklist), category classification

## v0.9.30
- File integrity monitoring, port scan detection, SYN flood monitoring

## v0.9.29
- Fix: auto-update download URL constructed from target_version

## v0.9.28
- Honeypot trap detection (50+ decoy endpoints)

## v0.9.27
- Security scanner: 30+ hardening checks (SSH, web server, file permissions, CVEs)

## v0.9.26
- Auto-remediation: fix 12 security findings on demand from dashboard

## v0.9.25
- Timed bans via iptables with auto-expiry

## v0.9.24
- CloudLinux/cPanel: cPHulk SQLite polling, journald fallback, extended SSH regex

## v0.9.23
- Fix: nginx global `access_log` with server blocks domain association

## v0.9.22
- Improved Apache detection for CentOS/RHEL

## v0.9.21
- Fix: web container detection matches container port

## v0.9.20
- Docker container detection, stdout log reader, Docker info in heartbeat

## v0.9.19
- Whitelisted IPs are detected (events reported) but never banned

## v0.9.18
- Raw access log line included in event details

## v0.9.17
- Fix: Apache `${APACHE_LOG_DIR}` resolution

## v0.9.16
- Instant whitelist propagation via WebSocket

## v0.9.15
- Fix: false rollback on `"signal: terminated"`

## v0.9.14
- Fix: removed `updateServiceFile()` regression loop

## v0.9.13
- Fix: `StartLimitIntervalSec=0` moved to `[Unit]`

## v0.9.12
- Improved updater diagnostics

## v0.9.10
- Fix: health-check window extended; stale ban cleanup

## v0.9.9
- Fix: cross-device rename failure in updater

## v0.9.8
- Fix: preflight check; atomic rollback

## v0.9.7
- Docker container log detection via bind-mounts

## v0.9.6
- `web_exploit` detection (Spring4Shell, Log4Shell, Struts OGNL...)

## v0.9.5
- Atomic binary replacement + 15s post-restart health check; rollback on crash

## v0.9.3
- Per-server WAF config: enable/disable types, detect-only mode, custom thresholds

## v0.9.2
- XSS, SSRF, web shell, header injection detection

## v0.9.0
- Initial WAF: SQLi, path traversal, RCE, shellshock, env/config probe, WordPress, XMLRPC, 404 flood, scanner detection

## v0.6.x
- Brute-force detection, GeoIP blocking, zombie process detection, auto-update, IP safety system
