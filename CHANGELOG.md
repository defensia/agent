# Changelog

All notable changes to the Defensia Agent.

## v1.2.0
- **ModSecurity inline WAF** — auto-detects Apache + mod_security2, writes 14 static rules (SQLi, XSS, RCE, SSRF, Shellshock, Log4Shell, Spring4Shell), configures Include + graceful reload. Blocks on first request. Zero impact without ModSecurity.
- Reports `modsec_active` in heartbeat

## v1.1.5
- **YARA install from dashboard** — "Install YARA" button auto-detects apt/dnf/yum/apk
- Reports `yara_installed` in heartbeat

## v1.1.4
- **YARA engine** — uses yara CLI if installed, 229 web rules from LMD synced from backend, cached locally

## v1.1.3
- Cap dynamic signatures at 200 to prevent scan stall on large servers
- Disabled LMD HEX regex patterns (need native YARA for performance)

## v1.1.2
- Removed UPLOAD_SHELL_PNG (too many FPs), skip WP <5.0 checksums, core file cap at 10

## v1.1.1
- Cap CORE_FILE_MODIFIED at 10 in scanner walk

## v1.1.0
- **Phase 3 complete** — WP database scanning, malicious process detection, quarantine, security posture score (0-100, A-F grade)

## v1.0.8
- Disabled exe/cmdline mismatch rootkit check (too many FPs on production servers)

## v1.0.7
- Fix rootkit exe/cmdline FPs (cron, php-fpm, redis, postgres, case-insensitive)
- Fix hash lookup empty JSON response

## v1.0.6
- Fix rootkit exe/cmdline FPs (python, busybox, interpreters)

## v1.0.5
- **Credential scan** — .env exposure, SSH key permissions, .git in web root, cloud credentials

## v1.0.4
- Malware scanner fully opt-in — nothing runs until user enables from dashboard

## v1.0.3
- **Phase 2 complete** — entropy analysis, timestamp anomalies, realtime watcher, system integrity (dpkg -V/rpm -Va), rootkit checks

## v1.0.2
- **Hash matching** — 64K+ hashes from MalwareBazaar + LMD, lookup via backend API

## v1.0.1
- **Dynamic signatures** — admin panel management, synced to agents via /sync

## v1.0.0
- **Scheduled malware scans** — configurable frequency/time/intensity from dashboard
- Allowlist sync from backend for user-ignored findings

## v0.9.99
- **Symfony, CakePHP, CodeIgniter** detection and security checks

## v0.9.98
- Framework checks FP prevention — production-only debug checks, line-level parsing

## v0.9.97
- Signature test suite — FP and detection tests for all signatures
- Fixed patterns with | (OR) using IsRegex
- Reduced FPs: MINER_GENERIC PHPOnly, narrowed PHISH_PAYPAL, FilesMan context

## v0.9.96
- Removed OBFUSC_HEX_DECODE and OBFUSC_LONG_BASE64 (getID3, theme configs FPs)
- Cap modified core files at 20

## v0.9.95
- **3-layer FP prevention** — WP core checksums, context-based severity, user allowlist with herd immunity

## v0.9.94
- Reduced malware signatures from 40 to 26 (removed TimThumb, preg_replace, iframe, PHPMailer FPs)
- PHPOnly flag, minified file skip, expanded exclusion dirs

## v0.9.93
- **Malware scanner Phase 1** — 40 signatures, framework detection (10 frameworks), framework security checks, dashboard tab with scan history

## v0.9.92
- **Malware scanner foundation** — scan engine, web root detection, signature matching

## v0.9.90
- Fix: auto-discover ingress logs from `/var/log/pods/` using pod UID

## v0.9.89
- Fix: entrypoint version detection + API URL for K8s registration

## v0.9.88
- Fix: entrypoint curl JSON payload on Alpine — single-line to avoid bad argument error

## v0.9.87
- **K8s API key registration** — multi-use Organization API Key for DaemonSet deployments

## v0.9.86
- Fix: remove `docker.sock` mount from Helm DaemonSet (fails on containerd-only K8s)

## v0.9.85
- **K8s ingress-level firewall** — ConfigMap deny list for nginx-ingress controller

## v0.9.84
- Signed releases with SLSA provenance
- Helm chart bumped to 0.3.0

## v0.9.83
- **Kubernetes Level 5** — K8s API integration, containerd log adapter, request counter
- K8s-aware Docker image with dual binary release (bare metal + K8s)

## v0.9.82
- **FTP brute force detection** — vsftpd, ProFTPD, Pure-FTPd

## v0.9.81
- Helm chart bumped to 0.2.0 (appVersion 0.9.80, mail + DB watchers)

## v0.9.80
- **Database auth watcher** — MySQL, PostgreSQL, MongoDB brute force detection + exposed port detection

## v0.9.79
- **Mail watcher** — Postfix SASL, Dovecot IMAP/POP3, Roundcube brute force detection (11 patterns)

## v0.9.78
- Fix: let backend handle ban escalation instead of agent-side `ExpiresAt`

## v0.9.77
- Fix: geoblocking reads `blocked_countries` from sync config (was silently ignored)

## v0.9.76
- Helm chart README with OCI install instructions, Docker labels docs, values table

## v0.9.75
- Fix: install oras in Helm chart workflow for provenance attach

## v0.9.74
- `values.schema.json` for Artifact Hub validation

## v0.9.73
- Fix: add Docker login for Cosign in Helm chart CI job

## v0.9.72
- **Cosign signing** for Docker images and Helm charts

## v0.9.71
- **Security: upgrade Go from 1.22 to 1.26** — fixes 25 CVEs in stdlib

## v0.9.70 – v0.9.66
- CI: Docker Hub push fixes and repo setup

## v0.9.65
- **Docker Hub dual-push** (`defensiacloud/agent`) + fix GHCR tags

## v0.9.64
- **Kubernetes Helm chart** — DaemonSet deployment + OCI chart published to GHCR

## v0.9.63
- **Docker Swarm support** — `docker-compose.swarm.yml` with `deploy: mode: global` (1 agent per node)
- Docker secrets support (`DEFENSIA_TOKEN_FILE`) for secure multi-node deployments

## v0.9.62
- **Docker labels autoconf** — `defensia.monitor`, `defensia.log-path`, `defensia.domain`, `defensia.waf`
- Configure monitoring per container via Docker labels without agent restart

## v0.9.61
- **Docker image published to GHCR** (`ghcr.io/defensia/agent`) — multi-arch (amd64 + arm64)
- Auto-register via `DEFENSIA_TOKEN` env var, docker-compose snippet included
- Automated build + push on every release tag

## v0.9.60
- **Threat feed blocking** — Spamhaus DROP/EDROP, Feodo Tracker, CINS Army applied to firewall
- Pre-emptive blocking of known-bad IPs

## v0.9.59
- **Virtual patching** — dynamic WAF rules from panel (regex patterns synced via heartbeat)

## v0.9.58
- Heartbeat reports `auth_watcher_method`, `firewall_mode`, `ban_capacity`, `active_bans_count`
- Fix: enable all WAF types by default when `waf_config` is null

## v0.9.57
- Fix: web log detection for Docker containers with non-standard log paths
- Improved Apache log discovery on cPanel servers

## v0.9.56
- Agent reports all bot actions (allow/log/block) as events for dashboard visibility
- Fix: skip web server reload when UA blocklist unchanged

## v0.9.55
- **UA bot blocking at web server level** — nginx `map+include` / Apache `SetEnvIfNoCase`
- Zero app load, graceful reload on every policy change

## v0.9.54
- `bot_unknown` events for unrecognized bot User-Agents — surfaces unknown crawlers in dashboard

## v0.9.53
- **Restore ipset firewall backend** — `defensia-bans` hash:ip set (65K capacity)
- Automatic FIFO rotation at 500 bans when ipset absent
- Migrates existing DROP rules on first run

## v0.9.52
- Skip private/reserved IPs (Docker bridge, localhost) in both SSH and WAF watchers

## v0.9.51
- Fix: deduplicate WAF scoring when same request appears in multiple log files

## v0.9.50
- **Cumulative per-IP WAF scoring engine** with configurable weights

## v0.9.49
- Fix: check WAF patterns against both raw and decoded URI to catch encoded attacks
- Private IP filter for WAF

## v0.9.48
- WAF config debug logging to confirm sync applies correctly

## v0.9.47
- Fix: connect WAF config from panel sync to web watcher — WAF detection was completely disabled

## v0.9.46
- Fix: remove duplicate `EventFunc` declaration

## v0.9.45
- User-Agent `DefensiaAgent/{version}` header on all API calls
- Allowed bots reported as `bot_crawl` events

## v0.9.44
- **Dynamic detection rules** from panel sync — SSH patterns configurable per server from dashboard

## v0.9.43
- **Expanded SSH detection** — 15 patterns (9 auth failures + 6 pre-auth scanning)

## v0.9.42
- **Monitor mode** — detect threats without blocking; new servers default to monitor mode

## v0.9.41
- Bot fingerprint detection with pre-filter gate before WAF scoring

## v0.9.40
- Report allowed bots as events for full visibility in dashboard

## v0.9.39
- **Bot fingerprint detection** from panel sync with allow/log/block policies

## v0.9.38
- Fix: nil pointer crash in `syncAndApply` when WAF disabled and BotFingerprints non-empty

## v0.9.37
- Dynamic WAF rules synced from panel (Phase 1)

## v0.9.36
- **Regex support** for dynamic WAF rules (OWASP CRS compatible)

## v0.9.35
- **Bot management** — pre-filter gate with allow/log/block policies per fingerprint

## v0.9.34
- **Configurable score weights** per server via WAF config from dashboard

## v0.9.33
- **ipset firewall backend** (65K+ ban capacity) with iptables FIFO fallback (500 bans)
- Startup trim for existing rules exceeding capacity

## v0.9.32
- Replace malware detection with WAF bot scoring engine

## v0.9.31
- Expand malware detection with YARA-sourced signatures and multi-language support

## v0.9.30
- Report monitor scan summaries to API
- Port scan detection, SYN flood monitoring, file integrity checks

## v0.9.29
- Add `port_scan`, `flood`, `integrity_change`, `malware` detectors

## v0.9.28
- Report `auth_watcher_method` in heartbeat
- **Honeypot trap detection** (50+ decoy endpoints)

## v0.9.27
- Fix: prefer journald on RHEL-family path (`/var/log/secure`) for CloudLinux 9.7/cPanel

## v0.9.26
- **Auto-remediation** — agent can fix 12 security findings on demand from dashboard

## v0.9.25
- **Security scanner** — 30+ hardening checks (SSH, web server, file permissions, CVEs)

## v0.9.24
- **CloudLinux/cPanel support** — journald fallback, `Invalid user` pattern, domlogs detection

## v0.9.23
- Fix: associate `server_name` domains with global `access_log` in nginx multi-vhost configs

## v0.9.22
- Improved Apache detection for CentOS/RHEL — `ServerRoot` resolution, symlink following, `apachectl -S`

## v0.9.21
- Fix: web container detection matches container port (`->80/tcp`) not host port (`:80->`)

## v0.9.20
- **Docker container detection** — auto-detect Docker, container inventory, web container identification
- Stdout log reader for containers using `docker logs`
- Docker info in heartbeat (`docker_version`, `docker_containers`)
- Bind mount + volume log discovery

## v0.9.19
- Whitelisted IPs are detected (events reported) but **never banned**

## v0.9.18
- Raw access log line included in event details for attack evidence

## v0.9.17
- Fix: Apache `${APACHE_LOG_DIR}` resolution
- Monitored domains and log paths reported in heartbeat

## v0.9.16
- Instant whitelist propagation via `sync.requested` WebSocket event

## v0.9.15
- WAF disabled by default until explicitly configured from panel
- Fix: false rollback on `"signal: terminated"`

## v0.9.14
- Fix: removed `updateServiceFile()` from updater — caused regression loop on every update

## v0.9.13
- Fix: clean up partial `.rollback` staging file on copy failure
- `StartLimitIntervalSec=0` moved to `[Unit]` section

## v0.9.12
- Fix: `ExecStartPre` also restores when binary is not executable
- Improved updater diagnostics, `recent_logs` in failure event payloads

## v0.9.11
- Fix: move `StartLimitIntervalSec` to `[Unit]` and auto-patch service file on update

## v0.9.10
- Fix: prevent binary loss during failed rollback
- Health-check window extended, stale ban cleanup on sync

## v0.9.9
- Fix: prevent `start-limit-hit` during auto-updates
- Fix: cross-device rename failure in updater

## v0.9.8
- Report `waf_disabled` event to panel when no web logs found
- Preflight check uses `check` subcommand; atomic rollback

## v0.9.7
- **Docker container log detection** via bind-mounts

## v0.9.6
- **Web exploit detection** — Spring4Shell, Log4Shell, Struts OGNL, ThinkPHP RCE, Drupalgeddon2

## v0.9.5
- **Atomic binary replacement** + 15s post-restart health check; rollback on crash

## v0.9.4
- Fix: double URL-decode bypass detection
- Reduce 404 flood threshold

## v0.9.3
- **Per-server WAF configuration** — enable/disable types, detect-only mode, custom thresholds

## v0.9.2
- **XSS, SSRF, web shell, header injection** detection

## v0.9.1
- Fix: restore release workflow, LICENSE

## v0.9.0
- **Initial WAF** — SQL injection, path traversal, RCE, shellshock, `.env` probe, config probe, WordPress brute force, XMLRPC abuse, 404 flood, scanner detection

## v0.8.5
- Fix: prevent banning server's own IPs and organization sibling IPs

## v0.8.4
- Fix: prevent banning reserved IPs (loopback, private, link-local)

## v0.8.3
- Include recent service logs in update failure events

## v0.8.2
- Report update outcomes (success/failure) to server via events API

## v0.8.1
- **Robust auto-updater** with backup, preflight check, and rollback

## v0.8.0
- **System metrics collection** — CPU, memory, disk, load, network reported to dashboard

## v0.7.0
- Fix: skip systemd hardening on old kernels

## v0.6.1
- **Force update via WebSocket** command

## v0.6.0
- **Multi-vhost domain mapping** — auto-detect nginx/Apache vhosts, hot-reload every 5 min

## v0.5.2
- Maintenance release

## v0.5.1
- **Multi-log web watcher** — monitor multiple log files simultaneously
- Software version scanner, updater improvements

## v0.3.1
- Fix: support upstart and sysvinit restart in auto-updater

## v0.3.0
- **Software audit collector** and sync via API/WebSocket

## v0.2.2
- Fix: static-link binary + support upstart/sysvinit

## v0.2.1
- Fix: resolve "text file busy" error on auto-update
- Allow ldflags version injection

## v0.2.0
- **IP detection, auto-update via heartbeat, install-only mode**
- DigitalOcean Marketplace support

## v0.1.0
- Initial release — SSH brute force detection, GeoIP blocking, heartbeat, ban enforcement via iptables
