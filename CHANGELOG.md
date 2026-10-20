# Changelog

All notable changes to the Defensia Agent.

## Unreleased
- **fix: Docker container no longer restart-loops on a spent install token** — install tokens are single-use. A container recreated without a persisted `/etc/defensia` re-ran `register` with the already-consumed token, got a 401, exited 1, and `--restart unless-stopped` relaunched it forever (10 register calls in the first minute against a local test server, and climbing).
- `defensia-agent register` now exits **78 (EX_CONFIG)** when the panel rejects the request itself (any 4xx except 429: spent/expired/unknown token, plan limit, rejected field) or the token is malformed locally. Transient failures (no response, 5xx, 429, unwritable config) keep exit 1. The installer treats any non-zero as failure, so it is unaffected.
- `docker-entrypoint.sh`, on exit 78, prints what to do (new token + `-v /etc/defensia:/etc/defensia`) and **stays idle instead of exiting** — Docker restarts even on exit 0. It re-checks every 60s for a `config.json` (then starts the agent) and repeats the reminder every 10 min. The rejected token's sha256 is kept in `/etc/defensia/.rejected-token` (or `/tmp` when not writable), so a `docker restart` with the same token does not call the API again; a different `DEFENSIA_TOKEN` clears it. Same test: 1 register call, container Up, 0 restarts.
- Transient registration failures are now retried inside the entrypoint with a 30s, then 60s backoff, instead of exiting into the restart policy.
- The entrypoint warns before registering when `/etc/defensia` is not a mounted volume, since recreating such a container needs a new token.
- `docker stop` on an idle or backing-off container now returns immediately (SIGTERM is trapped) instead of waiting for the 10s kill.

## v1.4.79
- **fix: ordinary cookies no longer trip the header-injection rule** — rule 9910010 matched percent-encoded newlines (`%0d%0a|%0a|%0d`) anywhere in `REQUEST_HEADERS`. Measured against 1,040,242 legitimate requests from 692 sites, that one alternation produced **1,084 of the 2,261 false positives — 48% of every false positive the inline rule set generated**. All 1,084 were a `%0a` or `%0d` byte inside an opaque session cookie, e.g. `USER_ID=5%0a%5d%95%5b…`.
- The encoded forms could never have caught the attack the rule is named for. `REQUEST_HEADERS` is populated *after* the HTTP parser has split the request on CRLF, so an encoded newline sitting inside a header value cannot split a header — the splitting attack needs a literal CR/LF, and a literal one in an already-parsed value means the request was malformed before ModSecurity saw it. The rule now matches literal `(\r\n|\n|\r)` only, which is the sole form that carries signal.
- Nothing was given up to get this: a reflected response-splitting payload arrives percent-encoded in the URI or the body, not in a request header, so it was never in this rule's reach in the first place.
- Effect on the same corpus: the inline false-positive rate drops from **0.243% to 0.126%** — 2,261 blocked legitimate requests down to 1,177.
- **fix: path traversal in a POST body is now reachable at all** — rule 9910004 targeted `REQUEST_URI` only. It caught 30.2% of traversal sent as GET and **0.02% of traversal sent as POST**: 14,157 payloads were structurally unblockable rather than merely missed. It now targets `ARGS|ARGS_NAMES|REQUEST_URI` in `phase:2`.
- Both halves of that change are required, which is why neither shipped alone. `REQUEST_URI` already carries the query string, so the only ground left to gain is the request body — and `ARGS` is not populated from a body until phase 2. Adding `ARGS` while leaving the rule in `phase:1` measured as exactly inert: POST-body traversal still returned 200.
- Measured on 73,924 malicious payloads: traversal detection **15.11% → 30.20%**, and the inline true-positive rate across all families **14.719% → 20.498%**, +4,272 blocked attacks.
- 9910007 (web shell), 9910008 (env probe) and 9910009 (config probe) share the same URI-only shape and were deliberately left as they are. The same widening measured no gain on them, and 9910009 already produces false positives of its own — matching shapes is not a reason to touch a rule.
- **Both fixes raise a ceiling, not a floor.** The agent writes `SecRule` directives and never `SecRuleEngine`, so on a host whose ModSecurity is still at the stock `DetectionOnly` these rules log without blocking, and the numbers above are what you get once prevention is on. Turning it on stays the operator's decision.

## v1.4.78
- **fix: registration could lock a new customer out for an hour** — a single rejected field cost five registration attempts and then an hour of 429s, with the real cause never shown. One production install failed 69 times in 22 minutes without the operator ever learning which field was wrong.
- **No required field can leave the agent empty any more.** The panel validates all seven of `install_token, name, hostname, ip_address, os, os_version, version` as required, and each one now has a fallback: `os_version` → `unknown` (matching what the no-`/etc/os-release` path already sent), `os` → `linux`, `hostname` ↔ `name` (each falls back to the other, since both identify the same server), `version` → `unknown`.
- The concrete gap was **`os_version`**: `/etc/os-release` makes `VERSION_ID` optional, so Arch, Gentoo and minimal container images parsed to an empty version and were rejected with a 422. The name was already guarded; the version was not.
- **An install token that cannot pass validation is now rejected locally**, before any request. The panel requires exactly 64 characters, and a token truncated or newline-padded by a shell paste is the most common registration failure — it previously cost a rate-limit slot and returned a 422 indistinguishable from a server-side problem. It is also the only required field with no honest fallback, since inventing one would turn a clear error into a vague one.
- **`AGENT_IP` is now validated.** A hostname or typo in that variable was forwarded verbatim and failed the panel's `ip` rule. Invalid values are ignored with a warning.
- **IPv6-only hosts now register with their real address.** Outbound-IP detection dialled an IPv4 address and then scanned interfaces for IPv4 only, so an IPv6-only host fell through to the `0.0.0.0` placeholder.
- **behaviour change — retries:** a 4xx other than 429 is no longer retried. It is permanent: the same payload will be rejected identically, and retrying only spends the hourly budget and replaces the real error with a rate-limit error. A 429 is retried only when `Retry-After` asks for a minute or less; past that the agent stops and prints how long to wait rather than appearing to hang. Transport errors and 5xx keep a 2s/4s backoff. One install run is now capped at **three** attempts against the panel's budget of five per hour, so a failed run always leaves the operator a real retry.
- **Registration failures now say what was rejected.** The output carries the HTTP status, the server's own message, each rejected field with its reason, and the action that resolves it. The previous `log.Fatalf("Registration failed: %v")` did include the response body, but flattened it into one line ending in raw JSON — which is why the incident above was diagnosed as a bad install token.

## v1.4.77
- **feat: Comodo cWAF rules are now classified** — Comodo ships by default on cPanel and DirectAdmin, and its rules use the vendor's reserved 200000-299999 ID range. Nothing matched them, so every Comodo detection arrived as `unknown` → `modsecurity_block` at CRITICAL severity. In production that was 7,424 uncategorised critical events across three servers, growing daily.
- Comodo is mapped **per rule ID**, not per family. Its numbering is structural rather than semantic: it groups rules by rule *file* (`00_Init_`, `10_HTTP_`, `21_PHP_`), i.e. by the layer of the request inspected. The 210xxx block alone holds pure policy enforcement, `/.env` probing, LFI and crawler detection, so a family-prefix map would be actively wrong. 39 rules mapped; unmapped Comodo IDs degrade to `modsecurity_block` instead of returning to `unknown`.
- The single highest-volume Comodo rule, 210492 (3,066 events), is `/.env` retrieval and now reports as `env_probe`.
- **behaviour change — severity:** probe classes (`env_probe`, `config_probe`, `path_traversal`) are now rated by outcome using the response status rather than by how gravely the rule set rated them. A probe the server refused is `warning`; one answered with 2xx means the file was served and stays `critical`. Measured over seven days this is **12,979 fewer `critical` events per week** from ModSecurity (18,370 → 5,391). Anyone with an alert rule on `critical_event` will see the difference. Enforcement rules stay capped at `info`.
- **behaviour change — ranking:** rules are now ranked by attack class rather than by rule family, so precedence can no longer depend on which vendor's rule fired. SQLi beats protocol enforcement because SQLi is the graver class, not because one rule set outranks another. This also changes how mixed CRS entries resolve, though only 3 such events exist in production today.
- As part of that, **Defensia's own inline rules (9910xxx) lose their vendor precedence**. They previously outranked every CRS family unconditionally, which meant a Defensia scanner rule firing beside a CRS SQLi rule would have reported `scanner_detected`. They are now ranked by their own attack class, with an exact-ID match only breaking ties within the same class.

## v1.4.76
- **fix: ModSecurity audit-log events were misclassified** — CRS reuses one tag for opposite meanings (`attack-protocol` covers both 920xxx protocol enforcement and 921xxx attacks), and classification took the *first* `attack-` tag in rule order. CRS phase-1 protocol rules log before phase-2 detection rules, so protocol noise shadowed the real finding.
- Classification now keys off the CRS rule-ID family with a priority rank, so the most severe real finding in an entry always wins. Meta rules (949xxx/980xxx) can never classify.
- **This was hiding real attacks, not just inflating counters:** 1,224 events tagged `attack-protocol` carried a genuine attack rule — 1,016 LFI never counted as `path_traversal`, plus PHP injection, RCE, SQLi and request smuggling. Defensia's own inline rules (9910xxx) carry no tags and were all collapsing into `modsecurity_block`, including 1,161 web shell detections.
- Enforcement families (910/911/920/922) are capped at `info` severity. CRS ships 911100 "method not allowed" at CRITICAL, so malformed Host headers were raising critical alerts.
- Plain `GET /` requests no longer land in `web_exploit`: they were 52,477 of 65,669 events in that bucket.

## v1.4.51
- **fix: false positive CORE_FILE_MODIFIED on wp-includes/version.php** — this file changes on every WordPress update and is not a useful injection target. Now excluded from core file integrity checks.

## v1.4.50
- **fix: false positive PHP in uploads** — standard anti-directory-listing `index.php` files (< 120 bytes, "Silence is golden") in `wp-content/uploads/` subdirectories are now skipped by the framework checker. Affects plugins like Astra, Elementor, MainWP, iThemes Security.

## v1.4.49
- **feat: cancel malware scan from dashboard** — new WebSocket event `malware_scan.cancelled` stops the scan between root iterations. Reports partial results before exiting.

## v1.4.48
- **fix: MariaDB deprecation warning causing false positive malware findings** — `CombinedOutput()` mixed stderr warnings ("Deprecated program name") into query results, triggering `WP_DB_INJECTED_POST`, `WP_DB_INJECTED_OPTION`, and `WP_DB_ROGUE_ADMIN` on every WordPress site using MariaDB. Now uses `Output()` (stdout only) and filters any remaining warning lines.
- **fix: false positive HEURISTIC_RECENT_PHP on plugin index.php files** — standard anti-directory-listing files (`<?php // Silence is golden`) in plugin asset directories are now skipped.

## v1.4.47
- **fix: custom scan paths ending in `/` were silently ignored** — a trailing separator makes `filepath.Glob` return zero matches *and* a nil error, so a path like `/home/*/web/*/public_html/` never got scanned and never reported an error. Patterns are now trimmed before matching, and blank entries are skipped instead of resolving to `.` or `/` (which made the scanner walk the whole filesystem).
- **HestiaCP / VestaCP support** — `/home/*/web/*/public_html` is now detected automatically, no custom path needed. The vhost directory is the domain, so each web root is reported with its domain.
- **fix: stop tailing bandwidth accounting logs** — HestiaCP/VestaCP write a second `CustomLog <domain>.bytes` per vhost holding byte counters, not HTTP requests. These are now skipped, removing roughly 40% of watched log sources on those servers.

## v1.4.25
- **fix: iptables rule ordering** — geo DROP rules now use -A (append) instead of -I (insert first), ensuring ACCEPT rules for panel IP and whitelisted IPs always take precedence

## v1.4.24
- **fix: geoblocking never blocks panel IP** — resolves Defensia panel URL to IP and inserts iptables ACCEPT rule before any geo DROP rules. Also protects all whitelisted IPs from geoblocking.

## v1.4.23
- **fix: WAF disable toggle** — empty `enabled_types` array from panel now correctly disables WAF detection (previously treated as "use all defaults")

## v1.4.22
- **ipset for ALL bans** — BanIP/UnbanIP use `defensia-bans` hash:ip set (65K capacity)
- Eliminates iptables "Memory allocation problem" — from 1,200+ rules to 3
- Batch `ipset restore` for ApplyBans (sub-second for 1,000+ IPs)
- CleanupStaleBans works with ipset members

## v1.4.21
- **Proactive country geoblocking** — ipset hash:net with full CIDR ranges from MaxMind mmdb
- Blocks ALL traffic from a country at kernel level (not reactive per-IP anymore)
- One ipset set per country, batch-loaded via `ipset restore` (sub-second)
- CIDR extraction cached after first call per country
- IPv4 only filter (ipset hash:net doesn't support IPv6)
- Graceful fallback to reactive blocking if ipset not installed
- Added `firewall.Init()`, `FirewallStatus()`, ipset detection

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
