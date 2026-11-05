# CSF Test Lab

Phase 14's deliverable: a local OrbStack lab that tests every CSF-related
change (phases 15-21) against **real CSF forks running on real Linux VMs**
before anything ever touches a customer server. This is the testing gate
Ricard asked for ("mucho testing, no avanzamos si no hay testing. Todo que dé
bien.") — no CSF-work phase advances without `make lab-up && make lab-test`
green, `go test -race ./...` green, CI green, and `php artisan test` green.

## 1. Purpose

CSF/LFD need systemd, real iptables/ipset and cron — they cannot be
meaningfully tested in a plain Docker container (Docker is used only as a
CI/local fallback, see §9 and `lab/ci/`). The lab provisions 7 CSF-adjacent
OrbStack Linux VMs plus one attacker VM, installs a pinned, hash-verified
CSF fork (or none) on each, wires a real `defensia-agent` binary built from
this worktree into each one, points them at a local, fully-isolated panel,
and runs a Go integration suite against all of them. The output is a
committed markdown report under `lab/reports/` — the evidence phases 15-21's
own verifiers require before any CSF-behaviour change is accepted.

## 2. Requirements

- **macOS on Apple Silicon (arm64)** with **OrbStack** installed and
  running. If `orbctl list` fails or hangs, OrbStack is probably stopped —
  run `orb start` and retry. Every lab script checks this (`preflight_orb`
  in `lib.sh`) and fails with a clear message if OrbStack is down; it never
  silently hangs.
- **Go** at the version in `go.mod` (the agent binary and the integration
  test binary are both built from this worktree, never installed via
  `install.sh`, and never from `~/sites/defensia-agent-phase14`'s own stale
  binary — see the project's `agent-repo-workflow` convention).
- **Docker** (OrbStack ships its own Docker engine) — used for the CI
  container fallback (`lab/ci/run-csf-container.sh`) and for the local lab
  panel (`docker-compose.lab.yml` in the panel worktree).
- **The panel checked out as a worktree**, by default at
  `~/sites/defensia-phase14-panel` (`PANEL_DIR` env var to override), on a
  phase branch created from `origin/main`:
  ```
  git worktree add ../defensia-phase14-panel -b gsd/phase-14-csf-lab-panel origin/main
  ```
  then `composer install` inside it — `vendor/` is not in git and the
  Dockerfile does not install it for you. Any other panel checkout works via
  `DEFENSIA_PANEL_DIR`. See `lab/panel/panel-up.sh`.
- **Disk**: goldens are full VM clones, roughly **~1 GB each** (8 VMs ⇒
  budget ~8-10 GB for the matrix alone, more headroom for Docker images/Go
  build cache). Keep at least 8 GB free on the volume OrbStack uses
  (`df -h /System/Volumes/Data` on a typical Mac layout); stop and
  investigate below that, don't push through it.
- **First-run time**: a fully cold `make lab-up` (no goldens, no panel, no
  agent binaries built) was measured at ~9 minutes in plan 04's initial
  bring-up and re-measured end-to-end in plan 10's clean-slate run (see that
  plan's SUMMARY/evidence report for the exact wall-clock on this machine on
  this date) — expect roughly 10-25 minutes depending on OrbStack image
  pull/cache state and host load.

## 3. Commands

| Command | What it does |
|---|---|
| `make lab-up` | Creates/starts all 8 lab VMs (building golden clones first run only), builds+installs the agent, brings up and bootstraps the local lab panel. Idempotent — a second run is a fast no-op. |
| `make lab-verify` | Health gate: OrbStack up, panel up+safe, every CSF VM's `csf -v`/`lfd`/`TESTING` matches `lab/matrix.sh`, every agent active+heartbeating. Non-zero exit if the lab itself is broken — run this before blaming a test failure on your code. |
| `make lab-test` | Runs the Go integration suite (`test/integration`, build tag `integration`) inside every agent VM as root, plus the attack stage (`attack(ssh,web,mail)`), and writes `lab/reports/<timestamp>.md`. Gates on `lab-verify` first. |
| `make lab-reset` | Restores every VM from its golden clone (fast: clone + boot, not a full reprovision) and re-registers its agent. `LAB_VMS="vm1 vm2"` to restrict to specific VMs. |
| `make lab-down` | Deletes the working VMs (not the goldens, not the panel) by default. `LAB_DOWN_ARGS="--all --panel"` additionally deletes the 8 goldens and tears down the lab panel compose project + its MySQL volume — this is the destructive, full clean-slate reset. |
| `make lab-attack TARGET=debian12-nocsf LEG=all` | Sends real SSH/WordPress/IMAP brute-force traffic from `lab-attacker` against `TARGET` (`LEG` ∈ `prepare\|ssh\|web\|mail\|all`). |
| `make lab-build` | Cross-compiles the agent binary and the integration test binary for the lab's arch (`LAB_ARCH`, derived from the host). |
| `LAB_VMS="vm1 vm2"` | Restricts almost any `lab-*` target to a subset of VMs (space-separated, matching `lab/matrix.sh` names). |
| `LAB_FORCE_FAIL=1 make lab-test` | Self-test: forces `TestLabHarnessForcedFailure` to fail on every VM, proving the gate can actually go red (not a tautology). Never leave this set for a real run. |
| `LAB_SKIP_ATTACK=1 make lab-test` | Skips the attack stage (saves ~3 min) for a quick CSF-only run. |
| `lab/up.sh --rebuild-golden <vm>` | Forces a from-scratch golden rebuild for one VM (e.g. after a `lab/provision/*.sh` change), instead of reusing the existing golden. |
| `lab/capture-fixtures.sh [--no-reset] [vm...]` | Re-captures the real `/etc/csf/*` fixture files under `internal/firewall/testdata/<fork>/` from the live VMs (used by plan 07's fixture-driven unit tests, not part of the day-to-day gate). |

## 4. Matrix

| VM | distro | fork (`forks.lock` id) | `csf -v` reports | `TESTING` | `lfd` | ipset | fw mode |
|---|---|---|---|---|---|---|---|
| `alma9-csf-orig` | AlmaLinux 9 | `original-15.00` | `v15.00 (generic)` | `0` | active | yes | ipset |
| `alma9-csf-aetherinox` | AlmaLinux 9 | `aetherinox-15.10` | `v15.10 (generic)` (multi-line banner) | `0` | active | yes | ipset |
| `debian12-csf-sentinel` | Debian 12 (bookworm) | `sentinel-15.13` | `v15.11 (generic)` (release 15.13, reports 15.11 — see Known gaps) | `0` | active | yes | ipset |
| `alma9-csf-da` | AlmaLinux 9 | `directadmin-15.12` | `v15.12 (DirectAdmin)` | `0` | active | yes | ipset |
| `alma8-csf-cwp-orphan` | AlmaLinux 8 | `original-15.00` (configured as an abandoned CWP install) | `v15.00 (generic)` + `*WARNING* TESTING mode is enabled` | `1` | **inactive** | yes | ipset |
| `alma10-noipset` | AlmaLinux 10 | `original-15.00` | `v15.00 (generic)` | `0` | active | **no** | **iptables** |
| `debian12-nocsf` | Debian 12 (bookworm) | none (control) | n/a | n/a | n/a | yes | n/a — also the fixed attack target |
| `lab-attacker` | AlmaLinux 9 | none | n/a | n/a | n/a | no | n/a — no agent, sends attack traffic only |

`alma10-noipset` exists for Phase 17 (iptables-only fallback). cPanel and
licensed DirectAdmin are deliberately absent from this matrix (see §8).

## 5. Architecture

- **Goldens + `orbctl clone`**: each VM has a `<vm>-golden` counterpart,
  fully provisioned once. `make lab-up`/`make lab-reset` clone from the
  golden rather than re-running the full provisioning chain, so a reset is
  seconds, not minutes. `lab/up.sh --rebuild-golden` forces a from-scratch
  golden rebuild when a provisioning script changes.
- **Panel**: a standalone Docker Compose project (`defensia-lab`, in the
  panel worktree's `docker-compose.lab.yml`) on host port **:5565**, with
  its own MySQL volume, fully isolated from the dev stack (`defensia-app-1`/
  `defensia-db-1` on :5555) and from production. Reached from inside the
  OrbStack VMs as `http://host.orb.internal:5565`. `php artisan lab:bootstrap`
  idempotently seeds a lab org/user/license override/API token and issues
  install tokens; `docker/lab/env-audit.php` proves no outbound-service
  secret ever leaks into the lab container's env.
- **Agent**: built from this worktree (`make lab-build`), cross-compiled for
  the VMs' arch, pushed via OrbStack's passthrough file copy (`orbctl push`
  fails with "unknown user" against a fresh VM before the agent's own user
  exists — `vm_push` in `lib.sh` works around this), installed, registered
  against the lab panel, and run as a systemd service. Never installed via
  `install.sh` — that script is for real customers.
- **Test binary**: the `test/integration` package (build tag `integration`,
  invisible to a normal `go test ./...`) is cross-compiled once by
  `lab-build`, pushed into every `LAB_AGENT_VMS` VM, and run as root with
  `-test.run '^TestLab'` (or `^TestAttack` for the attack stage). Running
  inside the VM (not over SSH from the Mac) is what lets the tests read
  `/etc/csf/*`, check `systemctl is-active`, and query `ipset`.
- **Reports**: `lab/test.sh` writes `lab/reports/<YYYY-MM-DD-HHMM>.md` — a
  table of VM × suite × pass/fail/skip/seconds, plus `agent`/`panel`
  worktree shas (bare, or `-dirty`-suffixed if uncommitted changes exist at
  generation time), the `forks.lock` sha256, and the OrbStack version. These
  **are committed** (they are the evidence future phases' verifiers check
  for). Raw per-run logs under `lab/reports/raw/` are gitignored — only the
  summary table is kept in git.

## 6. Adding a fork

1. Add a line to `lab/forks.lock` (`id|kind|url|sha256|pin` — tgz: sha256 of
   the downloaded artifact; git: exact commit sha, sha256 field `-`). Never
   point at `download.configserver.com` — ConfigServer stopped distributing
   CSF on 2025-08-31 and that domain is at risk of take-over squatting; use
   a public GitHub mirror/release/fork instead.
2. Add the new VM to every case table in `lab/matrix.sh` (`vm_distro`,
   `vm_family`, `vm_fork`, `vm_role`, `vm_testing`, `vm_lfd`, `vm_ipset`,
   `vm_csfv_regex`, `vm_csf_version`, `vm_fw_mode`, `vm_has_agent`) and to
   `LAB_VMS`/`LAB_AGENT_VMS`/`LAB_CSF_VMS` as appropriate.
3. `make lab-up LAB_VMS=<new-vm>` to provision just that VM.
4. `lab/capture-fixtures.sh <new-vm>` to capture its real `/etc/csf/*`
   artefacts into `internal/firewall/testdata/<fork>/`, then hand-write that
   directory's `expected.json` (see
   `internal/firewall/testdata/README.md` for the schema — `expected.json`
   is never auto-derived from a single capture run).
5. Extend `csf_fixtures_test.go` and, if the new fork changes lab-wide
   expectations (e.g. a new `fw_mode`), `test/integration/lab_csf_test.go`.

## 7. Safety rules

- **Never `download.configserver.com`** anywhere in a script, fork pin, or
  VM config — an orphaned/misconfigured VM pointing there is specifically
  one of the lab's own test fixtures (`alma8-csf-cwp-orphan`), never a real
  outbound call. Lab VMs never actually reach that host.
- **No production tokens, binaries, mirrors, or database** — ever. Agents
  register only against the local, fully-isolated lab panel
  (`host.orb.internal:5565`) using lab-only install tokens from
  `lab:bootstrap`.
- **`MAIL_MAILER=log`** is enforced and hard-gated by `panel-up.sh`/
  `verify.sh` — the lab panel can never send a real email.
- **`latest_agent_version` is asserted empty** — the lab panel must never
  advertise an update, which would make a real agent elsewhere try to
  self-update from lab state.
- **Attacker traffic uses TEST-NET-3 (`203.0.113.0/24`, RFC 5737)**
  source IPs exclusively — never a real/routable address.
- **No `release.sh`/`deploy.sh`** is ever run from the lab or by any lab
  script.

## 8. Known gaps / findings for later phases

- **Vite build is required for a green `php artisan test` in the panel
  worktree.** `public/build` is gitignored; a fresh worktree or a rebase has
  no `manifest.json`, which makes **117 tests fail** with
  `ViteManifestNotFoundException` — not a real regression. Run
  `npm ci && npm run build` (~15s on this host) before trusting a red
  `php artisan test` run in any panel worktree. The lab panel itself is only
  ever exercised through `/up` and the JSON API (no browser E2E in phase
  14), so the lab panel's own compose project does not need the frontend
  build — only the worktree's own `php artisan test` run does.
- **Midnight-UTC flaky test, not lab-related.**
  `Tests\Feature\EventResolutionTest::test_a_resolved_finding_is_not_counted_as_a_critical_on_the_dashboard`
  fails deterministically between **00:00 and 00:30 UTC** (app timezone is
  UTC; the test creates an event at `now()->subMinutes(30)` while the
  controller counts from `today()`). Check `date -u` before concluding a red
  `php artisan test` run is a real failure in that window.
- **Debian 12 dovecot login lines don't match the agent's mail regexes out
  of the box.** The stock `imap-login`/PAM log line shape is not what the
  agent's mail watcher matches; the lab's attack target
  (`lab/provision/target-services.sh`) configures dovecot with a
  passwd-file passdb + `auth_verbose=yes` specifically so a failed login
  writes the `Password mismatch` line shape the watcher's regex actually
  matches. A real customer dovecot install may need the same consideration
  if its auth backend differs.
- **`sync.Once` in `HasCSF`** — noted during plan 01/03 as a seam worth
  revisiting if a future plan needs per-call (not per-process) CSF
  detection; not touched in phase 14.
- **Runner ipset result (plan 09)**: GitHub's `ubuntu-latest` runner already
  has `ip_set`/`xt_set`/`nfnetlink` loaded, and `ipset create/destroy`
  succeeds inside the CI container with no extra `modprobe`. Not yet
  promoted from a non-blocking diagnostic to a hard-gated CI assertion
  (`LAB_EXPECT_FW_MODE` stays empty in `ci.yml`) — a candidate for a future
  plan now that this is confirmed working.
- **DirectAdmin stub decision (plan 03)**: `alma9-csf-da` uses the
  `poralix/da-csf` fork (DirectAdmin-*compatible*, GPL), not a real licensed
  DirectAdmin install — licensed DirectAdmin and cPanel are out of scope for
  this lab and are validated later on real test servers in a separate phase.
- **Shared-IP heartbeat rate-limiter contention (plans 05/06/08) — FIXED
  upstream, confirmed in plan 10.** All 7 agent VMs' panel traffic arrives at
  the lab panel's Apache container under one shared `REMOTE_ADDR`
  (OrbStack/Docker NAT); the `agent-heartbeat` (and sibling `agent-*`) rate
  limiters used to fall back to per-IP keying instead of per-agent-id,
  collapsing 7 independent budgets into one (see `deferred-items.md` and the
  threat flag in `14-05-SUMMARY.md`). The panel's `fix/agent-rate-limit-keyed-per-agent`
  PR (merged to `origin/main` before plan 10) keys the limiter on
  `sha1($request->bearerToken())` with an IP fallback instead. Plan 10's
  clean-slate run rebased the panel worktree onto that fix and confirmed, via
  the lab panel's own access/app logs, **zero 429s** across a full cold
  `make lab-up` + `make lab-test` run — `lab/verify.sh`'s 180s heartbeat
  tolerance is still a sensible safety margin, but is no longer load-bearing
  against this specific contention.
- **A single `/api/v1/servers` snapshot in `verify.sh` can race a concurrent
  heartbeat write (plan 10).** Live evidence on 2026-11-05: an agent
  heartbeated every ~60s with 200 OK and zero errors throughout the
  surrounding window, yet one `verify.sh` run still saw an empty
  `last_seen_at` for that exact agent in its one-shot GET. `verify.sh` now
  retries the lookup once (re-fetch + re-check after a 3s pause) before
  failing — a gate-robustness fix, not a product change. If this still
  shows up after the retry, treat it as a real finding, not a flake.
- **The lab's single shared Sanctum `lab` token does not survive being
  rotated — by anything.** Every `lab:bootstrap` call (direct, or via any
  `verify.sh`/`panel-up.sh` run) unconditionally revokes and reissues that
  one token server-side (`LabBootstrap.php`: `tokens()->where('name',
  'lab')->delete()` then `createToken('lab')`). Two consequences, both
  observed live on 2026-11-05:
  - `make lab-down LAB_DOWN_ARGS="--all --panel"` drops the panel's whole
    MySQL volume — any token value cached anywhere outside the lab's own
    `$STATE_DIR/panel.json` (a shell variable, a note, a browser tab) is
    gone for good; only `lab-up`'s own `panel-up.sh` → `lab:bootstrap` call
    can mint a valid one again. Never hand-carry a token across a
    `--all --panel` reset.
  - **Known design limitation, not a fixed bug: two concurrent lab
    operations are mutually destructive.** `lab/test.sh` captures the token
    once near the top of its own run; `attack.sh`'s traffic-generation
    phase takes real wall-clock time, and ANY other `lab:bootstrap` call in
    that window (direct, or via a concurrently-run `make lab-verify`/
    `make lab-test` from a second terminal/session) invalidates the
    captured token mid-run, producing a `401 Unauthenticated` on
    `TestAttackEventsReachPanel` that has nothing to do with the attack
    traffic itself (`2026-11-05-1434.md`; the observed trigger that day was
    a second, independent `make lab-verify`/`make lab-test` run executed by
    another session verifying the lab concurrently — not a defect in the
    attack traffic or the harness's own sequential logic). `lab/test.sh`
    now re-reads the token immediately before the attack-stage run instead
    of reusing the one captured minutes earlier, which **narrows the
    window but does not cure the design**: the lab still has exactly one
    shared Sanctum token, and any two lab operations running at the same
    time can still race each other out from under themselves. **Phases
    15-21 should treat "never run two lab-* commands concurrently" as a
    hard operating rule, not a suggestion** — with multiple agents
    potentially driving the same lab, this will bite harder than it did
    here. The real fix is structural (out of scope for this plan): either
    a token per caller/purpose instead of one named `lab` token for
    everything, or a `lab:bootstrap` mode that mints an additional token
    without revoking ones already in use.
  - A failure report must never ship with an empty diagnostic section
    (`2026-11-05-1447.md` did, before this fix): `lab/test.sh`'s
    `## Failures` block now falls back to the raw log's own tail when the
    failure has no Go-test `--- FAIL` marker to extract context around
    (e.g. `attack.sh` dying before the test binary ever runs).
