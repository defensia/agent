#!/usr/bin/env bash
# lab/lib.sh — shared helpers for the Phase 14 CSF test lab.
# Sourced by lab/*.sh and lab/provision/*.sh driver scripts. bash 3.2 safe
# (macOS ships bash 3.2): no associative arrays, no file-into-array
# builtins, no lowercase-parameter expansion operators.
set -euo pipefail

# --- Paths -------------------------------------------------------------
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
STATE_DIR="$LAB_DIR/.state"
CACHE_DIR="$LAB_DIR/cache"

# The clean panel worktree from origin/main created by plan 14-02 — never
# the dirty local checkout ~/sites/defensia.
PANEL_DIR="${DEFENSIA_PANEL_DIR:-$HOME/sites/defensia-phase14-panel}"
PANEL_PORT=5565
PANEL_URL_HOST="http://localhost:5565"
PANEL_URL_VM="http://host.orb.internal:5565"

case "$(uname -m)" in
  arm64|aarch64) LAB_ARCH="arm64" ;;
  x86_64|amd64)  LAB_ARCH="amd64" ;;
  *)             LAB_ARCH="$(uname -m)" ;;
esac

# --- Logging -------------------------------------------------------------
log() { printf '[lab] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit "${2:-1}"; }

# --- Hashing (macOS vs Linux/CI) -----------------------------------------
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

# --- OrbStack preflight ---------------------------------------------------
preflight_orb() {
  command -v orbctl >/dev/null 2>&1 || die "OrbStack no instalado (orbctl no encontrado)" 2
  orbctl status 2>&1 | grep -qi running || die "OrbStack parado: arranca OrbStack con: orb start" 2
}

# --- VM helpers -------------------------------------------------------------
vm_exists() { orbctl info "$1" >/dev/null 2>&1; }

vm_root() {
  local vm=$1
  shift
  orb -m "$vm" -u root "$@"
}

# Copy a file or directory into a VM.
#
# `orbctl push -m VM src dest` requires a Linux user matching the macOS
# username to already exist inside the VM; on a freshly created machine
# in this environment that account is not guaranteed to exist yet
# ("[-32098] lookup user: unknown user <name>", observed empirically on
# a fresh alma:9 machine whose `orbctl info` record stayed stuck at
# state "provisioning" even though systemd itself was fully booted and
# usable via `vm_root`). Non-isolated OrbStack machines (the lab default
# — nothing in lab/ sets --isolated) bind-mount the ENTIRE host root
# filesystem into the VM at identical absolute paths (verified: reading
# a file from inside the VM at its macOS path returns the same bytes),
# so the most reliable "push" is simply a root-owned `cp -a` from that
# passthrough path — it needs no OrbStack-side user bookkeeping at all.
# Fall back to `orbctl push` only if the passthrough path is not visible
# inside the VM (e.g. a future --isolated machine).
vm_push() {
  local vm=$1 src=$2 dest=${3:-} abs_src
  if [ -d "$src" ]; then
    abs_src="$(cd "$src" && pwd)"
  else
    abs_src="$(cd "$(dirname "$src")" && pwd)/$(basename "$src")"
  fi
  dest="${dest:-/root/$(basename "$src")}"
  if vm_root "$vm" test -e "$abs_src" >/dev/null 2>&1; then
    if [ -d "$src" ]; then
      vm_root "$vm" bash -c "mkdir -p '$dest' && cp -a '$abs_src'/. '$dest'/"
    else
      vm_root "$vm" bash -c "mkdir -p \"\$(dirname '$dest')\" && cp -a '$abs_src' '$dest'"
    fi
  else
    orbctl push -m "$vm" "$src" "$dest"
  fi
}

# Push a directory to a VM. Same strategy as vm_push (host-filesystem
# passthrough first, orbctl push fallback) — kept as a distinct name for
# call-site clarity when the source is known to be a directory.
vm_push_dir() { vm_push "$@"; }

# wait_vm_ready VM [timeout=180]
wait_vm_ready() {
  local vm=$1 timeout=${2:-180} waited=0 state
  while [ "$waited" -lt "$timeout" ]; do
    state="$(vm_root "$vm" systemctl is-system-running 2>/dev/null || true)"
    case "$state" in
      running|degraded) return 0 ;;
    esac
    sleep 2
    waited=$((waited + 2))
  done
  die "VM $vm not ready after ${timeout}s (systemctl is-system-running never reported running/degraded)"
}

# vm_ip VM — IPv4 only (OrbStack VM-to-VM hostnames resolve over IPv6).
vm_ip() {
  vm_root "$1" ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -1
}

# --- Panel helpers -------------------------------------------------------
panel_compose() {
  docker compose -f "$PANEL_DIR/docker-compose.lab.yml" "$@"
}

# panel_bootstrap ARGS... — runs `php artisan lab:bootstrap "$@"` inside the
# lab panel container, writes the single JSON output line to
# $STATE_DIR/panel.json (each call rotates the 'lab' Sanctum token, so the
# state file always reflects the latest) and echoes it.
panel_bootstrap() {
  mkdir -p "$STATE_DIR"
  local out
  out="$(panel_compose exec -T app php artisan lab:bootstrap "$@" | tail -1)"
  printf '%s\n' "$out" >"$STATE_DIR/panel.json"
  printf '%s\n' "$out"
}

# panel_api_token — the current lab Sanctum token from $STATE_DIR/panel.json.
panel_api_token() { json_get "$STATE_DIR/panel.json" api_token; }

# ensure_active_protection VM — flips the agent's monitor_mode off via a
# direct DB update (same effect as toggling "Active Protection" on in the
# panel UI for that server). New agents register with monitor_mode=true
# by design (AgentService::register, app/Services/AgentService.php) — a
# brand new install defaults to detect-only so nobody gets locked out of
# their own box the moment the agent starts. `make lab-reset` re-registers
# every agent from scratch, so every caller that needs real ban
# enforcement (not just a `brute_force`/monitor-mode event) must call this
# first: with monitor_mode left on, syncAndApply's own
# `if !sync.Config.MonitorMode { firewall.ApplyBans(...) }` guard skips
# every ban regardless of backend. Idempotent (no-op once already false);
# shared by lab/attack.sh, lab/diagnose-firewall.sh and lab/test.sh so the
# three callers can never drift into three different DB update strings.
ensure_active_protection() {
  local vm=$1
  panel_compose exec -T app php artisan tinker --execute="
    \$a = \App\Models\Agent::where('name', '$vm')->first();
    if (!\$a) { echo 'ERROR: no agent named $vm'; exit(1); }
    if (\$a->monitor_mode) { \$a->update(['monitor_mode' => false]); echo 'toggled-off'; } else { echo 'already-off'; }
  " 2>&1 | tail -1
}

# panel_get PATH — authenticated GET against the lab panel (host-side URL).
panel_get() {
  curl -fsS -H "Authorization: Bearer $(panel_api_token)" -H 'Accept: application/json' "$PANEL_URL_HOST$1"
}

# panel_post PATH JSON — authenticated POST. Does NOT use curl -f: an
# error body (e.g. a 422 "not eligible" ban rejection) must stay visible
# to the caller, not be swallowed as a bare non-zero exit. Splits the
# response body from the trailing HTTP status via a single curl -w call
# and returns non-zero (after printing the body) on >= 400.
panel_post() {
  local path=$1 json=$2 out body code
  out="$(curl -sS -X POST \
    -H "Authorization: Bearer $(panel_api_token)" \
    -H 'Accept: application/json' -H 'Content-Type: application/json' \
    -d "$json" -w '\n%{http_code}' "$PANEL_URL_HOST$path")"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  printf '%s' "$body"
  if [ "$code" -ge 400 ] 2>/dev/null; then
    printf '\n[panel_post] %s %s -> HTTP %s\n' "$path" "$json" "$code" >&2
    return 1
  fi
}

# panel_delete PATH — authenticated DELETE, same body-visible contract as panel_post.
panel_delete() {
  local path=$1 out body code
  out="$(curl -sS -X DELETE \
    -H "Authorization: Bearer $(panel_api_token)" \
    -H 'Accept: application/json' \
    -w '\n%{http_code}' "$PANEL_URL_HOST$path")"
  code="${out##*$'\n'}"
  body="${out%$'\n'*}"
  printf '%s' "$body"
  if [ "$code" -ge 400 ] 2>/dev/null; then
    printf '\n[panel_delete] %s -> HTTP %s\n' "$path" "$code" >&2
    return 1
  fi
}

# panel_tinker PHP — runs `php artisan tinker --execute="$1"` inside the lab
# panel container. Refuses unless the bootstrapped panel.json confirms the
# lab DB (defensia_lab) — this executes arbitrary PHP against whatever
# database the container is pointed at, so a wrong/production DB must
# never be in reach by accident.
panel_tinker() {
  local php=$1 db
  db="$(json_get "$STATE_DIR/panel.json" db_database 2>/dev/null || true)"
  [ "$db" = "defensia_lab" ] || die "panel_tinker refused: panel.json db_database='$db' (expected defensia_lab)"
  panel_compose exec -T app php artisan tinker --execute="$php"
}

# --- JSON ------------------------------------------------------------------
# json_get FILE KEY — dotted path (a.b.0.c; numeric segments index lists).
json_get() {
  local file=$1 key=$2
  python3 - "$file" "$key" <<'PYEOF'
import json
import sys

file_path, key = sys.argv[1], sys.argv[2]
with open(file_path) as f:
    data = json.load(f)

cur = data
for seg in key.split('.'):
    if cur is None:
        break
    if isinstance(cur, list):
        try:
            idx = int(seg)
        except ValueError:
            cur = None
            break
        cur = cur[idx] if 0 <= idx < len(cur) else None
    elif isinstance(cur, dict):
        cur = cur.get(seg)
    else:
        cur = None
        break

print("" if cur is None else cur)
PYEOF
}

# --- forks.lock ------------------------------------------------------------
# forks_field ID FIELDNUM — field 1=id 2=kind 3=url 4=sha256 5=pin
forks_field() {
  awk -F'|' -v id="$1" -v f="$2" '$1==id{print $f}' "$LAB_DIR/forks.lock"
}

# --- Agent install/register (plan 05, LAB-02) -------------------------------

# config_agent_id VM — reads agent_id back out of the VM's
# /etc/defensia/config.json. `defensia-agent register` pretty-prints the
# config (`"agent_id": 1`, with a space after the colon), so the extraction
# must not assume a bare "key":value with no space.
config_agent_id() {
  vm_root "$1" grep -oE '"agent_id": *[0-9]+' /etc/defensia/config.json 2>/dev/null \
    | grep -oE '[0-9]+$' | head -1 || true
}

# install_agent VM — idempotent agent install+register against the lab
# panel. No-op for VMs without an agent (lab-attacker, vm_has_agent=no).
# Callers must have sourced lab/matrix.sh (vm_has_agent/vm_ip) in addition
# to this file.
#
# Skips re-registration when the agent is already active, has an
# /etc/defensia/config.json with an agent_id, and that agent_id is present
# in the panel's /api/v1/servers list — but still reinstalls (and restarts,
# never re-registers) the binary when its sha256 differs from the locally
# built one, so `make lab-up`/`make lab-reset` after a code change ships
# the new build without spending a fresh install token.
install_agent() {
  local vm=$1
  [ "$(vm_has_agent "$vm")" = "yes" ] || return 0

  local binary="$REPO_DIR/build/defensia-agent-linux-$LAB_ARCH"
  [ -f "$binary" ] || die "agent binary missing: $binary (run 'make lab-build' first)"
  local local_sha
  local_sha="$(sha256_of "$binary")"

  local agent_id=""
  if vm_root "$vm" systemctl is-active defensia-agent >/dev/null 2>&1 \
    && vm_root "$vm" test -s /etc/defensia/config.json >/dev/null 2>&1; then
    agent_id="$(config_agent_id "$vm")"
  fi

  if [ -n "$agent_id" ]; then
    local ids registered=0 remote_sha
    ids="$(panel_get /api/v1/servers 2>/dev/null | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    print(" ".join(str(a["id"]) for a in d["data"]))
except Exception:
    print("")
' || true)"
    case " $ids " in
      *" $agent_id "*) registered=1 ;;
    esac

    if [ "$registered" -eq 1 ]; then
      remote_sha="$(vm_root "$vm" sha256sum /usr/local/bin/defensia-agent 2>/dev/null | awk '{print $1}' || true)"
      if [ "$remote_sha" != "$local_sha" ]; then
        log "$vm: agent binary changed (local=$local_sha remote=${remote_sha:-missing}) - reinstalling, not re-registering"
        vm_push "$vm" "$binary" /root/defensia-agent
        vm_root "$vm" install -m0755 /root/defensia-agent /usr/local/bin/defensia-agent
        vm_root "$vm" systemctl restart defensia-agent
      else
        log "$vm: agent ok (id=$agent_id)"
      fi
      return 0
    fi
  fi

  log "$vm: (re)registering agent against the lab panel"
  panel_bootstrap --forget-agent="$vm" --install-tokens=1 >/dev/null
  local token ip
  token="$(json_get "$STATE_DIR/panel.json" install_tokens.0)"
  [ -n "$token" ] || die "$vm: lab:bootstrap returned no install token"
  ip="$(vm_ip "$vm")"

  vm_push "$vm" "$binary" /root/defensia-agent
  vm_push "$vm" "$REPO_DIR/defensia-agent.service" /root/defensia-agent.service
  vm_push "$vm" "$LAB_DIR/provision/agent.sh" /root/lab-provision/agent.sh

  vm_root "$vm" bash /root/lab-provision/agent.sh "$PANEL_URL_VM" "$vm" "$token" "$ip"

  agent_id="$(config_agent_id "$vm")"
  [ -n "$agent_id" ] || die "$vm: agent.sh completed but agent_id could not be read back from /etc/defensia/config.json"

  mkdir -p "$STATE_DIR/agents"
  printf '{"vm":"%s","agent_id":%s}\n' "$vm" "$agent_id" >"$STATE_DIR/agents/$vm.json"
  log "$vm: agent registered (id=$agent_id)"
}
