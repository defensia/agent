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

# Copy a single file to a VM. If the source is a directory, fall back to a
# tar-based copy (orbctl push directory support is unverified — see 14-03
# Task 2 action notes).
vm_push() {
  local vm=$1 src=$2 dest=${3:-}
  if [ -d "$src" ]; then
    vm_push_dir "$vm" "$src" "$dest"
  else
    orbctl push -m "$vm" "$src" "$dest"
  fi
}

# Push a directory to a VM via tar (works regardless of whether `orbctl
# push` supports directories natively).
vm_push_dir() {
  local vm=$1 src=$2 dest=${3:-} tmp base
  base="$(basename "$src")"
  dest="${dest:-/root/$base}"
  tmp="$(mktemp "${TMPDIR:-/tmp}/lab-push-XXXXXX").tar.gz"
  tar czf "$tmp" -C "$(dirname "$src")" "$base"
  orbctl push -m "$vm" "$tmp" "/root/$(basename "$tmp")"
  vm_root "$vm" bash -c "mkdir -p '$dest' && tar xzf '/root/$(basename "$tmp")' -C '$dest' --strip-components=1 && rm -f '/root/$(basename "$tmp")'"
  rm -f "$tmp"
}

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
