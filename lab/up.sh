#!/usr/bin/env bash
# lab/up.sh [--rebuild-golden] [vm...]
#
# Idempotent VM lifecycle for the Phase 14 CSF test lab:
#   1. build (or reuse) a stopped "<vm>-golden" machine per VM — provisioned
#      once with base packages + the VM's CSF fork (or attacker tooling),
#      then stopped so cloning it is instant (orbctl clone ~0.2s);
#   2. clone+start the working "<vm>" machine from its golden.
#
# Default VMs: $LAB_VMS (lab/matrix.sh) — the 8 fixed lab machines.
# --rebuild-golden forces a from-scratch rebuild of every requested golden
# (and its working VM) instead of reusing a cached one.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

rebuild_golden=0
vms=""
for arg in "$@"; do
  case "$arg" in
    --rebuild-golden) rebuild_golden=1 ;;
    *) vms="$vms $arg" ;;
  esac
done
vms="${vms# }"
[ -n "$vms" ] || vms="$LAB_VMS"

preflight_orb
"$LAB_DIR/fetch-forks.sh"

# Plain string, not an array: macOS ships bash 3.2, where "${arr[@]}" on an
# empty array under `set -u` throws "unbound variable" (fixed only in bash
# 4.4+). Word-splitting this unquoted below is intentional (0 or 2 tokens).
memory_opt=""
if [ -n "${LAB_VM_MEMORY:-}" ]; then
  memory_opt="--memory $LAB_VM_MEMORY"
fi

# Disk is the real constraint for the 8-VM matrix (goldens + working VMs),
# not RAM (OrbStack's whole guest shares one dynamic 8 GiB VM). Refuse to
# create more VMs once free space drops below ~8 GiB rather than risk
# filling the disk out from under other running projects on this Mac.
check_disk() {
  local avail_kb avail_gb
  avail_kb="$(df -k /System/Volumes/Data 2>/dev/null | awk 'NR==2{print $4}')"
  [ -n "$avail_kb" ] || return 0
  avail_gb=$((avail_kb / 1024 / 1024))
  if [ "$avail_gb" -lt 8 ]; then
    die "disk free ${avail_gb}GiB < 8GiB safety threshold — stopping before creating more VMs (see critical_environment_facts)"
  fi
}

# post_vm_hook VM — no-op placeholder. Plan 14-05 replaces this with the
# agent install/register step against the lab panel.
post_vm_hook() { :; }

# build_golden VM — create+provision "<vm>-golden" once, then stop it.
build_golden() {
  local vm=$1 g role fork sha
  g="$(vm_golden "$vm")"

  if [ "$rebuild_golden" -eq 1 ]; then
    orbctl delete -f "$g" >/dev/null 2>&1 || true
    orbctl delete -f "$vm" >/dev/null 2>&1 || true
  fi

  if vm_exists "$g"; then
    log "golden $g already exists — reusing (pass --rebuild-golden to force)"
    return 0
  fi

  check_disk
  log "building golden $g ($(vm_distro "$vm"))"
  orbctl create $memory_opt "$(vm_distro "$vm")" "$g"
  wait_vm_ready "$g" 240
  vm_push "$g" "$LAB_DIR/provision" /root/lab-provision

  role="$(vm_role "$vm")"
  fork="$(vm_fork "$vm")"
  case "$role" in
    csf|csf-orphan)
      vm_root "$g" bash /root/lab-provision/base.sh "$(vm_family "$vm")" "$(vm_ipset "$vm")"
      vm_push "$g" "$CACHE_DIR/$fork.tgz" "/root/csf-$fork.tgz"
      if [ "$role" = "csf-orphan" ]; then
        vm_root "$g" bash /root/lab-provision/csf.sh "$fork" --orphan
      else
        vm_root "$g" bash /root/lab-provision/csf.sh "$fork"
      fi
      ;;
    attack-target)
      vm_root "$g" bash /root/lab-provision/base.sh "$(vm_family "$vm")" "$(vm_ipset "$vm")"
      ;;
    attacker)
      vm_root "$g" bash /root/lab-provision/attacker.sh
      ;;
    *)
      die "unknown role '$role' for $vm"
      ;;
  esac

  sha="-"
  if [ "$fork" != "none" ]; then
    sha="$(forks_field "$fork" 4)"
    [ "$sha" != "-" ] || sha="$(forks_field "$fork" 5)"
  fi
  vm_root "$g" bash -c "mkdir -p /var/lib/defensia-lab && printf 'vm=%s fork=%s sha=%s\n' '$vm' '$fork' '$sha' > /var/lib/defensia-lab/golden.txt"

  orbctl stop "$g"
}

# wait_csf_active VM — CSF/lfd units come up ~10s after start; poll up to 60s.
wait_csf_active() {
  local vm=$1 waited=0
  while [ "$waited" -lt 60 ]; do
    if [ "$(vm_root "$vm" systemctl is-active csf 2>/dev/null || true)" = "active" ]; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  die "$vm: csf did not become active within 60s after start"
}

# ensure_vm VM — clone from golden if the working VM doesn't exist yet,
# otherwise just (re)start it. Then wait for readiness (+ CSF if applicable).
ensure_vm() {
  local vm=$1 g
  g="$(vm_golden "$vm")"

  if vm_exists "$vm"; then
    orbctl start "$vm" >/dev/null 2>&1 || true
  else
    check_disk
    orbctl clone "$g" "$vm"
    orbctl start "$vm"
  fi

  wait_vm_ready "$vm" 180

  case "$(vm_role "$vm")" in
    csf|csf-orphan) wait_csf_active "$vm" ;;
  esac
}

start_epoch=$(date +%s)
count=0
for vm in $vms; do
  build_golden "$vm"
  ensure_vm "$vm"
  # --- agent install/register (plan 05) ---
  post_vm_hook "$vm"
  log "UP $vm ip=$(vm_ip "$vm")"
  count=$((count + 1))
done
elapsed=$(( $(date +%s) - start_epoch ))
log "lab-up: $count VMs ready in ${elapsed}s"
