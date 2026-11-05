#!/usr/bin/env bash
# lab/reset.sh [vm...]
#
# Restores lab VM(s) to their golden state: delete the working VM, clone it
# fresh from "<vm>-golden", start it, and wait for readiness (+ CSF/lfd if
# applicable). Dies if the golden is missing ("run make lab-up first").
# Default VMs: $LAB_VMS.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

vms="$*"
[ -n "$vms" ] || vms="$LAB_VMS"

preflight_orb

# post_vm_hook VM — no-op placeholder. Plan 14-05 replaces this with
# re-registration against the lab panel (clone keeps /etc/defensia/config.json
# but the IP/hostname change, so the simplest correct behaviour later is to
# always re-run register here).
post_vm_hook() { :; }

wait_csf_active() {
  local vm=$1 waited=0
  while [ "$waited" -lt 60 ]; do
    if [ "$(vm_root "$vm" systemctl is-active csf 2>/dev/null || true)" = "active" ]; then
      return 0
    fi
    sleep 2
    waited=$((waited + 2))
  done
  die "$vm: csf did not become active within 60s after reset"
}

start_epoch=$(date +%s)
count=0
for vm in $vms; do
  g="$(vm_golden "$vm")"
  vm_exists "$g" || die "golden $g missing for $vm — run 'make lab-up' first"

  orbctl delete -f "$vm" >/dev/null 2>&1 || true
  orbctl clone "$g" "$vm"
  orbctl start "$vm"
  wait_vm_ready "$vm" 180

  case "$(vm_role "$vm")" in
    csf|csf-orphan) wait_csf_active "$vm" ;;
  esac

  post_vm_hook "$vm"
  log "RESET $vm ip=$(vm_ip "$vm")"
  count=$((count + 1))
done

elapsed=$(( $(date +%s) - start_epoch ))
log "lab-reset: $count VMs restored in ${elapsed}s"
