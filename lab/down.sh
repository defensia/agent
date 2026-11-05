#!/usr/bin/env bash
# lab/down.sh [--all] [--panel] [vm...]
#
# Deletes working lab VMs. --all also deletes their "<vm>-golden" machines.
# --panel additionally tears down the lab panel's own compose project
# (defensia-lab) with its volume. Only ever touches machines in $LAB_VMS
# (and their goldens) — never anything else on this OrbStack instance.
# Default VMs: $LAB_VMS.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

all=0
panel=0
vms=""
for arg in "$@"; do
  case "$arg" in
    --all) all=1 ;;
    --panel) panel=1 ;;
    *) vms="$vms $arg" ;;
  esac
done
vms="${vms# }"
[ -n "$vms" ] || vms="$LAB_VMS"

preflight_orb

for vm in $vms; do
  case " $LAB_VMS " in
    *" $vm "*) ;;
    *) die "refusing to delete '$vm': not in \$LAB_VMS" ;;
  esac

  orbctl delete -f "$vm" >/dev/null 2>&1 || true
  log "down: deleted $vm (if it existed)"

  if [ "$all" -eq 1 ]; then
    g="$(vm_golden "$vm")"
    orbctl delete -f "$g" >/dev/null 2>&1 || true
    log "down: deleted golden $g (if it existed)"
  fi
done

if [ "$panel" -eq 1 ]; then
  log "down: stopping lab panel (docker compose -p defensia-lab down -v)"
  panel_compose down -v
fi
