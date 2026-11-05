#!/usr/bin/env bash
# lab/verify.sh [vm...]
#
# Health gate for the Phase 14 CSF test lab: VM-level (exists, reachable,
# systemd state, has an IPv4) + CSF-level (csf -v matches the fork's
# expected version, csf/lfd active per lab/matrix.sh, TESTING flag,
# panel-allow, orphan downloadservers/sinkhole) + ipset/no-csf/attacker
# tooling expectations. Prints "PASS <vm> <check>" / "FAIL <vm> <check>:
# <reason>" per check and "verify: N checks, F failures" at the end. Exits
# non-zero if any check failed — this must catch a broken lab BEFORE a
# later test blames the agent code for it. Default VMs: $LAB_VMS.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

vms="$*"
[ -n "$vms" ] || vms="$LAB_VMS"

preflight_orb

CHECKS=0
FAILS=0

pass() { CHECKS=$((CHECKS + 1)); printf 'PASS %s %s\n' "$1" "$2"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); printf 'FAIL %s %s: %s\n' "$1" "$2" "$3"; }

# vm_root_out VM cmd... — like vm_root but captures stdout without ever
# tripping `set -e` at the call site (always pair with `|| true` there).
vm_root_out() {
  local vm=$1
  shift
  orb -m "$vm" -u root "$@" 2>/dev/null
}

check_vm_level() {
  local vm=$1 state ip

  if vm_exists "$vm"; then
    pass "$vm" "vm-exists"
  else
    fail "$vm" "vm-exists" "orbctl info $vm failed (VM missing)"
    return 1
  fi

  if vm_root "$vm" true >/dev/null 2>&1; then
    pass "$vm" "vm-reachable"
  else
    fail "$vm" "vm-reachable" "vm_root $vm true failed"
    return 1
  fi

  state="$(vm_root_out "$vm" systemctl is-system-running || true)"
  case "$state" in
    running|degraded) pass "$vm" "systemd-state" ;;
    *) fail "$vm" "systemd-state" "systemctl is-system-running = '$state' (expected running|degraded)" ;;
  esac

  ip="$(vm_ip "$vm" 2>/dev/null || true)"
  if [ -n "$ip" ]; then
    pass "$vm" "ipv4"
  else
    fail "$vm" "ipv4" "vm_ip $vm returned empty"
  fi

  return 0
}

check_csf_level() {
  local vm=$1 role regex lfd_expect testing_expect csfv lfd_state
  role="$(vm_role "$vm")"
  regex="$(vm_csfv_regex "$vm")"
  lfd_expect="$(vm_lfd "$vm")"
  testing_expect="$(vm_testing "$vm")"

  csfv="$(vm_root_out "$vm" csf -v || true)"
  if printf '%s' "$csfv" | grep -Eq "$regex"; then
    pass "$vm" "csf-version"
  else
    fail "$vm" "csf-version" "csf -v = '$csfv' does not match /$regex/"
  fi

  if [ "$(vm_root_out "$vm" systemctl is-active csf || true)" = "active" ]; then
    pass "$vm" "csf-active"
  else
    fail "$vm" "csf-active" "systemctl is-active csf != active"
  fi

  lfd_state="$(vm_root_out "$vm" systemctl is-active lfd || true)"
  if [ "$lfd_state" = "$lfd_expect" ]; then
    pass "$vm" "lfd"
  else
    fail "$vm" "lfd" "systemctl is-active lfd = '$lfd_state' (expected $lfd_expect)"
  fi

  if vm_root "$vm" bash -c "grep -Eq '^TESTING = \"$testing_expect\"' /etc/csf/csf.conf" >/dev/null 2>&1; then
    pass "$vm" "testing-flag"
  else
    fail "$vm" "testing-flag" "TESTING != \"$testing_expect\" in /etc/csf/csf.conf"
  fi

  if vm_root "$vm" grep -q 'lab-panel' /etc/csf/csf.allow >/dev/null 2>&1; then
    pass "$vm" "panel-allow"
  else
    fail "$vm" "panel-allow" "csf.allow has no lab-panel entry"
  fi

  if [ "$role" = "csf-orphan" ]; then
    if vm_root "$vm" bash -c "grep -Ev '^[[:space:]]*#' /etc/csf/downloadservers 2>/dev/null | grep -q download.configserver.com" >/dev/null 2>&1; then
      pass "$vm" "orphan-downloadservers"
    else
      fail "$vm" "orphan-downloadservers" "downloadservers does not point at configserver.com"
    fi

    if vm_root "$vm" grep -q 'download.configserver.com' /etc/hosts >/dev/null 2>&1; then
      pass "$vm" "orphan-sinkhole"
    else
      fail "$vm" "orphan-sinkhole" "/etc/hosts has no sinkhole for configserver.com"
    fi
  fi
}

check_ipset() {
  local vm=$1 expect
  expect="$(vm_ipset "$vm")"
  if [ "$expect" = "yes" ]; then
    if vm_root "$vm" command -v ipset >/dev/null 2>&1; then
      pass "$vm" "ipset-present"
    else
      fail "$vm" "ipset-present" "ipset expected (vm_ipset=yes) but command -v ipset failed"
    fi
  else
    if vm_root "$vm" command -v ipset >/dev/null 2>&1; then
      fail "$vm" "ipset-absent" "ipset NOT expected (vm_ipset=no) but command -v ipset succeeded"
    else
      pass "$vm" "ipset-absent"
    fi
  fi
}

check_nocsf() {
  local vm=$1
  if vm_root "$vm" command -v csf >/dev/null 2>&1; then
    fail "$vm" "no-csf" "csf unexpectedly present"
  else
    pass "$vm" "no-csf"
  fi
}

check_attacker_tools() {
  local vm=$1 tool
  for tool in sshpass curl python3; do
    if vm_root "$vm" command -v "$tool" >/dev/null 2>&1; then
      pass "$vm" "attacker-$tool"
    else
      fail "$vm" "attacker-$tool" "$tool not found"
    fi
  done
}

for vm in $vms; do
  if ! check_vm_level "$vm"; then
    continue
  fi

  role="$(vm_role "$vm")"
  case "$role" in
    csf|csf-orphan)
      check_csf_level "$vm"
      check_ipset "$vm"
      ;;
    attack-target)
      check_nocsf "$vm"
      check_ipset "$vm"
      ;;
    attacker)
      check_attacker_tools "$vm"
      ;;
  esac
done

# --- panel + agent checks (plan 05) ---

printf 'verify: %s checks, %s failures\n' "$CHECKS" "$FAILS"
[ "$FAILS" -eq 0 ]
