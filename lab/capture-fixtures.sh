#!/usr/bin/env bash
# lab/capture-fixtures.sh [--no-reset] [vm...]
#
# Captures real CSF artefacts from running lab VMs into
# internal/firewall/testdata/<fork>/ for the fixture-driven unit tests
# added in Phase 14 plan 07 (LAB-04). For each of the 5 CSF-variant VMs
# this regenerates: csf-v.txt, version.txt, downloadservers, csf.conf,
# csf.allow, csf.deny, lfd-ps.txt, lfd-active.txt, captured.txt.
#
# Does NOT write expected.json or testdata/README.md — those encode
# fixed per-fork facts (known in advance from lab/matrix.sh and the
# phase research) and are hand-maintained, not re-derived from a capture
# run. Re-running this script after a lab change (e.g. a provisioning
# fix) is expected to leave expected.json/README.md untouched unless a
# human re-checks and edits them.
#
# Default behaviour resets every target VM from its golden clone first
# (lab/reset.sh) so the capture always starts from the same known-clean
# state lab/verify.sh checks. Pass --no-reset to capture from the VMs'
# current state as-is (faster re-capture when the matrix is already
# known-healthy, e.g. immediately after `make lab-verify` passed).
#
# Sanitisation: the VM's own private IPv4 (DHCP-assigned by OrbStack,
# changes across resets) is replaced with 192.0.2.10 (TEST-NET-1, RFC
# 5737 — reserved for documentation, never a real route) in every
# captured file, so the committed fixtures never depend on the lab's
# current DHCP lease. Nothing else is stripped: the GPL header comments,
# stock empty license-key fields, and default UI_PASS in csf.conf are
# ConfigServer's own unconfigured defaults, not secrets.
#
# bash 3.2 safe (macOS ships bash 3.2): no associative arrays, no
# mapfile, no lowercase-parameter expansion.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

TESTDATA_DIR="$REPO_DIR/internal/firewall/testdata"

# fixture_dir_for_vm VM -> internal/firewall/testdata/<dir> name.
#
# Deliberately NOT the same as vm_fork(): alma8-csf-cwp-orphan installs
# the identical original-15.00 CSF release as alma9-csf-orig (same
# vm_fork id) but its csf.conf (TESTING=1), downloadservers
# (configserver.com, not commented out) and lfd state (inactive) are a
# distinct fixture scenario the fixture-driven tests must tell apart —
# so it gets its own fixture directory name.
fixture_dir_for_vm() {
  case "$1" in
    alma9-csf-orig) echo "original-15.00" ;;
    alma9-csf-aetherinox) echo "aetherinox-15.10" ;;
    debian12-csf-sentinel) echo "sentinel-15.13" ;;
    alma9-csf-da) echo "directadmin-15.12" ;;
    alma8-csf-cwp-orphan) echo "cwp-orphan-15.00" ;;
    *) die "capture-fixtures: no fixture dir mapping for VM $1" ;;
  esac
}

CAPTURE_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan"

# sed_inplace EXPR FILE — portable in-place sed (GNU on Linux/CI vs BSD on
# macOS use incompatible -i syntax; same pattern lib.sh uses for
# sha256sum/shasum).
sed_inplace() {
  local expr=$1 file=$2
  if sed --version >/dev/null 2>&1; then
    sed -i "$expr" "$file"
  else
    sed -i '' "$expr" "$file"
  fi
}

no_reset=0
vms=""
for arg in "$@"; do
  case "$arg" in
    --no-reset) no_reset=1 ;;
    *) vms="$vms $arg" ;;
  esac
done
vms="$(printf '%s' "$vms" | sed -e 's/^ *//' -e 's/ *$//')"
[ -n "$vms" ] || vms="$CAPTURE_VMS"

preflight_orb

if [ "$no_reset" -eq 0 ]; then
  log "capture-fixtures: resetting [$vms] to a known-clean golden state before capture"
  # shellcheck disable=SC2086
  "$LAB_DIR/reset.sh" $vms
else
  log "capture-fixtures: --no-reset given, capturing from current VM state as-is"
fi

capture_one() {
  local vm=$1 fixture_dir dir ip date_utc fork pin f
  fixture_dir="$(fixture_dir_for_vm "$vm")"
  dir="$TESTDATA_DIR/$fixture_dir"
  mkdir -p "$dir"

  log "$vm -> internal/firewall/testdata/$fixture_dir"

  vm_root "$vm" sh -c 'csf -v 2>&1' >"$dir/csf-v.txt" || true
  vm_root "$vm" cat /etc/csf/version.txt >"$dir/version.txt" 2>/dev/null || : >"$dir/version.txt"
  vm_root "$vm" cat /etc/csf/downloadservers >"$dir/downloadservers" 2>/dev/null || : >"$dir/downloadservers"
  vm_root "$vm" cat /etc/csf/csf.conf >"$dir/csf.conf"
  vm_root "$vm" cat /etc/csf/csf.allow >"$dir/csf.allow"

  # Add a throwaway fixture deny entry, capture csf.deny, then remove it
  # again — the VM must come out of this exactly as clean as reset.sh /
  # lab/verify.sh expect (verify.sh does not check csf.deny content, but
  # leaving a stray entry would be a real behaviour change to the lab).
  vm_root "$vm" csf -d 203.0.113.9 lab-fixture >/dev/null 2>&1 || true
  vm_root "$vm" cat /etc/csf/csf.deny >"$dir/csf.deny"
  vm_root "$vm" csf -dr 203.0.113.9 >/dev/null 2>&1 || true
  # csf -dr internally restarts csf/iptables; observed on
  # alma8-csf-cwp-orphan (TESTING=1) that the restart's own iptables -D
  # can race and fail even though the IP is genuinely gone from both
  # csf.deny and iptables/ipset, leaving a stale /etc/csf/csf.error that
  # makes every subsequent `csf -v` print an error banner instead of the
  # version. Clear it defensively so this capture never leaves a VM
  # noisier than it found it.
  vm_root "$vm" rm -f /etc/csf/csf.error >/dev/null 2>&1 || true

  vm_root "$vm" sh -c "ps -eo user,args | grep '[l]fd'" >"$dir/lfd-ps.txt" 2>/dev/null || : >"$dir/lfd-ps.txt"
  vm_root "$vm" systemctl is-active lfd >"$dir/lfd-active.txt" 2>/dev/null || true
  [ -s "$dir/lfd-active.txt" ] || printf 'inactive\n' >"$dir/lfd-active.txt"

  ip="$(vm_ip "$vm")"
  date_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  fork="$(vm_fork "$vm")"
  pin="$(forks_field "$fork" 5)"
  printf 'vm=%s distro=%s fork=%s date=%s forks.lock-pin=%s\n' \
    "$vm" "$(vm_distro "$vm")" "$fork" "$date_utc" "$pin" >"$dir/captured.txt"

  if [ -n "$ip" ]; then
    for f in csf-v.txt version.txt downloadservers csf.conf csf.allow csf.deny lfd-ps.txt lfd-active.txt captured.txt; do
      [ -f "$dir/$f" ] || continue
      sed_inplace "s/$ip/192.0.2.10/g" "$dir/$f"
    done
  fi
}

for vm in $vms; do
  capture_one "$vm"
done

log "capture-fixtures: done for [$vms]."
log "Verify the VMs were left clean: lab/verify.sh $vms"
