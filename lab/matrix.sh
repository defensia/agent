#!/usr/bin/env bash
# lab/matrix.sh — single source of truth for the 8 fixed lab VM names and
# their per-VM expectations. Sourced after lab/lib.sh (uses die() from it).
# bash 3.2 safe: case tables instead of associative arrays.
set -euo pipefail

LAB_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf lab-attacker"
LAB_AGENT_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf"
LAB_CSF_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset"

# The three lists above are consumed, never checked — so dropping a VM from
# LAB_AGENT_VMS used to be invisible: test.sh simply never visits it, prints no
# row for it, and still ends with "Overall: PASS". A fork would then go
# unexercised in VM while the report claimed the matrix was green, which is
# exactly the evidence LAB-01/LAB-03 and the "integration per VM" half of
# COL-01/COL-02 rest on. internal/firewall's TestFixtureSetComplete pins the 5
# fixture directories for the same reason; this is that guard for the matrix.
#
# Membership is fixed by REQUIREMENTS.md LAB-01 (orig, aetherinox, sentinel,
# da, cwp-orphan, alma10-noipset, no-CSF) plus the attacker. Changing the
# matrix means changing the requirement, so it must be a deliberate edit here.
# The unquoted $1 is the point: it splits the space-separated list into one
# VM per line so sort can order it. Quoting it would compare the raw strings
# and make the guard order-sensitive.
# shellcheck disable=SC2086
_matrix_sorted() { printf '%s\n' $1 | sort | tr '\n' ' '; }
_matrix_expect() {
  _name="$1"; _got="$(_matrix_sorted "$2")"; _want="$(_matrix_sorted "$3")"
  [ "$_got" = "$_want" ] || die "lab matrix drift: $_name is [${_got% }], want [${_want% }] (see REQUIREMENTS.md LAB-01)"
}
_matrix_expect LAB_VMS "$LAB_VMS" \
  "alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf lab-attacker"
_matrix_expect LAB_AGENT_VMS "$LAB_AGENT_VMS" \
  "alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf"
_matrix_expect LAB_CSF_VMS "$LAB_CSF_VMS" \
  "alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset"
unset -f _matrix_sorted _matrix_expect
unset _name _got _want

# vm_distro VM -> "distro:version" (orbctl create argument)
vm_distro() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|alma9-csf-da|lab-attacker) echo "alma:9" ;;
    debian12-csf-sentinel|debian12-nocsf) echo "debian:bookworm" ;;
    alma8-csf-cwp-orphan) echo "alma:8" ;;
    alma10-noipset) echo "alma:10" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_family VM -> alma|debian
vm_family() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|alma9-csf-da|alma8-csf-cwp-orphan|alma10-noipset|lab-attacker) echo "alma" ;;
    debian12-csf-sentinel|debian12-nocsf) echo "debian" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_fork VM -> fork id from forks.lock, or "none" (orphan reuses original-15.00)
vm_fork() {
  case "$1" in
    alma9-csf-orig|alma8-csf-cwp-orphan|alma10-noipset) echo "original-15.00" ;;
    alma9-csf-aetherinox) echo "aetherinox-15.10" ;;
    debian12-csf-sentinel) echo "sentinel-15.13" ;;
    alma9-csf-da) echo "directadmin-15.12" ;;
    debian12-nocsf|lab-attacker) echo "none" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_role VM -> csf|csf-orphan|attack-target|attacker
vm_role() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma10-noipset) echo "csf" ;;
    alma8-csf-cwp-orphan) echo "csf-orphan" ;;
    debian12-nocsf) echo "attack-target" ;;
    lab-attacker) echo "attacker" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_testing VM -> "0"|"1"|"-" (expected /etc/csf/csf.conf TESTING value)
vm_testing() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma10-noipset) echo "0" ;;
    alma8-csf-cwp-orphan) echo "1" ;;
    debian12-nocsf|lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_lfd VM -> active|inactive|"-" (expected systemctl is-active lfd)
vm_lfd() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma10-noipset) echo "active" ;;
    alma8-csf-cwp-orphan) echo "inactive" ;;
    debian12-nocsf|lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_ipset VM -> yes|no (whether the ipset package is installed)
vm_ipset() {
  case "$1" in
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma8-csf-cwp-orphan|debian12-nocsf) echo "yes" ;;
    alma10-noipset|lab-attacker) echo "no" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_csfv_regex VM -> extended regex expected in `csf -v` output, or "-"
vm_csfv_regex() {
  case "$1" in
    alma9-csf-orig|alma8-csf-cwp-orphan|alma10-noipset) echo 'v15\.00 \(generic\)' ;;
    alma9-csf-aetherinox) echo 'v15\.10 \(generic\)' ;;
    debian12-csf-sentinel) echo 'v15\.11 \(generic\)' ;;
    alma9-csf-da) echo 'v15\.12 \(DirectAdmin\)' ;;
    debian12-nocsf|lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_csf_version VM -> reported csf version string, or "-"
vm_csf_version() {
  case "$1" in
    alma9-csf-orig|alma8-csf-cwp-orphan|alma10-noipset) echo "15.00" ;;
    alma9-csf-aetherinox) echo "15.10" ;;
    debian12-csf-sentinel) echo "15.11" ;;
    alma9-csf-da) echo "15.12" ;;
    debian12-nocsf|lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_fw_mode VM -> ipset|iptables|"-"
vm_fw_mode() {
  case "$1" in
    alma10-noipset) echo "iptables" ;;
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma8-csf-cwp-orphan|debian12-nocsf) echo "ipset" ;;
    lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_has_agent VM -> yes|no (whether the defensia-agent binary is installed)
vm_has_agent() {
  case "$1" in
    lab-attacker) echo "no" ;;
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma8-csf-cwp-orphan|alma10-noipset|debian12-nocsf) echo "yes" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_csf_fork VM -> the firewall.CSFSnapshot.Fork value the real agent code
# is expected to detect (internal/firewall/csf_fork.go's Fork* constants:
# "original-15.00" | "aetherinox" | "sentinel" | "directadmin"), "none" for a
# VM with no CSF at all, or "-" for a VM with no agent (lab-attacker). This is
# deliberately distinct from vm_fork (the forks.lock *installer* id, e.g.
# "aetherinox-15.10") — vm_csf_fork is the evidence-based DETECTION result
# plan 15-01's detectFork() produces, which never equals the installer id.
vm_csf_fork() {
  case "$1" in
    alma9-csf-orig|alma8-csf-cwp-orphan|alma10-noipset) echo "original-15.00" ;;
    alma9-csf-aetherinox) echo "aetherinox" ;;
    debian12-csf-sentinel) echo "sentinel" ;;
    alma9-csf-da) echo "directadmin" ;;
    debian12-nocsf) echo "none" ;;
    lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_dl_configserver VM -> "1" if /etc/csf/downloadservers is expected to
# have an active (non-#) configserver.com line, "0" for every other CSF VM,
# "-" for a VM with no CSF at all. Only alma8-csf-cwp-orphan (the orphan
# fork, deliberately never re-pointed at a fork's own download servers)
# keeps the stock configserver.com entries active.
vm_dl_configserver() {
  case "$1" in
    alma8-csf-cwp-orphan) echo "1" ;;
    alma9-csf-orig|alma9-csf-aetherinox|debian12-csf-sentinel|alma9-csf-da|alma10-noipset) echo "0" ;;
    debian12-nocsf|lab-attacker) echo "-" ;;
    *) die "unknown VM $1" ;;
  esac
}

# vm_csf_ipv6_test VM -> "1" if TestLabCSFPortIPv6Mirror should actually
# exercise the IPv6 mirroring path on this VM, else "0". Limited to two VMs
# (one per distro family) rather than all CSF VMs: the test edits csf.conf's
# IPV6 flag directly and runs a real `csf -r`, so running it everywhere adds
# wall-clock without adding coverage once both families are proven.
vm_csf_ipv6_test() {
  case "$1" in
    alma9-csf-orig|debian12-csf-sentinel) echo "1" ;;
    *) echo "0" ;;
  esac
}

# vm_golden VM -> golden machine name used for clone-based reset
vm_golden() { echo "$1-golden"; }
