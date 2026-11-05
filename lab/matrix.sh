#!/usr/bin/env bash
# lab/matrix.sh — single source of truth for the 8 fixed lab VM names and
# their per-VM expectations. Sourced after lab/lib.sh (uses die() from it).
# bash 3.2 safe: case tables instead of associative arrays.
set -euo pipefail

LAB_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf lab-attacker"
LAB_AGENT_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset debian12-nocsf"
LAB_CSF_VMS="alma9-csf-orig alma9-csf-aetherinox debian12-csf-sentinel alma9-csf-da alma8-csf-cwp-orphan alma10-noipset"

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

# vm_golden VM -> golden machine name used for clone-based reset
vm_golden() { echo "$1-golden"; }
