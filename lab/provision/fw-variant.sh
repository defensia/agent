#!/usr/bin/env bash
# lab/provision/fw-variant.sh <nft-a|nft-b|nft-c>
# Runs as root inside an Alma 10 VM. Provisions the three RHEL 10 firewall
# scenarios phase 17 (NFT-01) diagnoses and, after plan 17-04/17-06, the
# agent's nftables backend targets:
#   nft-a: iptables-nft present, no ipset (the lab's existing alma10-noipset)
#   nft-b: no iptables at all, no ipset, firewalld (nftables-only system)
#   nft-c: ipset binary present but kernel-side unusable (shim), firewalld
# Idempotent: a marker file skips the install step on re-run, but the
# final asserts always re-run so a drifted VM is caught even with the
# marker present.
set -euo pipefail

variant=${1:?"usage: fw-variant.sh <nft-a|nft-b|nft-c>"}

MARKER_DIR=/var/lib/defensia-lab
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/fw-variant-$variant.done"

case "$variant" in
  nft-a)
    if [ ! -f "$MARKER" ]; then
      dnf -y install nftables
      touch "$MARKER"
    fi
    command -v nft >/dev/null 2>&1
    command -v iptables >/dev/null 2>&1
    ! command -v ipset >/dev/null 2>&1
    iptables --version | grep -q nf_tables
    ;;

  nft-b)
    if [ ! -f "$MARKER" ]; then
      dnf -y install nftables firewalld
      systemctl enable --now firewalld
      dnf -y remove ipset iptables-nft || true
      if command -v iptables >/dev/null 2>&1 || ! command -v firewall-cmd >/dev/null 2>&1; then
        echo "fw-variant nft-b: iptables still present or firewalld missing after the first removal pass, retrying" >&2
        dnf -y install firewalld || true
        rpm -e --nodeps iptables-nft 2>&1 || true
        echo "fw-variant nft-b: used the rpm -e --nodeps fallback path" >&2
      fi
      touch "$MARKER"
    fi
    command -v nft >/dev/null 2>&1
    ! command -v iptables >/dev/null 2>&1
    ! command -v ip6tables >/dev/null 2>&1
    ! command -v ipset >/dev/null 2>&1
    [ "$(systemctl is-active firewalld)" = active ]
    ;;

  nft-c)
    if [ ! -f "$MARKER" ]; then
      dnf -y install nftables firewalld ipset
      systemctl enable --now firewalld
      if [ ! -e /usr/sbin/ipset.real ]; then
        mv /usr/sbin/ipset /usr/sbin/ipset.real
      fi
      cat > /usr/sbin/ipset <<'SHIM'
#!/bin/sh
# defensia-lab nft-c: ipset binary present but the kernel side is unusable
# (simulates containers without CAP_NET_ADMIN / missing ip_set). Lab only.
case "$1" in --version|-v|version) echo "ipset v7.22, protocol version: 7"; exit 0;; esac
echo "ipset v7.22: Kernel error received: Operation not permitted" >&2
exit 1
SHIM
      chmod 0755 /usr/sbin/ipset
      touch "$MARKER"
    fi
    command -v nft >/dev/null 2>&1
    command -v ipset >/dev/null 2>&1
    ! ipset list -n >/dev/null 2>&1
    command -v iptables >/dev/null 2>&1
    [ "$(systemctl is-active firewalld)" = active ]
    ;;

  *)
    echo "ERROR: unknown fw-variant '$variant' (expected nft-a|nft-b|nft-c)" >&2
    exit 1
    ;;
esac

nft --version
iptables --version 2>&1 || true
command -v ipset iptables ip6tables nft firewall-cmd csf || true
