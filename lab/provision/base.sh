#!/usr/bin/env bash
# lab/provision/base.sh <alma|debian> <ipset:yes|no>
# Runs as root inside a Linux VM/container. Installs the base packages CSF
# and the attack legs need, and makes sure sshd logs failed-password
# attempts (needed by the SSH brute-force leg).
set -euo pipefail

MARKER_DIR=/var/lib/defensia-lab
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/base.done"

family=${1:?"usage: base.sh <alma|debian> <ipset:yes|no>"}
ipset_flag=${2:?"usage: base.sh <alma|debian> <ipset:yes|no>"}

case "$family" in
  alma)
    dnf -y install perl perl-libwww-perl perl-IO-Socket-SSL perl-Net-SSLeay \
      tar gzip procps-ng iproute rsyslog openssh-server cronie curl findutils which
    dnf -y install iptables-nft || dnf -y install iptables
    if [ "$ipset_flag" = yes ]; then
      dnf -y install ipset
    elif command -v ipset >/dev/null 2>&1; then
      dnf -y remove ipset
    fi
    systemctl enable --now rsyslog sshd crond
    ;;
  debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q perl libwww-perl liblwp-protocol-https-perl \
      libio-socket-ssl-perl libjson-perl libnet-ssleay-perl iptables cron \
      rsyslog openssh-server curl procps iproute2
    if [ "$ipset_flag" = yes ]; then
      apt-get install -y -q ipset
    fi
    systemctl enable --now rsyslog ssh cron
    ;;
  *)
    echo "ERROR: unknown family '$family' (expected alma|debian)" >&2
    exit 1
    ;;
esac

# ensure sshd logs failed-password lines (attack-leg prerequisite)
install -d -m0755 /etc/ssh/sshd_config.d
printf 'PasswordAuthentication yes\nUseDNS no\n' > /etc/ssh/sshd_config.d/99-lab.conf
systemctl restart sshd 2>/dev/null || systemctl restart ssh

if [ "$ipset_flag" = no ] && command -v ipset >/dev/null 2>&1; then
  echo "ERROR: ipset still present after requested removal (ipset_flag=no)" >&2
  exit 1
fi

touch "$MARKER"
echo "base.sh done: family=$family ipset=$ipset_flag (marker: $MARKER)"
