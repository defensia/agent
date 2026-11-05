#!/usr/bin/env bash
# lab/provision/attacker.sh — provisions lab-attacker (Alma 9).
# Runs as root inside the Linux VM. hydra is not packaged for Alma 9
# arm64; sshpass + plain ssh/curl/python3 cover the SSH/web/mail legs.
set -euo pipefail

MARKER_DIR=/var/lib/defensia-lab
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/attacker.done"

dnf -y install openssh-clients curl python3 iproute
dnf -y install sshpass || { dnf -y install epel-release && dnf -y install sshpass; }

command -v sshpass >/dev/null 2>&1 || { echo "ERROR: sshpass missing after install" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl missing after install" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 missing after install" >&2; exit 1; }

touch "$MARKER"
echo "attacker.sh done (marker: $MARKER)"
