#!/bin/bash
set -euo pipefail

echo "==> Configuring UFW firewall..."

# Reset to defaults
ufw --force reset

# Default policies
ufw default deny incoming
ufw default allow outgoing

# Allow SSH
ufw allow OpenSSH

# Enable firewall
ufw --force enable

echo "==> UFW configured: deny incoming, allow outgoing, allow SSH"
ufw status verbose
