#!/bin/bash
set -euo pipefail

echo "==> Installing Defensia Agent..."

# Install dependencies
apt-get -y update
apt-get -y install curl jq iptables

# Download and install agent binary + systemd service (without starting)
curl -fsSL https://github.com/defensia/agent/releases/latest/download/install.sh -o /tmp/defensia-install.sh
chmod +x /tmp/defensia-install.sh
bash /tmp/defensia-install.sh --install-only
rm -f /tmp/defensia-install.sh

# Verify binary exists
if [[ -x /usr/local/bin/defensia-agent ]]; then
    echo "==> Defensia Agent binary installed at /usr/local/bin/defensia-agent"
    /usr/local/bin/defensia-agent --version 2>/dev/null || true
else
    echo "ERROR: Defensia Agent binary not found!"
    exit 1
fi

# Verify systemd service exists
if systemctl list-unit-files | grep -q defensia-agent; then
    echo "==> Defensia Agent systemd service installed"
else
    echo "ERROR: Defensia Agent systemd service not found!"
    exit 1
fi

echo "==> Defensia Agent installation complete (not started — awaiting token configuration)"
