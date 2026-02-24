#!/bin/bash
# Defensia Agent — First boot script (runs once via cloud-init)

# Create config directory if missing
mkdir -p /etc/defensia
chmod 750 /etc/defensia

# Log first boot
echo "[$(date -u +"%Y-%m-%dT%H:%M:%SZ")] Defensia first boot complete. Awaiting token configuration." \
    >> /var/log/defensia-setup.log
