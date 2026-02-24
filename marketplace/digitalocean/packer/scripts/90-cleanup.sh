#!/bin/bash
set -euo pipefail

echo "==> Cleaning up image for DigitalOcean Marketplace..."

# Remove apt cache
apt-get -y autoremove
apt-get -y autoclean
apt-get -y clean

# Remove temp files
rm -rf /tmp/* /var/tmp/*

# Remove SSH host keys (regenerated on first boot)
rm -f /etc/ssh/ssh_host_*

# Remove root SSH authorized keys
rm -f /root/.ssh/authorized_keys

# Clear root password
passwd -d root 2>/dev/null || true

# Truncate log files
find /var/log -type f -exec truncate -s 0 {} \;

# Remove rotated/compressed logs
find /var/log -type f -name "*.gz" -delete
find /var/log -type f -name "*.1" -delete
find /var/log -type f -name "*.old" -delete

# Clear bash history
unset HISTFILE
rm -f /root/.bash_history
history -c 2>/dev/null || true

# Clear machine-id (regenerated on first boot)
truncate -s 0 /etc/machine-id

# Clear cloud-init data so it runs on next boot
cloud-init clean --logs 2>/dev/null || true

# Zero fill free space for smaller snapshot
dd if=/dev/zero of=/zerofile bs=4096 2>/dev/null || true
rm -f /zerofile
sync

echo "==> Cleanup complete"
