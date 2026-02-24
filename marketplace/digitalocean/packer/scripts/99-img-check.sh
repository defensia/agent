#!/bin/bash
# DigitalOcean Marketplace image validation
# Based on: https://github.com/digitalocean/marketplace-partners

PASS=0
FAIL=0
WARN=0

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }
warn() { echo "  WARN: $1"; ((WARN++)); }

echo ""
echo "==> DigitalOcean Marketplace Image Validation"
echo "================================================"

# 1. Check OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    pass "Operating system: ${PRETTY_NAME}"
else
    fail "Cannot detect operating system"
fi

# 2. Check cloud-init
if command -v cloud-init &>/dev/null; then
    CI_VERSION=$(cloud-init --version 2>&1 | awk '{print $2}')
    pass "cloud-init installed (${CI_VERSION})"
else
    fail "cloud-init not installed"
fi

# 3. Check SSH
if dpkg -l openssh-server &>/dev/null 2>&1 || rpm -q openssh-server &>/dev/null 2>&1; then
    pass "OpenSSH server installed"
else
    fail "OpenSSH server not installed"
fi

# 4. Check firewall
if ufw status | grep -q "Status: active"; then
    pass "UFW firewall is active"
elif systemctl is-active --quiet firewalld; then
    pass "firewalld is active"
else
    fail "No firewall is active"
fi

# 5. Check no root authorized_keys
if [[ ! -f /root/.ssh/authorized_keys ]] || [[ ! -s /root/.ssh/authorized_keys ]]; then
    pass "No root SSH authorized_keys"
else
    fail "Root SSH authorized_keys found (must be removed)"
fi

# 6. Check no root password
if passwd -S root 2>/dev/null | grep -qE "^root (L|NP)"; then
    pass "Root password is locked/cleared"
else
    warn "Root password may be set (DigitalOcean will reset it)"
fi

# 7. Check bash history cleared
if [[ ! -f /root/.bash_history ]] || [[ ! -s /root/.bash_history ]]; then
    pass "Bash history cleared"
else
    fail "Bash history not cleared"
fi

# 8. Check no compressed/rotated logs
ROTATED=$(find /var/log -type f \( -name "*.gz" -o -name "*.1" -o -name "*.old" \) 2>/dev/null | wc -l)
if [[ "$ROTATED" -eq 0 ]]; then
    pass "No rotated/compressed log files"
else
    fail "Found ${ROTATED} rotated/compressed log files"
fi

# 9. Check pending security updates
UPDATES=$(apt list --upgradable 2>/dev/null | grep -c "security" || true)
if [[ "$UPDATES" -eq 0 ]]; then
    pass "No pending security updates"
else
    warn "${UPDATES} pending security updates"
fi

# 10. Defensia-specific: check agent binary
if [[ -x /usr/local/bin/defensia-agent ]]; then
    pass "Defensia Agent binary installed"
else
    fail "Defensia Agent binary not found"
fi

# 11. Defensia-specific: check systemd service
if systemctl list-unit-files | grep -q defensia-agent; then
    pass "Defensia Agent systemd service configured"
else
    fail "Defensia Agent systemd service not found"
fi

# 12. Defensia-specific: check MOTD
if [[ -x /etc/update-motd.d/99-defensia ]]; then
    pass "Defensia MOTD script installed"
else
    warn "Defensia MOTD script not found"
fi

echo ""
echo "================================================"
echo "  Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
echo "================================================"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    echo "  IMAGE VALIDATION FAILED — fix the issues above before submitting."
    exit 1
else
    echo "  IMAGE VALIDATION PASSED"
    exit 0
fi
