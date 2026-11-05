#!/usr/bin/env bash
# lab/provision/target-services.sh <alma|debian>
# Runs as root inside the attack-target VM (debian12-nocsf). Installs nginx
# (serves the agent's wp-login.php/xmlrpc.php brute-force legs — no real
# WordPress needed, the agent's weblog watcher only cares about the POST
# method + URI + status code) and dovecot (serves the IMAP brute-force
# leg), then restarts defensia-agent so its watchers re-detect the newly
# installed services (HasMailService() and web-log auto-detection only run
# at agent startup).
#
# Idempotent: skips the install step once the marker exists, but always
# re-asserts the dovecot lab config and restarts dovecot + defensia-agent
# (cheap, and guards against a VM reset wiping /etc/dovecot but not this
# marker — never observed, but the cost of checking is a few ms).
set -euo pipefail

MARKER_DIR=/var/lib/defensia-lab
mkdir -p "$MARKER_DIR"
MARKER="$MARKER_DIR/target-services.done"

family=${1:?"usage: target-services.sh <alma|debian>"}

if [ ! -f "$MARKER" ]; then
  case "$family" in
    debian)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -q
      apt-get install -y -q nginx dovecot-imapd
      ;;
    alma)
      dnf -y install nginx dovecot
      ;;
    *)
      echo "ERROR: unknown family '$family' (expected alma|debian)" >&2
      exit 1
      ;;
  esac
fi

# dovecot: passwd-file passdb + auth_verbose, so a failed login writes
# "auth: passwd-file(labmail,<ip>,<sess>): Password mismatch" — the one
# line shape the agent's mail watcher regex 68 actually matches (see
# 14-RESEARCH.md FINDING: the stock imap-login/PAM lines do not match).
cat >/etc/dovecot/conf.d/99-lab.conf <<'EOF'
disable_plaintext_auth = no
auth_verbose = yes
auth_mechanisms = plain login
passdb {
  driver = passwd-file
  args = scheme=PLAIN username_format=%u /etc/dovecot/lab-users
}
userdb {
  driver = static
  args = uid=nobody gid=nogroup home=/tmp/%u
}
EOF

if [ "$family" = alma ]; then
  sed -i 's/gid=nogroup/gid=nobody/' /etc/dovecot/conf.d/99-lab.conf
fi

# Disable the system/PAM passdb: it would otherwise be tried first and its
# failure lines ("pam_authenticate() failed") don't match the agent's
# regex either — the passwd-file passdb above must be the only one.
sed -i 's/^!include auth-system.conf.ext/#!include auth-system.conf.ext/' /etc/dovecot/conf.d/10-auth.conf

printf 'labmail:{PLAIN}lab-correct-password\n' >/etc/dovecot/lab-users
# 0644, not 0600: the auth worker reads this file as the unprivileged
# `dovecot`/`nobody` user, not root — 0600 (root-only) makes every lookup
# fail with "Permission denied" before it ever reaches a real
# match/mismatch decision (found empirically 2026-11-05: every login
# attempt logged a dovecot-internal auth error instead of the "Password
# mismatch" line the agent's mail watcher regex needs). World-readable is
# an acceptable lab tradeoff — the file holds one fake, lab-only password.
chmod 0644 /etc/dovecot/lab-users

systemctl enable --now nginx dovecot
systemctl restart dovecot
# Watchers only detect services at agent startup (HasMailService(),
# DetectWebLogInfo()) — restart so this run's nginx/dovecot are picked up.
systemctl restart defensia-agent 2>/dev/null || true

ss -ltn | grep -q ':143 ' || { echo "ERROR: dovecot not listening on :143" >&2; exit 1; }
ss -ltn | grep -q ':80 ' || { echo "ERROR: nginx not listening on :80" >&2; exit 1; }

touch "$MARKER"
echo "target-services.sh done (marker: $MARKER)"
