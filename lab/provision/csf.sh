#!/usr/bin/env bash
# lab/provision/csf.sh <fork-id> [--orphan] [--panel-ip IP]
# Runs as root inside a Linux VM/container. Expects the pinned fork
# tarball already pushed to /root/csf-<fork-id>.tgz (see lab/fetch-forks.sh
# + lab/lib.sh vm_push). Idempotent: skips the install step if already
# done, but always re-asserts TESTING, the panel allow and the orphan
# downloadservers/sinkhole block.
set -euo pipefail

MARKER_DIR=/var/lib/defensia-lab
mkdir -p "$MARKER_DIR"

fork_id=${1:?"usage: csf.sh <fork-id> [--orphan] [--panel-ip IP]"}
shift

orphan=0
panel_ip_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --orphan)
      orphan=1
      shift
      ;;
    --panel-ip)
      panel_ip_arg=${2:?"--panel-ip needs an IP"}
      shift 2
      ;;
    *)
      echo "ERROR: unknown argument '$1'" >&2
      exit 1
      ;;
  esac
done

MARKER="$MARKER_DIR/csf-$fork_id.done"
ARCHIVE="/root/csf-$fork_id.tgz"

if [ ! -f "$MARKER" ]; then
  [ -f "$ARCHIVE" ] || { echo "ERROR: expected archive $ARCHIVE not found" >&2; exit 1; }

  rm -rf /root/csf-src
  mkdir -p /root/csf-src
  tar xzf "$ARCHIVE" -C /root/csf-src

  # Search for install.sh, not csf.pl: several forks' archives bundle
  # extra copies of csf.pl under control-panel-specific subdirectories
  # (e.g. original-15.00 ships csf/cwp/csf.pl and csf/vestacp/csf.pl
  # alongside the real csf/csf.pl) so `find -name csf.pl | head -1` can
  # pick a subtree with no install.sh in it. install.sh is unique.
  SRC="$(dirname "$(find /root/csf-src -maxdepth 3 -type f -name install.sh | head -1)")"
  [ -n "$SRC" ] && [ -d "$SRC" ] || { echo "ERROR: install.sh not found after extracting $ARCHIVE" >&2; exit 1; }

  case "$fork_id" in
    directadmin-*)
      id diradmin >/dev/null 2>&1 || useradd -r diradmin
      mkdir -p /usr/local/directadmin
      printf '#!/bin/sh\nexit 0\n' > /usr/local/directadmin/directadmin
      chmod +x /usr/local/directadmin/directadmin
      ;;
  esac

  # install.sh emits harmless cp/chmod errors on every fork (missing Geo/
  # php/py/cgi assets) — success is judged by the csf -v gate below, not
  # by this command's own exit code.
  (cd "$SRC" && sh install.sh) > /root/csf-install.log 2>&1 || true

  case "$fork_id" in
    directadmin-*)
      # Stop the agent's DirectAdmin collectors from running against a
      # fake DA once csf itself no longer needs the stub to report
      # (DirectAdmin) in `csf -v` (open question 3 in 14-RESEARCH.md).
      rm -f /usr/local/directadmin/directadmin
      if ! csf -v 2>&1 | grep -q '(DirectAdmin)'; then
        mkdir -p /usr/local/directadmin
        printf '#!/bin/sh\nexit 0\n' > /usr/local/directadmin/directadmin
        chmod +x /usr/local/directadmin/directadmin
        echo "NOTE: DA stub kept (csf -v needs it)"
      fi
      ;;
  esac

  if ! command -v csf >/dev/null 2>&1 || ! csf -v 2>&1 | grep -Eq 'v1[0-9]\.[0-9]+'; then
    echo "ERROR: csf install failed for $fork_id — tail of /root/csf-install.log:" >&2
    tail -50 /root/csf-install.log >&2 || true
    exit 1
  fi
fi

if [ "$orphan" -eq 1 ]; then
  # Simulate an orphaned CWP install: downloadservers still points at the
  # (now closed) ConfigServer domain, TESTING=1 (lfd never daemonises).
  # SAFETY: sinkhole the domains in /etc/hosts so nothing in the lab ever
  # actually contacts configserver.com (csget cron / lfd self-update).
  printf 'download.configserver.com\ndownload2.configserver.com\n' > /etc/csf/downloadservers
  sed -i 's/^TESTING = .*/TESTING = "1"/' /etc/csf/csf.conf
  grep -q 'download.configserver.com' /etc/hosts || \
    echo '127.0.0.1 download.configserver.com download2.configserver.com' >> /etc/hosts
else
  sed -i 's/^TESTING = .*/TESTING = "0"/' /etc/csf/csf.conf
fi

panel_ip="$panel_ip_arg"
if [ -z "$panel_ip" ]; then
  # getent exits 2 ("not found") when host.orb.internal can't be resolved
  # (e.g. CI, which has no OrbStack) — under set -e/pipefail that silently
  # killed the whole script with no error message before this fix (found
  # running this exact script in a plain Docker container, LAB-05). The
  # `|| true` only tolerates lookup failure; a real csf.sh bug would still
  # surface via the csf -v gate above.
  panel_ip="$(getent ahostsv4 host.orb.internal 2>/dev/null | awk 'NR==1{print $1}')" || true
fi
if [ -n "$panel_ip" ]; then
  # CSF's default outbound filter silently blocks the agent -> panel
  # traffic unless the panel host is explicitly allowed (14-RESEARCH.md
  # Pitfall 1).
  csf -a "$panel_ip" lab-panel || true
else
  echo "NOTE: no panel IP resolved/provided — skipping csf -a allow (expected in CI)"
fi

systemctl enable csf || true
systemctl restart csf
if [ "$orphan" -eq 1 ]; then
  # TESTING=1: lfd must never daemonise, AND must stay disabled — merely
  # stopping it (while leaving it enabled) is not enough: on the next boot
  # (lab/up.sh clones the golden and starts it, lab/reset.sh does the same)
  # systemd auto-starts every enabled unit, lfd tries to run under
  # TESTING=1, gets killed (signal 9) almost immediately, and lands in
  # "failed" instead of the expected "inactive". Found via a real golden
  # build + clone + boot cycle, not a dry read of this script.
  systemctl disable --now lfd || true
else
  systemctl enable --now lfd || true
fi

systemctl is-active --quiet csf || { echo "ERROR: csf not active after restart" >&2; exit 1; }
if [ "$orphan" -ne 1 ]; then
  systemctl is-active --quiet lfd || { echo "ERROR: lfd not active after restart" >&2; exit 1; }
fi
grep -Eq '^TESTING = "[01]"' /etc/csf/csf.conf || { echo "ERROR: TESTING not set to 0 or 1 in csf.conf" >&2; exit 1; }

touch "$MARKER"
csf -v
