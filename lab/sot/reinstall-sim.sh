#!/usr/bin/env bash
# lab/sot/reinstall-sim.sh [--restore]
#
# Runs INSIDE a CSF VM as root. Simulates a control panel reinstalling
# (or auto-updating) the CSF fork: a reinstall typically resets csf.conf
# to the fork's own shipped defaults and bumps the version string -- the
# exact "version_changed" drift hint (CONTRACT, sotDrift.js) this
# command proves against a real file swap instead of a mocked one.
#
# Without --restore: backs up the CURRENT csf.conf and version.txt
# (whatever they are right now, not necessarily pristine -- a test may
# have already changed desired state since boot), then copies
# /root/lab-sot/pristine-csf.conf (saved by the calling stage beforehand
# from the golden VM's original conf) over /etc/csf/csf.conf and
# rewrites /etc/csf/version.txt to "<current version>.1".
#
# --restore: puts both files back to exactly what they were right
# before the non---restore call.
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "reinstall-sim.sh must run as root" >&2; exit 1; }

DIR=/root/lab-sot
CONF=/etc/csf/csf.conf
VERSION=/etc/csf/version.txt
PRISTINE="$DIR/pristine-csf.conf"
CONF_ORIG="$DIR/csf-conf.orig"
VERSION_ORIG="$DIR/version.txt.orig"

mkdir -p "$DIR"

if [ "${1:-}" = "--restore" ]; then
  [ -f "$VERSION_ORIG" ] || { echo "reinstall-sim.sh --restore: no $VERSION_ORIG saved" >&2; exit 1; }
  [ -f "$CONF_ORIG" ] || { echo "reinstall-sim.sh --restore: no $CONF_ORIG saved" >&2; exit 1; }
  cp -a "$VERSION_ORIG" "$VERSION"
  cp -a "$CONF_ORIG" "$CONF"
  sha256sum "$CONF" | awk '{print $1}'
  cat "$VERSION"
  exit 0
fi

[ -f "$PRISTINE" ] || { echo "reinstall-sim.sh: $PRISTINE missing -- the calling stage must save it first" >&2; exit 1; }

cp -a "$VERSION" "$VERSION_ORIG"
cp -a "$CONF" "$CONF_ORIG"
cp -a "$PRISTINE" "$CONF"

orig_version="$(cat "$VERSION_ORIG")"
printf '%s.1\n' "$orig_version" > "$VERSION"

sha256sum "$CONF" | awk '{print $1}'
cat "$VERSION"
