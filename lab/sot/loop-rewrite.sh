#!/usr/bin/env bash
# lab/sot/loop-rewrite.sh <interval_s> <count> KEY=VALUE
#
# Runs INSIDE a CSF VM as root. Simulates a control panel (or a browser
# tab left open on the CSF settings page) rewriting csf.conf repeatedly:
# calls ui-saveconf.sh with the given KEY=VALUE override every
# interval_s seconds, count times, then exits. Used by the lab to prove
# the auto-correct hourly rate limit / paused_conflict escalation
# (16.1-11) against something that keeps changing the file for real,
# not just a mocked clock.
set -euo pipefail

interval=${1:?"usage: loop-rewrite.sh <interval_s> <count> KEY=VALUE"}
count=${2:?"usage: loop-rewrite.sh <interval_s> <count> KEY=VALUE"}
override=${3:?"usage: loop-rewrite.sh <interval_s> <count> KEY=VALUE"}

[ "$(id -u)" = "0" ] || { echo "loop-rewrite.sh must run as root" >&2; exit 1; }

DIR=/root/lab-sot
LOG="$DIR/loop.log"
PIDFILE="$DIR/loop.pid"
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$DIR"
echo $$ > "$PIDFILE"

i=0
while [ "$i" -lt "$count" ]; do
  sha="$(bash "$SELF_DIR/ui-saveconf.sh" "$override")"
  printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$sha" >> "$LOG"
  i=$((i + 1))
  if [ "$i" -lt "$count" ]; then
    sleep "$interval"
  fi
done

rm -f "$PIDFILE"
