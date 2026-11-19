#!/usr/bin/env bash
# lab/sot/ui-saveconf.sh [KEY=VALUE ...]
#
# Runs INSIDE a CSF VM as root. Emulates the CSF web UI's "Save" action
# (DisplayUI.pm, RESEARCH.md Decision 5): rewrites every uncommented
# `KEY = "value"` line to normalised spacing (every other line stays
# byte-identical), applying any KEY=VALUE overrides given on the command
# line -- simulating a stale browser form that still has an old value for
# one key loaded when the user clicks Save. Never restarts CSF: the real
# UI's Save button does not either (that is SOT-02/03's whole point --
# a saveconf replay must leave the file semantically unchanged and must
# never trigger a CSF reload).
set -euo pipefail

CONF=/etc/csf/csf.conf
[ "$(id -u)" = "0" ] || { echo "ui-saveconf.sh must run as root" >&2; exit 1; }

# Build a single ";"-joined KEY=VALUE string for awk to split itself --
# portable (no gawk-only features), so this works under plain POSIX awk
# as well as gawk/mawk/busybox awk, whichever a given fork's base image
# ships.
overrides=""
for arg in "$@"; do
  if [ -n "$overrides" ]; then
    overrides="$overrides;$arg"
  else
    overrides="$arg"
  fi
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

mode="$(stat -c '%a' "$CONF")"

awk -v overrides="$overrides" '
BEGIN {
  n = split(overrides, pairs, ";")
  for (i = 1; i <= n; i++) {
    if (pairs[i] == "") continue
    eq = index(pairs[i], "=")
    if (eq == 0) continue
    k = substr(pairs[i], 1, eq - 1)
    v = substr(pairs[i], eq + 1)
    ov[k] = v
  }
}
{
  line = $0
  if (match(line, /^[A-Z0-9_]+[ \t]*=[ \t]*"[^"]*"/)) {
    matched = substr(line, RSTART, RLENGTH)
    key = matched
    sub(/[ \t]*=.*/, "", key)
    if (key in ov) {
      val = ov[key]
    } else {
      val = matched
      sub(/^[A-Z0-9_]+[ \t]*=[ \t]*"/, "", val)
      sub(/"$/, "", val)
    }
    print key " = \"" val "\""
    next
  }
  print line
}
' "$CONF" > "$tmp"

chmod "$mode" "$tmp"
mv "$tmp" "$CONF"
sha256sum "$CONF" | awk '{print $1}'
