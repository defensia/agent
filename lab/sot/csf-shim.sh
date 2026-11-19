#!/usr/bin/env bash
# lab/sot/csf-shim.sh install|uninstall|calls <vm>
#
# HOST side (sources lab/lib.sh). The agent resolves the csf binary by
# absolute path (internal/firewall/csf_exec.go's csfBinaryPath checks
# /usr/sbin/csf then /usr/local/csf/bin/csf directly -- confirmed by
# reading it, never a $PATH search), so a wrapper placed anywhere on
# $PATH would simply never be invoked, even though the agent's own
# systemd unit sets no explicit PATH. Installs the logging wrapper AT
# the real binary's own resolved path instead: renames the real binary
# to <path>.lab-real next to it, writes a wrapper script in its place
# that appends every invocation's timestamp+args to
# /root/lab-sot/csf-calls.log and execs the renamed real binary with
# the same args. `uninstall` puts the original back exactly.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"

action=${1:?"usage: csf-shim.sh install|uninstall|calls <vm>"}
vm=${2:?"usage: csf-shim.sh install|uninstall|calls <vm>"}

resolve_bin() {
  for candidate in /usr/sbin/csf /usr/local/csf/bin/csf; do
    if vm_root "$vm" test -f "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  printf ''
}

do_install() {
  local bin real tmp
  bin="$(resolve_bin)"
  [ -n "$bin" ] || { echo "csf-shim.sh: could not find the real csf binary on $vm" >&2; exit 1; }
  real="${bin}.lab-real"

  if vm_root "$vm" test -f "$real" >/dev/null 2>&1; then
    echo "csf-shim.sh: shim already installed on $vm ($real exists)" >&2
    return 0
  fi

  vm_root "$vm" mkdir -p /root/lab-sot
  vm_root "$vm" cp -a "$bin" "$real"

  # Built on the host with each line passed as a printf ARGUMENT (not
  # interpolated into the format string itself), so none of the
  # wrapper's own shell metacharacters ($, %, *) are at risk of being
  # misread by this script's own shell or by printf's format parsing --
  # only $real is deliberately expanded now; "$@" stays literal for the
  # wrapper to expand when it runs on the VM.
  tmp="$(mktemp)"
  {
    printf '%s\n' '#!/bin/sh'
    printf '%s\n' 'printf "%s %s\n" "$(date +%s)" "$*" >> /root/lab-sot/csf-calls.log'
    printf '%s\n' "exec \"$real\" \"\$@\""
  } > "$tmp"

  vm_push "$vm" "$tmp" "$bin"
  vm_root "$vm" chmod 700 "$bin"
  rm -f "$tmp"

  echo "installed: $bin now logs to /root/lab-sot/csf-calls.log (real binary at $real)"
}

do_uninstall() {
  local candidate
  for candidate in /usr/sbin/csf.lab-real /usr/local/csf/bin/csf.lab-real; do
    if vm_root "$vm" test -f "$candidate" >/dev/null 2>&1; then
      vm_root "$vm" mv "$candidate" "${candidate%.lab-real}"
      echo "uninstalled: restored ${candidate%.lab-real}"
      return 0
    fi
  done
  echo "csf-shim.sh: no shim installed on $vm" >&2
}

do_calls() {
  vm_root "$vm" cat /root/lab-sot/csf-calls.log 2>/dev/null || true
}

case "$action" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  calls) do_calls ;;
  *) echo "usage: csf-shim.sh install|uninstall|calls <vm>" >&2; exit 1 ;;
esac
