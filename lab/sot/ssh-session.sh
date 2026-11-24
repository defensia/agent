#!/usr/bin/env bash
# lab/sot/ssh-session.sh open|close <vm>
#
# HOST side (sources lab/lib.sh). Opens (or closes) a real, persistent
# SSH session from lab-attacker into <vm>, so the 16.1 integration tests
# can prove the live-session guard (guardAllowRemoval / ssh_session_ip)
# against a session the agent's own sshSessionIPs() genuinely observes
# as ESTABLISHED, not a mocked one. Never touches any other key in
# lab-attacker's or the target's ~/.ssh/authorized_keys -- every line
# this script adds or removes carries the "lab-sot" tag.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"

ATTACKER_VM="lab-attacker"
KEY=/root/.ssh/lab_sot
ALIAS_IP="198.51.100.77"
TAG="lab-sot"

action=${1:?"usage: ssh-session.sh open|close <vm>"}
vm=${2:?"usage: ssh-session.sh open|close <vm>"}
pidfile_on_attacker="/root/lab-sot/ssh-session-$vm.pid"

do_open() {
  vm_root "$ATTACKER_VM" mkdir -p /root/lab-sot /root/.ssh
  if ! vm_root "$ATTACKER_VM" test -f "$KEY" >/dev/null 2>&1; then
    vm_root "$ATTACKER_VM" ssh-keygen -t ed25519 -N '' -f "$KEY" -C "$TAG" >/dev/null
  fi
  local pubkey
  pubkey="$(vm_root "$ATTACKER_VM" cat "$KEY.pub")"

  vm_root "$vm" mkdir -p /root/.ssh
  vm_root "$vm" touch /root/.ssh/authorized_keys
  if ! vm_root "$vm" grep -qF "$pubkey" /root/.ssh/authorized_keys; then
    vm_root "$vm" bash -c "printf '%s %s\n' \"$pubkey\" \"$TAG\" >> /root/.ssh/authorized_keys"
  fi

  # Fresh alias each call: drop a stale one left by a previous (possibly
  # crashed) run before adding it again.
  vm_root "$ATTACKER_VM" bash -c "ip addr del '$ALIAS_IP/32' dev eth0 2>/dev/null || true"
  vm_root "$ATTACKER_VM" ip addr add "$ALIAS_IP/32" dev eth0

  local target_ip
  target_ip="$(vm_ip "$vm")"
  vm_root "$vm" ip route replace "$ALIAS_IP/32" dev eth0

  vm_root "$ATTACKER_VM" bash -c "
    nohup ssh -N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -b '$ALIAS_IP' -i '$KEY' root@'$target_ip' \
      >/root/lab-sot/ssh-session-$vm.log 2>&1 &
    echo \$! > '$pidfile_on_attacker'
  "

  sleep 2

  if ! vm_root "$vm" sh -c "ss -Hnt state established '( sport = :22 )'" | grep -q "$ALIAS_IP"; then
    echo "ssh-session.sh open: $vm does not show an ESTABLISHED session from $ALIAS_IP" >&2
    exit 1
  fi

  echo "$ALIAS_IP"
}

do_close() {
  if vm_root "$ATTACKER_VM" test -f "$pidfile_on_attacker" >/dev/null 2>&1; then
    local pid
    pid="$(vm_root "$ATTACKER_VM" cat "$pidfile_on_attacker")"
    vm_root "$ATTACKER_VM" bash -c "kill '$pid' 2>/dev/null || true"
    vm_root "$ATTACKER_VM" rm -f "$pidfile_on_attacker"
  fi
  vm_root "$ATTACKER_VM" bash -c "ip addr del '$ALIAS_IP/32' dev eth0 2>/dev/null || true"
  vm_root "$vm" bash -c "sed -i '/$TAG/d' /root/.ssh/authorized_keys 2>/dev/null || true"
}

case "$action" in
  open) do_open ;;
  close) do_close ;;
  *) echo "usage: ssh-session.sh open|close <vm>" >&2; exit 1 ;;
esac
