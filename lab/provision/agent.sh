#!/usr/bin/env bash
# lab/provision/agent.sh <panel_url> <agent_name> <install_token> <agent_ip>
#
# Runs as root inside a lab VM. Expects /root/defensia-agent (binary, built
# from this worktree's source) and /root/defensia-agent.service already
# pushed by lab/lib.sh's install_agent. Installs, registers against the
# local lab panel, and starts the service.
#
# Debian VMs may lack python3 — this script uses grep/sed only, never
# python3 (unlike the host-side lab/lib.sh helpers, which always have it).
set -euo pipefail

if [ $# -ne 4 ]; then
  echo "usage: agent.sh <panel_url> <agent_name> <install_token> <agent_ip>" >&2
  exit 1
fi

panel_url=$1
agent_name=$2
install_token=$3
agent_ip=$4

systemctl stop defensia-agent 2>/dev/null || true

install -m0755 /root/defensia-agent /usr/local/bin/defensia-agent
install -m0644 /root/defensia-agent.service /etc/systemd/system/defensia-agent.service

rm -f /etc/defensia/config.json
mkdir -p /etc/defensia

set +e
DEFENSIA_CONFIG=/etc/defensia/config.json AGENT_IP="$agent_ip" \
  /usr/local/bin/defensia-agent register "$panel_url" "$agent_name" "$install_token"
rc=$?
set -e

if [ "$rc" -ne 0 ]; then
  echo "agent.sh: 'defensia-agent register' exited $rc" >&2
  exit "$rc"
fi

if ! grep -q '"agent_id"' /etc/defensia/config.json 2>/dev/null; then
  echo "agent.sh: /etc/defensia/config.json has no agent_id after register" >&2
  exit 1
fi

systemctl daemon-reload
systemctl enable --now defensia-agent

sleep 5
systemctl is-active defensia-agent
