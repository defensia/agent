#!/usr/bin/env bash
# lab/verify.sh [vm...]
#
# Health gate for the Phase 14 CSF test lab: VM-level (exists, reachable,
# systemd state, has an IPv4) + CSF-level (csf -v matches the fork's
# expected version, csf/lfd active per lab/matrix.sh, TESTING flag,
# panel-allow, orphan downloadservers/sinkhole) + ipset/no-csf/attacker
# tooling expectations. Prints "PASS <vm> <check>" / "FAIL <vm> <check>:
# <reason>" per check and "verify: N checks, F failures" at the end. Exits
# non-zero if any check failed — this must catch a broken lab BEFORE a
# later test blames the agent code for it. Default VMs: $LAB_VMS.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"

vms="$*"
[ -n "$vms" ] || vms="$LAB_VMS"

preflight_orb

CHECKS=0
FAILS=0

pass() { CHECKS=$((CHECKS + 1)); printf 'PASS %s %s\n' "$1" "$2"; }
fail() { CHECKS=$((CHECKS + 1)); FAILS=$((FAILS + 1)); printf 'FAIL %s %s: %s\n' "$1" "$2" "$3"; }

# vm_root_out VM cmd... — like vm_root but captures stdout without ever
# tripping `set -e` at the call site (always pair with `|| true` there).
vm_root_out() {
  local vm=$1
  shift
  orb -m "$vm" -u root "$@" 2>/dev/null
}

check_vm_level() {
  local vm=$1 state ip

  if vm_exists "$vm"; then
    pass "$vm" "vm-exists"
  else
    fail "$vm" "vm-exists" "orbctl info $vm failed (VM missing)"
    return 1
  fi

  if vm_root "$vm" true >/dev/null 2>&1; then
    pass "$vm" "vm-reachable"
  else
    fail "$vm" "vm-reachable" "vm_root $vm true failed"
    return 1
  fi

  state="$(vm_root_out "$vm" systemctl is-system-running || true)"
  case "$state" in
    running|degraded) pass "$vm" "systemd-state" ;;
    *) fail "$vm" "systemd-state" "systemctl is-system-running = '$state' (expected running|degraded)" ;;
  esac

  ip="$(vm_ip "$vm" 2>/dev/null || true)"
  if [ -n "$ip" ]; then
    pass "$vm" "ipv4"
  else
    fail "$vm" "ipv4" "vm_ip $vm returned empty"
  fi

  return 0
}

check_csf_level() {
  local vm=$1 role regex lfd_expect testing_expect csfv lfd_state
  role="$(vm_role "$vm")"
  regex="$(vm_csfv_regex "$vm")"
  lfd_expect="$(vm_lfd "$vm")"
  testing_expect="$(vm_testing "$vm")"

  csfv="$(vm_root_out "$vm" csf -v || true)"
  if printf '%s' "$csfv" | grep -Eq "$regex"; then
    pass "$vm" "csf-version"
  else
    fail "$vm" "csf-version" "csf -v = '$csfv' does not match /$regex/"
  fi

  if [ "$(vm_root_out "$vm" systemctl is-active csf || true)" = "active" ]; then
    pass "$vm" "csf-active"
  else
    fail "$vm" "csf-active" "systemctl is-active csf != active"
  fi

  lfd_state="$(vm_root_out "$vm" systemctl is-active lfd || true)"
  if [ "$lfd_state" = "$lfd_expect" ]; then
    pass "$vm" "lfd"
  else
    fail "$vm" "lfd" "systemctl is-active lfd = '$lfd_state' (expected $lfd_expect)"
  fi

  if vm_root "$vm" bash -c "grep -Eq '^TESTING = \"$testing_expect\"' /etc/csf/csf.conf" >/dev/null 2>&1; then
    pass "$vm" "testing-flag"
  else
    fail "$vm" "testing-flag" "TESTING != \"$testing_expect\" in /etc/csf/csf.conf"
  fi

  if vm_root "$vm" grep -q 'lab-panel' /etc/csf/csf.allow >/dev/null 2>&1; then
    pass "$vm" "panel-allow"
  else
    fail "$vm" "panel-allow" "csf.allow has no lab-panel entry"
  fi

  if [ "$role" = "csf-orphan" ]; then
    if vm_root "$vm" bash -c "grep -Ev '^[[:space:]]*#' /etc/csf/downloadservers 2>/dev/null | grep -q download.configserver.com" >/dev/null 2>&1; then
      pass "$vm" "orphan-downloadservers"
    else
      fail "$vm" "orphan-downloadservers" "downloadservers does not point at configserver.com"
    fi

    if vm_root "$vm" grep -q 'download.configserver.com' /etc/hosts >/dev/null 2>&1; then
      pass "$vm" "orphan-sinkhole"
    else
      fail "$vm" "orphan-sinkhole" "/etc/hosts has no sinkhole for configserver.com"
    fi
  fi
}

check_ipset() {
  local vm=$1 expect
  expect="$(vm_ipset "$vm")"
  if [ "$expect" = "yes" ]; then
    if vm_root "$vm" command -v ipset >/dev/null 2>&1; then
      pass "$vm" "ipset-present"
    else
      fail "$vm" "ipset-present" "ipset expected (vm_ipset=yes) but command -v ipset failed"
    fi
  else
    if vm_root "$vm" command -v ipset >/dev/null 2>&1; then
      fail "$vm" "ipset-absent" "ipset NOT expected (vm_ipset=no) but command -v ipset succeeded"
    else
      pass "$vm" "ipset-absent"
    fi
  fi
}

check_nocsf() {
  local vm=$1
  if vm_root "$vm" command -v csf >/dev/null 2>&1; then
    fail "$vm" "no-csf" "csf unexpectedly present"
  else
    pass "$vm" "no-csf"
  fi
}

check_attacker_tools() {
  local vm=$1 tool
  for tool in sshpass curl python3; do
    if vm_root "$vm" command -v "$tool" >/dev/null 2>&1; then
      pass "$vm" "attacker-$tool"
    else
      fail "$vm" "attacker-$tool" "$tool not found"
    fi
  done
}

for vm in $vms; do
  if ! check_vm_level "$vm"; then
    continue
  fi

  role="$(vm_role "$vm")"
  case "$role" in
    csf|csf-orphan)
      check_csf_level "$vm"
      check_ipset "$vm"
      ;;
    attack-target)
      check_nocsf "$vm"
      check_ipset "$vm"
      ;;
    attacker)
      check_attacker_tools "$vm"
      ;;
  esac
done

# --- panel + agent checks (plan 05) ---

# Overridable so the outbound-env canary negative test can inject a
# non-empty key (e.g. POSTHOG_API_KEY) without touching the running
# container's real environment. Evaluated with `eval`, so it may contain
# extra flags (docker compose exec -e KEY=VAL ...).
AUDIT_CMD="${LAB_ENV_AUDIT_CMD:-panel_compose exec -T app php docker/lab/env-audit.php}"

# lookup_last_seen AGENT_ID SERVERS_FILE — last_seen_at for AGENT_ID from an
# already-fetched /api/v1/servers response, or "" if absent/empty/unparsable.
lookup_last_seen() {
  python3 -c "
import json
try:
    with open('$2') as f:
        data = json.load(f)
    for a in data.get('data', []):
        if str(a.get('id')) == '$1':
            print(a.get('last_seen_at') or '')
            break
except Exception:
    pass
" 2>/dev/null || true
}

# check_agent_heartbeat VM SERVERS_FILE — agent-active, VM-reaches-panel,
# heartbeat freshness (<=180s, from the already-fetched /api/v1/servers
# response) and no panic: in the agent's last 15 min of journal.
#
# [reverb]/[ws] connect-refused/reconnect lines are EXPECTED here (the lab
# sets no REVERB_* env, so AgentController hands back an empty/host-less
# Reverb URL and the agent falls back to its /sync ticker — see
# 14-05-PLAN.md interfaces) and are never part of this grep or any other
# check below; only a literal "panic:" counts as a failure.
check_agent_heartbeat() {
  local vm=$1 servers_file=$2 agent_active vm_panel_code agent_id last_seen age panics

  agent_active="$(vm_root_out "$vm" systemctl is-active defensia-agent || true)"
  if [ "$agent_active" = "active" ]; then
    pass "$vm" "agent active"
  else
    fail "$vm" "agent active" "systemctl is-active defensia-agent = '$agent_active' (expected active)"
  fi

  vm_panel_code="$(vm_root_out "$vm" curl -s -o /dev/null -w '%{http_code}' "$PANEL_URL_VM/up" || true)"
  if [ "$vm_panel_code" = "200" ]; then
    pass "$vm" "vm-reaches-panel"
  else
    fail "$vm" "vm-reaches-panel" "curl $PANEL_URL_VM/up from $vm = '$vm_panel_code' (expected 200)"
  fi

  agent_id="$(config_agent_id "$vm")"
  if [ -z "$agent_id" ]; then
    fail "$vm" "heartbeat" "no agent_id in /etc/defensia/config.json"
  else
    last_seen="$(lookup_last_seen "$agent_id" "$servers_file")"

    # One retry, not a silent pass: a single-shot GET /api/v1/servers can
    # race a concurrent heartbeat write for this exact agent (observed live
    # on 2026-11-05: agent heartbeats landed every ~60s with 200 OK and zero
    # errors throughout the surrounding window, yet one verify.sh snapshot
    # still saw an empty last_seen_at for that one agent) — re-fetching
    # once after a short pause tells a genuine one-off race apart from a
    # truly stale/dead agent, which must still fail. This is a gate
    # robustness fix, not a product behavior change (see phase 14 plan 10
    # SUMMARY for the live evidence).
    if [ -z "$last_seen" ]; then
      sleep 3
      panel_get /api/v1/servers >"$servers_file" 2>/dev/null || true
      last_seen="$(lookup_last_seen "$agent_id" "$servers_file")"
    fi

    if [ -z "$last_seen" ]; then
      fail "$vm" "heartbeat" "agent id $agent_id not found in /api/v1/servers, or last_seen_at empty (retried once)"
    else
      age="$(python3 -c "
from datetime import datetime, timezone
s = '$last_seen'.replace('Z', '+00:00')
try:
    t = datetime.fromisoformat(s)
    print(int((datetime.now(timezone.utc) - t).total_seconds()))
except Exception:
    print(999999)
" 2>/dev/null || echo 999999)"

      if [ "$age" -le 180 ] 2>/dev/null; then
        pass "$vm" "heartbeat (${age}s)"
      else
        fail "$vm" "heartbeat" "last_seen_at age=${age}s > 180s (or unparsable: '$last_seen')"
      fi
    fi
  fi

  panics="$(vm_root_out "$vm" journalctl -u defensia-agent --since '-15 min' --no-pager 2>/dev/null | { grep -c 'panic:' || true; })"
  if [ "${panics:-0}" -eq 0 ] 2>/dev/null; then
    pass "$vm" "agent-journal-no-panic"
  else
    fail "$vm" "agent-journal-no-panic" "$panics 'panic:' line(s) in the last 15 min (excluding [reverb]/[ws] noise, which is expected)"
  fi
}

panel_http_code="$(curl -s -o /dev/null -w '%{http_code}' "$PANEL_URL_HOST/up" 2>/dev/null || true)"
if [ "$panel_http_code" = "200" ]; then
  pass "panel" "up"
else
  fail "panel" "up" "GET $PANEL_URL_HOST/up = '$panel_http_code' (expected 200)"
fi

if [ "$panel_http_code" = "200" ]; then
  safety_json="$(panel_bootstrap 2>/dev/null || true)"
  if [ -n "$safety_json" ]; then
    mail_default="$(json_get "$STATE_DIR/panel.json" mail_default)"
    latest_agent_version="$(json_get "$STATE_DIR/panel.json" latest_agent_version)"
    db_database="$(json_get "$STATE_DIR/panel.json" db_database)"
    app_env="$(json_get "$STATE_DIR/panel.json" app_env)"

    if [ "$mail_default" = "log" ]; then
      pass "panel" "safety mail_default"
    else
      fail "panel" "safety mail_default" "mail_default='$mail_default' (expected log)"
    fi

    if [ -z "$latest_agent_version" ]; then
      pass "panel" "safety latest_agent_version"
    else
      fail "panel" "safety latest_agent_version" "latest_agent_version='$latest_agent_version' (expected empty)"
    fi

    if [ "$db_database" = "defensia_lab" ]; then
      pass "panel" "safety db_database"
    else
      fail "panel" "safety db_database" "db_database='$db_database' (expected defensia_lab)"
    fi

    if [ "$app_env" != "production" ]; then
      pass "panel" "safety app_env"
    else
      fail "panel" "safety app_env" "app_env='$app_env' (must not be production)"
    fi
  else
    fail "panel" "safety mail_default" "lab:bootstrap produced no output"
    fail "panel" "safety latest_agent_version" "lab:bootstrap produced no output"
    fail "panel" "safety db_database" "lab:bootstrap produced no output"
    fail "panel" "safety app_env" "lab:bootstrap produced no output"
  fi

  # Assignment + exit-code capture must happen inside an `if` condition, not
  # as a bare `var=$(...)` statement: under `set -e` a failing command
  # substitution in a plain assignment aborts the whole script immediately
  # (the canary negative test below is exactly the case that hits this -
  # env-audit.php legitimately exits 1 when it finds a leaked key).
  if audit_out="$(eval "$AUDIT_CMD" 2>&1)"; then
    audit_rc=0
  else
    audit_rc=$?
  fi
  if [ "$audit_rc" -eq 0 ]; then
    checked="$(printf '%s' "$audit_out" | tail -1 | python3 -c '
import sys, json
try:
    print(json.load(sys.stdin).get("checked", "?"))
except Exception:
    print("?")
' 2>/dev/null || echo '?')"
    pass "panel" "safety outbound-env ($checked keys empty)"
  else
    leaked="$(printf '%s' "$audit_out" | tail -1 | python3 -c '
import sys, json
try:
    print(" ".join(json.load(sys.stdin).get("non_empty", [])))
except Exception:
    print("parse error")
' 2>/dev/null || echo 'parse error')"
    fail "panel" "safety outbound-env" "$leaked"
  fi

  servers_file="$STATE_DIR/servers.json"
  if panel_get /api/v1/servers >"$servers_file" 2>/dev/null; then
    for vm in $vms; do
      [ "$(vm_has_agent "$vm")" = "yes" ] || continue
      check_agent_heartbeat "$vm" "$servers_file"
    done
  else
    for vm in $vms; do
      [ "$(vm_has_agent "$vm")" = "yes" ] || continue
      fail "$vm" "heartbeat" "GET /api/v1/servers failed"
    done
  fi
else
  # Panel is down: still count (and FAIL) the heartbeat check for every
  # applicable VM rather than silently skipping it.
  for vm in $vms; do
    [ "$(vm_has_agent "$vm")" = "yes" ] || continue
    fail "$vm" "heartbeat" "panel unreachable ($PANEL_URL_HOST/up = '$panel_http_code'), skipped"
  done
fi

printf 'verify: %s checks, %s failures\n' "$CHECKS" "$FAILS"
[ "$FAILS" -eq 0 ]
