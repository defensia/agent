#!/usr/bin/env bash
# lab/sot/api.sh — Sanctum API helpers for the CSF source-of-truth lab
# stages (lab/sot-stages.sh). Sourced (bash 3.2 compatible, no arrays,
# no associative arrays), after lab/lib.sh + lab/matrix.sh. Every HTTP
# call reuses lib.sh's own panel_get/panel_post/panel_delete (Bearer
# token, body-visible-on-error contract) -- this file is a thin,
# SOT/template-specific naming layer over those, not a parallel HTTP
# client.
#
# Routes (panel, Sanctum v1, from routes/api.php):
#   GET  /api/v1/servers/{agent}/csf/sot
#   POST /api/v1/servers/{agent}/csf/sot/{activate|exit|accept|revert|correction|resume|retry}
#   POST /api/v1/csf/templates ; DELETE /api/v1/csf/templates/{id}
#   POST /api/v1/csf/templates/{id}/preview ; POST /api/v1/csf/templates/{id}/rollouts
#   GET  /api/v1/csf/rollouts/{id} ; POST /api/v1/csf/rollouts/{id}/{stop|resume|close}

# agent_id_of VM — reads the agent_id lib.sh's own install_agent records
# at $STATE_DIR/agents/<vm>.json ({"vm":"...","agent_id":N}) when that
# cache exists; falls back to a direct panel DB lookup otherwise (the
# cache is only ever written on a (re)register, not on every lab run --
# a VM whose agent has never needed reinstalling since the state dir was
# last cleared has no cache file at all).
agent_id_of() {
  local vm=$1
  if [ -f "$STATE_DIR/agents/$vm.json" ]; then
    json_get "$STATE_DIR/agents/$vm.json" agent_id
    return 0
  fi
  panel_tinker "echo App\Models\Agent::where('name', '$vm')->value('id');" 2>&1 | tail -1
}

# sot_get AGENT_ID [JSONPATH] — GET the CSF SOT state. With no JSONPATH,
# prints the raw JSON body. With JSONPATH, prints just that dotted-path
# value (lib.sh's own json_get semantics) extracted from the body.
sot_get() {
  local agent_id=$1 path=${2:-} tmp body
  body="$(panel_get "/api/v1/servers/$agent_id/csf/sot")" || return 1
  if [ -z "$path" ]; then
    printf '%s' "$body"
    return 0
  fi
  tmp="$(mktemp)"
  printf '%s' "$body" >"$tmp"
  json_get "$tmp" "$path"
  rm -f "$tmp"
}

# sot_post AGENT_ID ACTION [JSON] — POST one of the 7 write actions.
# JSON defaults to "{}" (activate/exit/revert/resume/retry take no
# body; accept takes {observed_hash}; correction takes {mode}). Prints
# the response body (write actions wrap the state in {"state": {...}}).
sot_post() {
  local agent_id=$1 action=$2 json=${3:-"{}"}
  panel_post "/api/v1/servers/$agent_id/csf/sot/$action" "$json"
}

# wait_sot AGENT_ID PYTHON_EXPR TIMEOUT_S — polls sot_get every 5s (first
# check immediate, no up-front sleep) until PYTHON_EXPR evaluates truthy
# against the parsed JSON body (bound to the name `state` in the expr's
# scope) or TIMEOUT_S elapses. Prints the last raw body it saw on
# failure (for diagnostics) and returns 1; returns 0 silently on success.
wait_sot() {
  local agent_id=$1 expr=$2 timeout=$3 waited=0 body ok
  while :; do
    body="$(sot_get "$agent_id")"
    ok="$(printf '%s' "$body" | python3 -c "
import json, sys
state = json.load(sys.stdin)
try:
    print('true' if (${expr}) else 'false')
except Exception as e:
    print('false')
" 2>/dev/null)"
    if [ "$ok" = "true" ]; then
      return 0
    fi
    if [ "$waited" -ge "$timeout" ]; then
      printf '%s\n' "$body" >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

# file_fp VM PATH — prints "<sha256> <mtime_ns>" for PATH on VM, via
# GNU coreutils `stat -c %.9Y` (nanosecond mtime; present on every lab
# image -- AlmaLinux 8/9/10 and Debian 12 all ship GNU stat). Used for
# every "byte- and mtime-identical" assertion in lab/sot-stages.sh: a
# sha256-only check cannot see a saveconf-style rewrite-with-identical-
# bytes-but-touched-mtime, which several sot-* stages must distinguish
# from "unexpectedly rewritten".
file_fp() {
  local vm=$1 path=$2
  vm_root "$vm" sh -c "sha256sum '$path' | awk '{print \$1}' | tr -d '\n'; printf ' '; stat -c '%.9Y' '$path'"
}

# tpl_create NAME PORTS_JSON — POST /api/v1/csf/templates, PORTS_JSON is
# the raw `{"TCP_IN": {"ensure_open": [...], "ensure_closed": [...]}, ...}`
# object (CsfTemplateService::create's exact expected shape). Prints the
# new template's id.
tpl_create() {
  local name=$1 ports_json=$2 tmp id
  tmp="$(mktemp)"
  panel_post "/api/v1/csf/templates" "{\"name\":\"$name\",\"ports\":$ports_json}" >"$tmp" || { cat "$tmp" >&2; rm -f "$tmp"; return 1; }
  id="$(json_get "$tmp" id)"
  rm -f "$tmp"
  printf '%s' "$id"
}

# tpl_delete TEMPLATE_ID — DELETE /api/v1/csf/templates/{id}.
tpl_delete() {
  local id=$1
  panel_delete "/api/v1/csf/templates/$id" >/dev/null
}

# tpl_preview TEMPLATE_ID AGENT_IDS_JSON — POST .../preview with
# {"agent_ids": AGENT_IDS_JSON}. AGENT_IDS_JSON is a JSON array literal,
# e.g. "[3,5,9]". Prints the raw response body.
tpl_preview() {
  local id=$1 agent_ids_json=$2
  panel_post "/api/v1/csf/templates/$id/preview" "{\"agent_ids\":$agent_ids_json}"
}

# rollout_start TEMPLATE_ID AGENT_IDS_JSON — POST .../rollouts with
# {"agent_ids": AGENT_IDS_JSON}. Prints the new rollout's id.
rollout_start() {
  local id=$1 agent_ids_json=$2 tmp rollout_id
  tmp="$(mktemp)"
  panel_post "/api/v1/csf/templates/$id/rollouts" "{\"agent_ids\":$agent_ids_json}" >"$tmp" || { cat "$tmp" >&2; rm -f "$tmp"; return 1; }
  rollout_id="$(json_get "$tmp" rollout_id)"
  rm -f "$tmp"
  printf '%s' "$rollout_id"
}

# rollout_get ROLLOUT_ID [JSONPATH] — GET /api/v1/csf/rollouts/{id}. With
# no JSONPATH, prints the raw body; with JSONPATH, extracts just that
# dotted-path value.
rollout_get() {
  local rollout_id=$1 path=${2:-} tmp body
  body="$(panel_get "/api/v1/csf/rollouts/$rollout_id")" || return 1
  if [ -z "$path" ]; then
    printf '%s' "$body"
    return 0
  fi
  tmp="$(mktemp)"
  printf '%s' "$body" >"$tmp"
  json_get "$tmp" "$path"
  rm -f "$tmp"
}

# wait_rollout ROLLOUT_ID PYTHON_EXPR TIMEOUT_S — same polling contract
# as wait_sot, against rollout_get's body (bound to `state`).
wait_rollout() {
  local rollout_id=$1 expr=$2 timeout=$3 waited=0 body ok
  while :; do
    body="$(rollout_get "$rollout_id")"
    ok="$(printf '%s' "$body" | python3 -c "
import json, sys
state = json.load(sys.stdin)
try:
    print('true' if (${expr}) else 'false')
except Exception as e:
    print('false')
" 2>/dev/null)"
    if [ "$ok" = "true" ]; then
      return 0
    fi
    if [ "$waited" -ge "$timeout" ]; then
      printf '%s\n' "$body" >&2
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

# rollout_action ROLLOUT_ID ACTION — POST /api/v1/csf/rollouts/{id}/{action}
# (stop|resume|close). Prints the raw response body ({"rollout": {...}}).
rollout_action() {
  local rollout_id=$1 action=$2
  panel_post "/api/v1/csf/rollouts/$rollout_id/$action" "{}"
}

# audit_actions AGENT_ID — the last 50 csf_sot_*/csf_rollout_* audit_logs
# rows for AGENT_ID, oldest first, as a JSON array of {action,properties}
# (lab DB only -- panel_tinker itself refuses against anything else).
audit_actions() {
  local agent_id=$1
  panel_tinker "
\$rows = App\Models\AuditLog::where('agent_id', $agent_id)
  ->where(function (\$q) { \$q->where('action', 'like', 'csf_sot_%')->orWhere('action', 'like', 'csf_rollout_%'); })
  ->oldest('id')->take(50)->get(['action', 'properties']);
echo json_encode(\$rows);
" 2>&1 | tail -1
}

# wait_audit AGENT_ID ACTION TIMEOUT_S — polls audit_actions every 5s
# until ACTION appears anywhere in the (last 50) rows, or TIMEOUT_S
# elapses. Events reach audit_logs via the agent's own async event
# queue (internal/api/client.go's QueueEvent -> a buffered channel
# flushed by a separate goroutine on its own schedule, not
# synchronously with the API call that triggered them), so a caller
# that just saw a status transition land must still allow a short
# settle window before the matching audit row is guaranteed to exist.
wait_audit() {
  local agent_id=$1 action=$2 timeout=$3 waited=0
  while :; do
    if audit_actions "$agent_id" | grep -q "$action"; then
      return 0
    fi
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

# wait_audit_grep AGENT_ID PATTERN TIMEOUT_S — same polling contract as
# wait_audit, but checks for an arbitrary grep PATTERN anywhere in the
# raw audit_actions JSON (action name AND properties both searchable in
# one call) -- for asserting a SPECIFIC reason/detail combination
# (e.g. an "ssh_port_in_use" refusal, not just any csf_sot_refused row),
# since the window where a live Report's own `refused` array would show
# that same combination can be as short as one lab-sped-up tick (the
# NEXT cycle's refusal/paused_conflict transition overwrites it), while
# the audit_logs row persists.
wait_audit_grep() {
  local agent_id=$1 pattern=$2 timeout=$3 waited=0
  while :; do
    if audit_actions "$agent_id" | grep -q -- "$pattern"; then
      return 0
    fi
    if [ "$waited" -ge "$timeout" ]; then
      return 1
    fi
    sleep 5
    waited=$((waited + 5))
  done
}

# audit_rollout_actions ROLLOUT_ID — the audit_logs rows for a rollout
# itself (csf_rollout_started/halted/completed/stopped/resumed/closed
# are logged with subject_type=CsfTemplateRollout, agent_id=null --
# NOT reachable via audit_actions, which filters by agent_id).
audit_rollout_actions() {
  local rollout_id=$1
  panel_tinker "
\$rows = App\Models\AuditLog::where('subject_type', 'CsfTemplateRollout')->where('subject_id', $rollout_id)
  ->oldest('id')->take(50)->get(['action', 'properties']);
echo json_encode(\$rows);
" 2>&1 | tail -1
}

# audit_count AGENT_ID ACTION SINCE_EPOCH — counts audit_logs rows for
# AGENT_ID with this exact ACTION created at or after SINCE_EPOCH (unix
# seconds) -- used by sot-auto to count automatic corrections without
# re-parsing the full audit_actions array in bash.
audit_count() {
  local agent_id=$1 action=$2 since=$3
  panel_tinker "
echo App\Models\AuditLog::where('agent_id', $agent_id)->where('action', '$action')
  ->where('created_at', '>=', date('Y-m-d H:i:s', $since))->count();
" 2>&1 | tail -1
}
