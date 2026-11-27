#!/usr/bin/env bash
# lab/load/handshake.sh — proves the REAL agent daemon (not the
# integration-test's own api.Client) honours the panel's aggregation
# handshake end to end on debian12-nocsf.
#
# IMPORTANT, found live running this leg (2026-11-27): the plan's original
# wording ("60 bot hits -> 60 rows OFF, <=2 rows ON") assumed any
# UA-pattern-matched bot type would collapse once aggregation is ON. That
# is NOT what 19-BASELINE.md/config/event_aggregation.php actually ship:
# the measured, committed production allowlist is `['bot_crawl']` ONLY —
# and internal/watcher/weblog.go only ever emits `bot_crawl` for a bot
# fingerprint match that ALSO passes checkBotFcrdns (a real, external
# forward-confirmed reverse-DNS check against the requesting IP). A lab
# attacker on a TEST-NET-3 alias cannot pass that check honestly (there is
# no DNS record anywhere that would resolve 203.0.113.x to a hostname
# matching a known crawler's domain) — so this lab cannot produce a real
# `bot_crawl` event at all, from either the real daemon or a fabricated
# one, without lying about network identity. Per this plan's own honesty
# requirement, this leg does NOT attempt that — it uses `bot_unknown`
# (a real, structurally-aggregatable candidate type per
# internal/api/eventtypes.go, but one that narrowly missed the AGG-01
# allowlist, see 19-BASELINE.md) and asserts the OPPOSITE of the plan's
# literal wording: `bot_unknown` traffic does NOT collapse even with
# aggregation globally ON, because PanelTypes restricts to `[bot_crawl]`
# only. That is itself a real, valuable proof against the REAL daemon —
# plan 12's "PanelTypes can only restrict, never extend" decision, tested
# here for the first time outside a unit test. The critical (mail
# brute-force) leg and the event_pipeline_stats check are unaffected by
# this and run exactly as planned.
#
# Requires `lab/attack.sh debian12-nocsf prepare` to have run first (this
# script calls it itself if lab/.state/attack.env is missing or stale).
# bash 3.2 safe.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"
set +e

VM="debian12-nocsf"

sql() {
  panel_compose exec -T db mysql -udefensia -psecret defensia_lab -N -e "$1" 2>/dev/null
}

# events_aggregation ARGS... -- see lab/load/run.sh's own copy of this
# comment: BROADCAST_CONNECTION is forced to null for this one call
# because the app container exports it as a real reverb-pointing env
# var that EventAggregationCommand's SyncRequested broadcast cannot
# resolve from inside this lab, which otherwise makes the command exit
# 1 even though the DB override write itself already succeeded.
events_aggregation() {
  panel_compose exec -T -e BROADCAST_CONNECTION=null app php artisan events:aggregation "$@"
}

fail() {
  printf 'HANDSHAKE_FAIL %s\n' "$1"
  events_aggregation --agent="$AGENT_ID" --default >/dev/null 2>&1
  exit 1
}

[ -f "$LAB_DIR/.state/agents/$VM.json" ] || die "handshake: no $LAB_DIR/.state/agents/$VM.json — run 'make lab-up LAB_VMS=$VM' first"
AGENT_ID="$(json_get "$LAB_DIR/.state/agents/$VM.json" agent_id)"
[ -n "$AGENT_ID" ] || die "handshake: could not read agent_id"

BOT_WINDOW_SECONDS="$(json_get "$LAB_DIR/load/profile.json" bot_window_seconds)"
[ -n "$BOT_WINDOW_SECONDS" ] || BOT_WINDOW_SECONDS=60

log "handshake: preparing attack aliases on lab-attacker -> $VM"
"$LAB_DIR/attack.sh" "$VM" prepare || fail "attack.sh prepare failed"
# shellcheck disable=SC1091
source "$LAB_DIR/.state/attack.env"
TARGET_IP="$LAB_ATTACK_TARGET_IP"

# calibration (plan's own escape hatch): if OFF produces 0 bot_unknown
# rows, the lab agent's own WAF config may not have bot_unknown enabled —
# check and fix via tinker, never by touching agent code. Recorded in the
# SUMMARY, not silently patched over.
CALIBRATION_NOTE=""
check_bot_unknown_enabled() {
  panel_compose exec -T app php artisan tinker --execute="
    \$a = \App\Models\Agent::find($AGENT_ID);
    \$w = \$a->waf_config ?? [];
    \$enabled = \$w['enabled_types'] ?? null;
    echo (\$enabled === null || in_array('bot_unknown', \$enabled)) ? 'yes' : 'no';
  " 2>&1 | tail -1
}
enable_bot_unknown() {
  panel_compose exec -T app php artisan tinker --execute="
    \$a = \App\Models\Agent::find($AGENT_ID);
    \$w = \$a->waf_config ?? [];
    if (isset(\$w['enabled_types']) && !in_array('bot_unknown', \$w['enabled_types'])) {
      \$w['enabled_types'][] = 'bot_unknown';
      \$a->update(['waf_config' => \$w]);
      echo 'enabled';
    } else {
      echo 'noop';
    }
  " 2>&1 | tail -1
}

bot_probe() {
  local mode=$1 ip=$2 n=60
  log "handshake: bot probe mode=$mode from $ip -> $TARGET_IP x$n"
  vm_root lab-attacker bash -c "
    for i in \$(seq 1 $n); do
      curl -s -o /dev/null --interface '$ip' --max-time 2 \
        -A 'LabAggBot/1.0 (+bot)' \
        'http://$TARGET_IP/agg-probe-$mode' >/dev/null 2>&1
      sleep 0.2
    done
  "
}

run_mode() {
  local mode=$1 ip=$2 wait_extra=20

  events_aggregation --agent="$AGENT_ID" --"$mode" >/dev/null \
    || fail "events:aggregation --agent=$AGENT_ID --$mode failed"
  vm_root "$VM" systemctl restart defensia-agent || fail "systemctl restart defensia-agent failed on $VM"
  sleep 15 # startup sync

  bot_probe "$mode" "$ip"

  log "handshake: waiting ${BOT_WINDOW_SECONDS}s + ${wait_extra}s for the bot window to close"
  sleep $((BOT_WINDOW_SECONDS + wait_extra))

  local rows occ
  rows="$(sql "SELECT COUNT(*) FROM events WHERE type='bot_unknown' AND source_ip='$ip'")"
  occ="$(sql "SELECT COALESCE(SUM(occurrence_count),0) FROM events WHERE type='bot_unknown' AND source_ip='$ip'")"

  if [ "$mode" = "off" ] && [ "$rows" = "0" ]; then
    CALIBRATION_NOTE="OFF leg produced 0 bot_unknown rows for a fresh IP — checking agent WAF config"
    local status
    status="$(check_bot_unknown_enabled)"
    if [ "$status" = "no" ]; then
      CALIBRATION_NOTE="$CALIBRATION_NOTE; bot_unknown was disabled in waf_config.enabled_types — enabling it ($(enable_bot_unknown)) and retrying this leg"
      vm_root "$VM" systemctl restart defensia-agent
      sleep 15
      bot_probe "$mode" "$ip"
      sleep $((BOT_WINDOW_SECONDS + wait_extra))
      rows="$(sql "SELECT COUNT(*) FROM events WHERE type='bot_unknown' AND source_ip='$ip'")"
      occ="$(sql "SELECT COALESCE(SUM(occurrence_count),0) FROM events WHERE type='bot_unknown' AND source_ip='$ip'")"
    else
      CALIBRATION_NOTE="$CALIBRATION_NOTE; bot_unknown already enabled (status=$status) — 0 rows is a real finding, not a config gap"
    fi
  fi

  printf '%s %s\n' "$rows" "$occ"
}

log "handshake: mode=off"
read -r rows_off occ_off <<<"$(run_mode off "$LAB_ATTACK_SSH_IP")"
[ "$rows_off" = "60" ] && [ "$occ_off" = "60" ] || fail "off: rows=$rows_off occ=$occ_off, want rows=60 occ=60"

log "handshake: mode=on"
read -r rows_on occ_on <<<"$(run_mode on "$LAB_ATTACK_WEB_IP")"
# bot_unknown is NOT in the production allowlist ([bot_crawl] only, see
# this file's header) -- the correct, honest expectation under ON is that
# it still does not collapse (PanelTypes restricts, never extends). A
# rows_on of 60 here is a PASS; a rows_on < 60 would mean PanelTypes
# leaked past its own restriction and is the real failure to catch.
[ "$rows_on" = "60" ] && [ "$occ_on" = "60" ] || fail "on: rows=$rows_on occ=$occ_on, want rows=60 occ=60 (bot_unknown is not allowlisted; it must stay unaggregated even with aggregation globally ON)"

log "handshake: critical leg (mail brute-force) under on"
"$LAB_DIR/attack.sh" "$VM" mail || fail "attack.sh mail leg failed"
sleep 10
mail_rows="$(sql "SELECT COUNT(*) FROM events WHERE type='mail_brute_force' AND source_ip='$LAB_ATTACK_MAIL_IP'")"
mail_bad="$(sql "SELECT COUNT(*) FROM events WHERE type='mail_brute_force' AND source_ip='$LAB_ATTACK_MAIL_IP' AND occurrence_count<>1")"
[ -n "$mail_rows" ] && [ "$mail_rows" -ge 5 ] 2>/dev/null || fail "mail leg: rows=$mail_rows, want >=5"
[ "$mail_bad" = "0" ] || fail "mail leg: $mail_bad rows with occurrence_count<>1 (critical must stay individual)"

log "handshake: waiting for one heartbeat (<=90s) with event_pipeline_stats"
pipeline_ok=""
waited=0
while [ "$waited" -lt 90 ]; do
  enabled="$(sql "SELECT JSON_EXTRACT(event_pipeline_stats,'\$.aggregation_enabled') FROM agents WHERE id=$AGENT_ID")"
  dqf="$(sql "SELECT COALESCE(JSON_EXTRACT(event_pipeline_stats,'\$.dropped_queue_full'),0) FROM agents WHERE id=$AGENT_ID")"
  dsf="$(sql "SELECT COALESCE(JSON_EXTRACT(event_pipeline_stats,'\$.dropped_send_failed'),0) FROM agents WHERE id=$AGENT_ID")"
  drj="$(sql "SELECT COALESCE(JSON_EXTRACT(event_pipeline_stats,'\$.dropped_rejected'),0) FROM agents WHERE id=$AGENT_ID")"
  if [ "$enabled" = "true" ] && [ "$((dqf + dsf + drj))" = "0" ]; then
    pipeline_ok="yes"
    break
  fi
  sleep 5
  waited=$((waited + 5))
done
[ "$pipeline_ok" = "yes" ] || fail "event_pipeline_stats did not report aggregation_enabled=true with zero drops within 90s (last: enabled=$enabled dqf=$dqf dsf=$dsf drj=$drj)"

events_aggregation --agent="$AGENT_ID" --default >/dev/null 2>&1

if [ -n "$CALIBRATION_NOTE" ]; then
  printf 'HANDSHAKE_CALIBRATION %s\n' "$CALIBRATION_NOTE"
fi
printf 'HANDSHAKE_NOTE bot_crawl (the only allowlisted type) requires real FCrDNS-verified crawler identity and cannot be honestly produced by a lab attacker; bot_unknown is used instead to prove PanelTypes restrict-only semantics against the real daemon (expected+observed: no collapse in either mode)\n'
printf 'HANDSHAKE_OK off_rows=%s off_occ=%s on_rows=%s on_occ=%s mail_rows=%s mail_bad=%s\n' \
  "$rows_off" "$occ_off" "$rows_on" "$occ_on" "$mail_rows" "$mail_bad"
exit 0
