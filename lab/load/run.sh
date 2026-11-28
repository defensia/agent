#!/usr/bin/env bash
# lab/load/run.sh — AGG-05 lab load proof (19-13-PLAN.md): replays one
# virtual server-day of profile-shaped synthetic traffic (lab/load/profile.json,
# the AGG-01 baseline) through the real agent/panel pipeline three times
# from the SAME seed — aggregation off, on, and a worst-case IP-rotating
# burst — and proves (via direct DB assertions, not test-binary-reported
# numbers alone) zero event loss, zero critical loss, and a row reduction
# at or above profile.json's own measured target.
#
# bash 3.2 safe (macOS ships 3.2): no associative arrays, no mapfile.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"
# lib.sh/matrix.sh each `set -euo pipefail` when sourced — turn -e back
# off, same reason as lab/test.sh/lab/attack.sh: one mode's failure must
# not abort the loop before the report captures every mode tried, and the
# restart-daemon trap below must still run on any failure path.
set +e

VM="debian12-nocsf"

preflight_orb

# --- Locked never-aggregate types (mirrors internal/api/eventtypes.go's
# lockedNeverAggregate — see loadgen.go's own comment on why this is a
# hand-kept copy, not an import) -- used by crit_bad's SQL below.
LOCKED_TYPES_SQL="'malware_realtime','malware_blocked','malware_quarantined','malware_scan_started','malware_scan_progress','malware_scan_completed','rce_attempt','web_shell','ban_created','sigma_detection'"

log "lab-load: building agent + integration binaries"
(cd "$REPO_DIR" && make lab-build) || die "lab-load: make lab-build failed"

BINARY="$REPO_DIR/build/integration-linux-$LAB_ARCH.test"
[ -f "$BINARY" ] || die "lab-load: integration binary missing: $BINARY"

vm_push "$VM" "$BINARY" /root/integration.test
vm_push "$VM" "$LAB_DIR/load/profile.json" /root/load-profile.json

[ -f "$LAB_DIR/.state/agents/$VM.json" ] || die "lab-load: no $LAB_DIR/.state/agents/$VM.json — run 'make lab-up LAB_VMS=$VM' first"
AGENT_ID="$(json_get "$LAB_DIR/.state/agents/$VM.json" agent_id)"
[ -n "$AGENT_ID" ] || die "lab-load: could not read agent_id from $LAB_DIR/.state/agents/$VM.json"

TARGET_REDUCTION_PCT="$(json_get "$LAB_DIR/load/profile.json" target_reduction_pct)"
[ -n "$TARGET_REDUCTION_PCT" ] || die "lab-load: profile.json has no target_reduction_pct"

# sql QUERY — runs QUERY against the lab's own defensia_lab database,
# refusing to run anywhere else (the one DB-destructive guard this script
# needs: a wrong DB_DATABASE here would mean every assertion below is
# silently checking the wrong table).
sql() {
  panel_compose exec -T db mysql -udefensia -psecret defensia_lab -N -e "$1" 2>/dev/null
}
db_name="$(sql 'SELECT DATABASE()')"
[ "$db_name" = "defensia_lab" ] || die "lab-load: sql() returned database '$db_name', expected defensia_lab — refusing to run"

# events_aggregation ARGS... — `php artisan events:aggregation`, with
# BROADCAST_CONNECTION forced to null for this one call. Measured in this
# lab: the app container exports BROADCAST_CONNECTION=reverb as a real
# env var (not overridable from phpunit.xml/.env alone), and
# EventAggregationCommand's own SyncRequested broadcast then throws
# "cURL error 6: Could not resolve host: reverb" from inside this CLI
# container — the DB override write itself already succeeded by the time
# that throw happens (observed: agents.event_aggregation_enabled is
# correctly set even on the exit-1 path), but a non-zero exit from this
# helper would otherwise abort every mode below. -e here is a docker
# compose exec flag, not a shell export — it only affects this one
# container invocation.
events_aggregation() {
  panel_compose exec -T -e BROADCAST_CONNECTION=null app php artisan events:aggregation "$@"
}

# --- Stop the real daemon for the duration of the synthetic replay: its
# own heartbeat/sync/event traffic must not mix with this run's rows, and
# its own aggregation-enabled state would otherwise race this script's
# own events:aggregation toggles. Restarted unconditionally on exit (trap),
# including on any failure path, by `set +e` + explicit restart calls
# below rather than relying on EXIT alone (vm_root can itself partially
# fail mid-trap on some shells) -- ERR is not used here since `set +e`
# means no implicit exit trip point exists to guard; the pattern is:
# function does the work and body itself calls restart_daemon on every
# exit route.
restart_daemon() {
  vm_root "$VM" systemctl start defensia-agent >/dev/null 2>&1
}
trap restart_daemon EXIT

log "lab-load: stopping real daemon on $VM for the duration of the replay"
vm_root "$VM" systemctl stop defensia-agent

TS="$(date +%Y-%m-%d-%H%M%S)"
REPORT="$LAB_DIR/reports/$TS-load.md"
mkdir -p "$LAB_DIR/reports/raw"

AGENT_SHA="$(git -C "$REPO_DIR" rev-parse --short HEAD)"
[ -z "$(git -C "$REPO_DIR" status --porcelain)" ] || AGENT_SHA="$AGENT_SHA-dirty"
PANEL_SHA="$(git -C "$PANEL_DIR" rev-parse --short HEAD)"
[ -z "$(git -C "$PANEL_DIR" status --porcelain)" ] || PANEL_SHA="$PANEL_SHA-dirty"
PROFILE_SOURCE="$(json_get "$LAB_DIR/load/profile.json" source)"

{
  printf '# AGG-05 load report %s\n\n' "$TS"
  printf -- '- agent: %s\n' "$AGENT_SHA"
  printf -- '- panel: %s\n' "$PANEL_SHA"
  printf -- '- profile: %s\n' "$PROFILE_SOURCE"
  printf -- '- target_reduction_pct: %s\n\n' "$TARGET_REDUCTION_PCT"
  printf '| mode | generated | criticals | rows | SUM(occurrence_count) | rollup rows | HTTP batches | retries | dropped | agent cpu ms | agent rss kb | php-fpm cpu avg %% | result |\n'
  printf '|------|-----------|-----------|------|------------------------|-------------|--------------|---------|---------|--------------|--------------|--------------------|--------|\n'
} >"$REPORT"

APP_CONTAINER="$(panel_compose ps -q app)"

overall_result="PASS"
rows_off=""
reduction_line=""
burst_reduction_line=""

for MODE in off on burst; do
  if [ "$MODE" = "off" ]; then
    agg_flag="--off"
  else
    agg_flag="--on"
  fi
  events_aggregation --agent="$AGENT_ID" "$agg_flag" >/dev/null \
    || die "lab-load: events:aggregation --agent=$AGENT_ID $agg_flag failed"

  RUN="agg19-$MODE-$(date +%s)"
  RAW="$LAB_DIR/reports/raw/$TS-load-$MODE.log"

  # Sample lab PHP-FPM CPU every 5s into a temp file while the replay runs.
  cpu_file="$(mktemp)"
  (
    while true; do
      docker stats --no-stream --format '{{.CPUPerc}}' "$APP_CONTAINER" 2>/dev/null | tr -d '%' >>"$cpu_file"
      sleep 5
    done
  ) &
  sampler_pid=$!

  log "lab-load: mode=$MODE run=$RUN"
  vm_root "$VM" env \
    LAB_VM="$VM" \
    LAB_LOAD_MODE="$MODE" \
    LAB_LOAD_RUN_ID="$RUN" \
    LAB_LOAD_PROFILE=/root/load-profile.json \
    LAB_PANEL_URL="$PANEL_URL_VM" \
    /root/integration.test -test.v -test.count=1 -test.timeout 40m -test.run '^TestLoadAggregation$' >"$RAW" 2>&1
  test_rc=$?

  kill "$sampler_pid" >/dev/null 2>&1
  wait "$sampler_pid" 2>/dev/null

  php_fpm_avg="$(awk '{s+=$1; n++} END { if (n>0) printf "%.1f", s/n; else print "0.0" }' "$cpu_file")"
  rm -f "$cpu_file"

  result_line="$(grep '^LOAD_RESULT ' "$RAW" | tail -1)"
  if [ -z "$result_line" ]; then
    log "lab-load: mode=$MODE produced no LOAD_RESULT line (test_rc=$test_rc) — see $RAW"
    overall_result="FAIL"
    printf '| %s | - | - | - | - | - | - | - | - | - | - | %s | FAIL |\n' "$MODE" "$php_fpm_avg" >>"$REPORT"
    continue
  fi

  generated="$(printf '%s\n' "$result_line" | grep -oE 'generated=[0-9]+' | cut -d= -f2)"
  criticals="$(printf '%s\n' "$result_line" | grep -oE 'criticals=[0-9]+' | cut -d= -f2)"
  batches="$(printf '%s\n' "$result_line" | grep -oE 'batches=[0-9]+' | cut -d= -f2)"
  retries="$(printf '%s\n' "$result_line" | grep -oE 'retries=[0-9]+' | cut -d= -f2)"
  dqf="$(printf '%s\n' "$result_line" | grep -oE 'dropped_queue_full=[0-9]+' | cut -d= -f2)"
  dsf="$(printf '%s\n' "$result_line" | grep -oE 'dropped_send_failed=[0-9]+' | cut -d= -f2)"
  drj="$(printf '%s\n' "$result_line" | grep -oE 'dropped_rejected=[0-9]+' | cut -d= -f2)"
  cpu_ms="$(printf '%s\n' "$result_line" | grep -oE 'cpu_ms=[0-9]+' | cut -d= -f2)"
  rss_kb="$(printf '%s\n' "$result_line" | grep -oE 'rss_kb=[0-9]+' | cut -d= -f2)"
  dropped_total=$((dqf + dsf + drj))

  rows="$(sql "SELECT COUNT(*) FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run'))='$RUN'")"
  occ="$(sql "SELECT COALESCE(SUM(occurrence_count),0) FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run'))='$RUN'")"
  crit_rows="$(sql "SELECT COUNT(*) FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run'))='$RUN' AND severity='critical'")"
  crit_bad="$(sql "SELECT COUNT(*) FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run'))='$RUN' AND (severity='critical' OR type IN ($LOCKED_TYPES_SQL)) AND occurrence_count<>1")"
  rollups="$(sql "SELECT COUNT(*) FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run'))='$RUN' AND JSON_UNQUOTE(JSON_EXTRACT(details,'\$.rollup'))='true'")"

  mode_result="PASS"
  reasons=""

  if [ "$test_rc" -ne 0 ]; then
    mode_result="FAIL"; reasons="$reasons test_rc=$test_rc"
  fi
  if [ "$dropped_total" != "0" ]; then
    mode_result="FAIL"; reasons="$reasons dropped_total=$dropped_total"
  fi

  case "$MODE" in
    off)
      rows_off="$rows"
      if [ "$rows" != "$generated" ] || [ "$occ" != "$generated" ]; then
        mode_result="FAIL"; reasons="$reasons rows=$rows occ=$occ generated=$generated (want rows==occ==generated)"
      fi
      ;;
    on)
      if [ "$occ" != "$generated" ]; then
        mode_result="FAIL"; reasons="$reasons occ=$occ generated=$generated (want occ==generated, zero loss)"
      fi
      if [ "$crit_rows" != "$criticals" ]; then
        mode_result="FAIL"; reasons="$reasons crit_rows=$crit_rows criticals=$criticals (want equal)"
      fi
      if [ "$crit_bad" != "0" ]; then
        mode_result="FAIL"; reasons="$reasons crit_bad=$crit_bad (want 0)"
      fi
      if [ -n "$rows_off" ] && [ "$rows_off" -gt 0 ]; then
        reduction="$(awk -v off="$rows_off" -v on="$rows" 'BEGIN { printf "%.2f", 100*(1-on/off) }')"
        reduction_line="Row reduction ON vs OFF: ${reduction}% (target ${TARGET_REDUCTION_PCT}%)"
        below_target="$(awk -v r="$reduction" -v t="$TARGET_REDUCTION_PCT" 'BEGIN { print (r+0 < t+0) ? 1 : 0 }')"
        if [ "$below_target" = "1" ]; then
          mode_result="FAIL"; reasons="$reasons reduction=${reduction}% below target=${TARGET_REDUCTION_PCT}%"
        fi
      else
        mode_result="FAIL"; reasons="$reasons rows_off unavailable or zero — cannot compute reduction"
      fi
      ;;
    burst)
      if [ "$occ" != "$generated" ]; then
        mode_result="FAIL"; reasons="$reasons occ=$occ generated=$generated (want occ==generated, zero loss)"
      fi
      burst_reduction="$(awk -v g="$generated" -v r="$rows" 'BEGIN { if (g>0) printf "%.2f", 100*(1-r/g); else print "0.00" }')"
      burst_reduction_line="Burst (worst-case, IP-rotating) reduction: ${burst_reduction}% — reported honestly, near-zero expected"
      ;;
  esac

  if [ "$mode_result" != "PASS" ]; then
    overall_result="FAIL"
    log "lab-load: mode=$MODE FAIL —$reasons"
  else
    log "lab-load: mode=$MODE PASS rows=$rows occ=$occ criticals=$criticals"
  fi

  printf '| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |\n' \
    "$MODE" "$generated" "$criticals" "$rows" "$occ" "$rollups" "$batches" "$retries" "$dropped_total" "$cpu_ms" "$rss_kb" "$php_fpm_avg" "$mode_result" \
    >>"$REPORT"
done

{
  printf '\n'
  [ -n "$reduction_line" ] && printf '%s\n\n' "$reduction_line"
  [ -n "$burst_reduction_line" ] && printf '%s\n\n' "$burst_reduction_line"
  printf '**Overall: %s**\n' "$overall_result"
} >>"$REPORT"

log "lab-load: report $REPORT"

# Reset the agent override to default (events:aggregation --default), AND
# clean up this run's synthetic rows — both AFTER the report is written,
# and both scoped to the lab DB only (sql() already refused to run
# anywhere else above).
events_aggregation --agent="$AGENT_ID" --default >/dev/null 2>&1
sql "DELETE FROM events WHERE JSON_UNQUOTE(JSON_EXTRACT(details,'\$.load_run')) LIKE 'agg19-%'" >/dev/null 2>&1

printf '%s\n' "${REPORT#"$REPO_DIR"/}"

[ "$overall_result" = "PASS" ]
exit $?
