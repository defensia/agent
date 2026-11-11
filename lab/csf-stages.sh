#!/usr/bin/env bash
# lab/csf-stages.sh — Phase 15 host-side stages, sourced by lab/test.sh
# after the per-VM integration-test loop and before the attack stage
# (plan 08). Three stages, each appending one row to the same report
# table test.sh is already writing and feeding failures into the same
# `failed_vms`/`## Failures` machinery the attack stage already uses:
#
#   csf-ingest       every agent VM's row in the REAL lab panel DB has the
#                     CSF facts/lists the real agent actually reported
#   csf-killswitch    org.csf_integration_disabled pauses and resumes a
#                     real agent end to end, within one restart-triggered
#                     sync (main.go's startup syncAndApply)
#   compat-old-agent  the last released tag's agent binary still
#                     heartbeats 200 against this (new) panel
#
# Requires lab/lib.sh + lab/matrix.sh already sourced by the caller (for
# vm_root/vm_csf_fork/vm_testing/vm_lfd/LAB_ARCH/REPO_DIR/PANEL_URL_VM) and
# the caller's own $LAB_DIR/$TS/$REPORT/$failed_vms in scope — this file
# intentionally has no `set -e`/`set -u` header of its own: it is SOURCED
# into test.sh's already-`set +e` shell, not executed standalone.

# panel_php PHP_CODE — runs PHP_CODE inside the lab panel's app container
# via `php artisan tinker --execute` and prints tinker's LAST stdout line.
# Every call site's PHP_CODE must end with `echo json_encode([...]);` —
# this helper is a dumb pipe, not a JSON-aware wrapper.
panel_php() {
  panel_compose exec -T app php artisan tinker --execute "$1" 2>&1 | tail -1
}

# panel_php_get KEY PHP_CODE — runs PHP_CODE (which must echo exactly one
# JSON object as its final statement) and extracts KEY via lib.sh's own
# json_get (dotted-path semantics), reusing the same JSON contract every
# other panel helper in this lab already relies on.
panel_php_get() {
  local key=$1 php=$2 tmp
  tmp="$(mktemp)"
  panel_php "$php" >"$tmp"
  json_get "$tmp" "$key"
  rm -f "$tmp"
}

# php_ok PHP_CODE — like panel_php_get, but specialised for this file's own
# {"ok":bool,"reason":str} convention: returns 0/1 and sets CSF_STAGE_REASON
# as a side channel for the caller to log/report.
CSF_STAGE_REASON=""
php_ok() {
  local tmp ok
  tmp="$(mktemp)"
  panel_php "$1" >"$tmp"
  ok="$(json_get "$tmp" ok)"
  CSF_STAGE_REASON="$(json_get "$tmp" reason)"
  rm -f "$tmp"
  case "$ok" in
    True | true | 1) return 0 ;;
    *) return 1 ;;
  esac
}

# poll MAX_SECONDS CMD... — retries CMD every 5s until it exits 0 or
# MAX_SECONDS have elapsed in total; returns CMD's own last exit code. CMD
# is always a function call (php_ok "..."), never a bare shell pipeline, so
# its side effect (setting CSF_STAGE_REASON) is visible to the caller after
# poll returns either way.
poll() {
  local max=$1
  shift
  local waited=0 rc
  "$@"
  rc=$?
  while [ "$rc" -ne 0 ] && [ "$waited" -lt "$max" ]; do
    sleep 5
    waited=$((waited + 5))
    "$@"
    rc=$?
  done
  return "$rc"
}

# csf_stage_row STAGE VM FORK PASS FAIL SECONDS RESULT — appends one row to
# $REPORT in the exact column shape test.sh's own per-VM loop uses, and (on
# failure) registers STAGE in failed_vms so the shared `## Failures` writer
# at the bottom of test.sh picks up $LAB_DIR/reports/raw/$TS-$STAGE.log
# automatically, exactly like the attack stage already does.
csf_stage_row() {
  local stage=$1 vm=$2 fork=$3 pass=$4 fail=$5 seconds=$6 result=$7
  printf '| %s | %s | - | %s | %s | %s | 0 | %s | %s |\n' \
    "$vm" "$fork" "$stage" "$pass" "$fail" "$seconds" "$result" >>"$REPORT"
  if [ "$result" != "PASS" ]; then
    failed_vms="$failed_vms $stage"
  fi
  log "$stage: pass=$pass fail=$fail seconds=${seconds}s result=$result"
}

# --- Stage: csf-ingest ------------------------------------------------
# For every CSF VM: the panel's stored Agent row has the facts the real
# agent reported (fork, testing, lfd, a fresh csf_last_reported_at, not
# paused, a 64-hex lists hash) AND agent_csf_lists has matching-hash
# deny/allow rows whose allow list carries the lab-panel comment entry
# every CSF VM's provisioning adds; the cwp-orphan's csf_download_servers
# still names download.configserver.com. For debian12-nocsf: csf_fork is
# null, csf_installed is false, csf_last_reported_at is null, and there are
# zero agent_csf_lists rows — "never had CSF" must stay indistinguishable
# from "nothing to report" at the DB layer, not just in the wire contract.
csf_stage_ingest_check_csf_vm() {
  local vm=$1 fork=$2 testing_bool=$3 lfd_bool=$4 orphan=$5
  local extra=""
  if [ "$orphan" = "1" ]; then
    extra="if (!in_array('download.configserver.com', \$a->csf_download_servers ?? [])) \$errs[] = 'csf_download_servers missing download.configserver.com: '.json_encode(\$a->csf_download_servers);"
  fi
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
\$errs = [];
if (!\$a) { echo json_encode(['ok'=>false,'reason'=>'agent not found']); exit; }
if (\$a->csf_fork !== '$fork') \$errs[] = "csf_fork={\$a->csf_fork} want $fork";
if (\$a->csf_installed !== true) \$errs[] = 'csf_installed='.var_export(\$a->csf_installed, true);
if (\$a->csf_testing !== $testing_bool) \$errs[] = 'csf_testing='.var_export(\$a->csf_testing, true);
if (\$a->csf_lfd_running !== $lfd_bool) \$errs[] = 'csf_lfd_running='.var_export(\$a->csf_lfd_running, true);
if (\$a->csf_paused !== false) \$errs[] = 'csf_paused='.var_export(\$a->csf_paused, true);
if (!\$a->csf_last_reported_at || \$a->csf_last_reported_at->diffInSeconds(now()) > 600) \$errs[] = 'csf_last_reported_at stale/null: '.\$a->csf_last_reported_at;
if (!preg_match('/^[0-9a-f]{64}\$/', (string) \$a->csf_lists_hash)) \$errs[] = 'csf_lists_hash not 64 hex: '.\$a->csf_lists_hash;
\$lists = App\Models\AgentCsfList::where('agent_id', \$a->id)->get()->keyBy('list');
if (!isset(\$lists['deny'])) \$errs[] = 'no deny agent_csf_lists row';
if (!isset(\$lists['allow'])) \$errs[] = 'no allow agent_csf_lists row';
foreach (['deny', 'allow'] as \$l) {
    if (isset(\$lists[\$l]) && \$lists[\$l]->hash !== \$a->csf_lists_hash) \$errs[] = "\$l hash mismatch: {\$lists[\$l]->hash} vs {\$a->csf_lists_hash}";
}
if (isset(\$lists['allow'])) {
    \$hasLabPanel = false;
    foreach (\$lists['allow']->entries ?? [] as \$e) {
        if (str_contains(\$e['comment'] ?? '', 'lab-panel')) { \$hasLabPanel = true; break; }
    }
    if (!\$hasLabPanel) \$errs[] = 'allow list has no lab-panel comment entry';
}
$extra
echo json_encode(['ok' => empty(\$errs), 'reason' => implode('; ', \$errs)]);
PHPEOF
  )
  php_ok "$php"
}

csf_stage_ingest_check_nocsf() {
  local php
  php=$(
    cat <<'PHPEOF'
$a = App\Models\Agent::where('name','debian12-nocsf')->first();
$errs = [];
if (!$a) { echo json_encode(['ok'=>false,'reason'=>'agent not found']); exit; }
if ($a->csf_fork !== null) $errs[] = "csf_fork={$a->csf_fork} want null";
if ($a->csf_installed !== false) $errs[] = 'csf_installed='.var_export($a->csf_installed, true);
if ($a->csf_last_reported_at !== null) $errs[] = 'csf_last_reported_at not null: '.$a->csf_last_reported_at;
$cnt = App\Models\AgentCsfList::where('agent_id', $a->id)->count();
if ($cnt !== 0) $errs[] = "agent_csf_lists rows = $cnt, want 0";
echo json_encode(['ok' => empty($errs), 'reason' => implode('; ', $errs)]);
PHPEOF
  )
  php_ok "$php"
}

csf_stage_ingest() {
  local stage="csf-ingest" start pass=0 fail=0 vm fork testing_bool lfd_bool orphan
  local RAW="$LAB_DIR/reports/raw/$TS-$stage.log"
  : >"$RAW"
  start=$(date +%s)

  for vm in $LAB_CSF_VMS; do
    fork="$(vm_csf_fork "$vm")"
    [ "$(vm_testing "$vm")" = "1" ] && testing_bool=true || testing_bool=false
    [ "$(vm_lfd "$vm")" = "active" ] && lfd_bool=true || lfd_bool=false
    orphan=0
    [ "$vm" = "alma8-csf-cwp-orphan" ] && orphan=1

    {
      echo "--- $vm ---"
      if poll 240 csf_stage_ingest_check_csf_vm "$vm" "$fork" "$testing_bool" "$lfd_bool" "$orphan"; then
        pass=$((pass + 1))
        echo "PASS $vm"
      else
        fail=$((fail + 1))
        echo "FAIL $vm: $CSF_STAGE_REASON"
      fi
    } >>"$RAW"
  done

  {
    echo "--- debian12-nocsf ---"
    if poll 60 csf_stage_ingest_check_nocsf; then
      pass=$((pass + 1))
      echo "PASS debian12-nocsf"
    else
      fail=$((fail + 1))
      echo "FAIL debian12-nocsf: $CSF_STAGE_REASON"
    fi
  } >>"$RAW"

  local seconds=$(($(date +%s) - start)) result="PASS"
  [ "$fail" -eq 0 ] || result="FAIL"
  csf_stage_row "$stage" "(all agent VMs)" "-" "$pass" "$fail" "$seconds" "$result"
}

# --- Stage: csf-killswitch --------------------------------------------
# organizations.csf_integration_disabled pauses a real agent within one
# restart-triggered sync (main.go's startup syncAndApply applies the flag
# immediately — no 5-minute ticker wait needed), and resuming it un-pauses
# within another restart. Every lab agent shares the one lab organization,
# so the flag is reset to false in a trap (RETURN) no matter how this
# function exits, and runs ONLY after csf-ingest/compat-old-agent (their
# own polls would otherwise race a pause this stage introduces) — enforced
# by call order in lab/test.sh, not by this function itself.
csf_killswitch_set_flag() {
  local vm=$1 value=$2
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
App\Models\Organization::find(\$a->organization_id)->update(['csf_integration_disabled' => $value]);
echo json_encode(['ok' => true, 'reason' => '']);
PHPEOF
  )
  php_ok "$php"
}

csf_killswitch_paused_is() {
  local vm=$1 want=$2
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
echo json_encode(['ok' => \$a->csf_paused === $want, 'reason' => 'csf_paused='.var_export(\$a->csf_paused, true)]);
PHPEOF
  )
  php_ok "$php"
}

# csf_killswitch_resumed_fresh VM SINCE_EPOCH — resumed check: csf_paused
# false AND csf_last_reported_at strictly newer than the Unix epoch seconds
# the resume restart was issued at (proves THIS restart's heartbeat landed,
# not a stale pre-pause one).
csf_killswitch_resumed_fresh() {
  local vm=$1 since=$2
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
\$errs = [];
if (\$a->csf_paused !== false) \$errs[] = 'csf_paused='.var_export(\$a->csf_paused, true);
if (!\$a->csf_last_reported_at || \$a->csf_last_reported_at->getTimestamp() <= $since) \$errs[] = 'csf_last_reported_at not newer than resume: '.\$a->csf_last_reported_at;
echo json_encode(['ok' => empty(\$errs), 'reason' => implode('; ', \$errs)]);
PHPEOF
  )
  php_ok "$php"
}

csf_killswitch_reset_flag() {
  csf_killswitch_set_flag "alma9-csf-orig" false >/dev/null || true
}

csf_stage_killswitch() {
  local stage="csf-killswitch" vm="alma9-csf-orig" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage.log"
  : >"$RAW"
  start=$(date +%s)
  # Always reset the org flag at the end, however this function returns —
  # a FAIL below must never leave the lab's one shared org paused for
  # every subsequent stage/run.
  trap csf_killswitch_reset_flag RETURN

  {
    echo "=== pause ==="
    if ! csf_killswitch_set_flag "$vm" true; then
      echo "FAIL set csf_integration_disabled=true: $CSF_STAGE_REASON"
      fail=$((fail + 1))
    else
      echo "OK set csf_integration_disabled=true"
      vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1

      if poll 150 csf_killswitch_paused_is "$vm" true; then
        echo "PASS $vm csf_paused=true ($CSF_STAGE_REASON)"
        pass=$((pass + 1))
      else
        echo "FAIL $vm never reported csf_paused=true within 150s ($CSF_STAGE_REASON)"
        fail=$((fail + 1))
      fi

      if vm_root "$vm" test -e /etc/defensia/csf-paused >/dev/null 2>&1; then
        echo "PASS /etc/defensia/csf-paused exists on $vm"
        pass=$((pass + 1))
      else
        echo "FAIL /etc/defensia/csf-paused missing on $vm"
        fail=$((fail + 1))
      fi

      # Bounded retry (3x, 3s apart): under the host's own documented high
      # load, a single `orb exec` round-trip can occasionally return
      # truncated/empty output (an infra hiccup, not a logic race — the
      # DB-side csf_paused=true poll just above already proves the pause
      # itself landed well before this check runs). Same category of fix
      # as Phase 14's verify.sh heartbeat retry: harden the assertion
      # against a transient read, never weaken what it actually checks.
      journal_ok=0
      for _try in 1 2 3; do
        if vm_root "$vm" journalctl -u defensia-agent --since "-5min" --no-pager 2>/dev/null | grep -qF '[csf] integration paused'; then
          journal_ok=1
          break
        fi
        sleep 3
      done
      if [ "$journal_ok" -eq 1 ]; then
        echo "PASS journal shows '[csf] integration paused' on $vm"
        pass=$((pass + 1))
      else
        echo "FAIL journal has no '[csf] integration paused' line on $vm (retried 3x)"
        fail=$((fail + 1))
      fi
    fi

    echo "=== resume ==="
    resume_epoch=$(date +%s)
    if ! csf_killswitch_set_flag "$vm" false; then
      echo "FAIL set csf_integration_disabled=false: $CSF_STAGE_REASON"
      fail=$((fail + 1))
    else
      echo "OK set csf_integration_disabled=false"
      vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1

      if poll 150 csf_killswitch_resumed_fresh "$vm" "$resume_epoch"; then
        echo "PASS $vm resumed and reported fresh ($CSF_STAGE_REASON)"
        pass=$((pass + 1))
      else
        echo "FAIL $vm did not resume/report fresh within 150s ($CSF_STAGE_REASON)"
        fail=$((fail + 1))
      fi

      if ! vm_root "$vm" test -e /etc/defensia/csf-paused >/dev/null 2>&1; then
        echo "PASS /etc/defensia/csf-paused removed on $vm"
        pass=$((pass + 1))
      else
        echo "FAIL /etc/defensia/csf-paused still present on $vm"
        fail=$((fail + 1))
      fi
    fi

    # Every lab agent shares this one organization: a 5-minute sync ticker
    # on the OTHER 6 agent VMs could otherwise pick the pause up on its own
    # schedule, well after this function returns. Force an immediate
    # resync everywhere and poll until every CSF VM reports resumed, so the
    # lab is left clean for whatever runs next (including a human).
    echo "=== restart every agent VM and confirm nobody is left paused ==="
    for other in $LAB_AGENT_VMS; do
      vm_root "$other" systemctl restart defensia-agent >/dev/null 2>&1 || true
    done
    local all_clear=1
    for other in $LAB_CSF_VMS; do
      if ! poll 150 csf_killswitch_paused_is "$other" false; then
        echo "FAIL $other still csf_paused!=false after the global restart ($CSF_STAGE_REASON)"
        all_clear=0
        fail=$((fail + 1))
      fi
    done
    if [ "$all_clear" -eq 1 ]; then
      echo "PASS every CSF VM confirmed csf_paused=false after the global restart"
      pass=$((pass + 1))
    fi
  } >>"$RAW"

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  csf_stage_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

# --- Stage: compat-old-agent -------------------------------------------
# The last tag released before this phase still heartbeats 200 against
# this (new, Phase-15-ingest) panel: old flat CSF fields still land
# (csf_installed), and the panel's tolerant tri-state ingest never nulls
# out a field (csf_fork) the old agent's payload simply doesn't send.
# csf_old_agent_check VM OLD_VER FORK_BEFORE SINCE_EPOCH — SINCE_EPOCH must
# be captured BEFORE the binary swap: last_seen_at merely being "fresh"
# (<=180s) is NOT sufficient evidence the old binary itself sent anything,
# since the previous (new) agent's own last heartbeat could still satisfy
# that window on its own — the strictly-newer-than-swap-time check is what
# actually proves THIS heartbeat came from the swapped-in old binary.
csf_old_agent_check() {
  local vm=$1 old_ver=$2 fork_before=$3 since=$4
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
\$errs = [];
if (\$a->version !== '$old_ver') \$errs[] = "version={\$a->version} want $old_ver";
if (!\$a->last_seen_at || \$a->last_seen_at->getTimestamp() <= $since) \$errs[] = 'last_seen_at not newer than the binary swap: '.\$a->last_seen_at;
if (\$a->csf_installed !== true) \$errs[] = 'csf_installed='.var_export(\$a->csf_installed, true);
if (\$a->csf_fork !== '$fork_before') \$errs[] = "csf_fork={\$a->csf_fork} want unchanged $fork_before (must not be overwritten by null)";
echo json_encode(['ok' => empty(\$errs), 'reason' => implode('; ', \$errs)]);
PHPEOF
  )
  php_ok "$php"
}

# csf_new_agent_check VM NEW_VER SINCE_EPOCH — same "strictly newer than
# the restore" proof in the other direction, plus csf_testing reporting
# again (non-null) proves the FULL tri-state agent is back, not merely
# that something heartbeated.
csf_new_agent_check() {
  local vm=$1 new_ver=$2 since=$3
  local php
  php=$(
    cat <<PHPEOF
\$a = App\Models\Agent::where('name','$vm')->first();
\$errs = [];
if (\$a->version !== '$new_ver') \$errs[] = "version={\$a->version} want $new_ver";
if (!\$a->last_seen_at || \$a->last_seen_at->getTimestamp() <= $since) \$errs[] = 'last_seen_at not newer than the restore: '.\$a->last_seen_at;
if (\$a->csf_testing === null) \$errs[] = 'csf_testing still null after restoring the new binary (tri-state fields should be reporting again)';
echo json_encode(['ok' => empty(\$errs), 'reason' => implode('; ', \$errs)]);
PHPEOF
  )
  php_ok "$php"
}

csf_old_agent_restore() {
  local vm=$1
  vm_root "$vm" bash -c 'install -m0755 /root/defensia-agent-new /usr/local/bin/defensia-agent && systemctl restart defensia-agent' >/dev/null 2>&1 || true
}

# CSF_OLD_AGENT_VM / csf_old_agent_restore_trap: a `trap ... RETURN` command
# string can only be a literal, so the target VM for the restore has to
# travel via a global rather than string-concatenated into the trap itself
# (which would need fragile nested quoting around an expanded variable).
CSF_OLD_AGENT_VM=""
csf_old_agent_restore_trap() {
  [ -n "$CSF_OLD_AGENT_VM" ] && csf_old_agent_restore "$CSF_OLD_AGENT_VM"
}

csf_stage_compat_old_agent() {
  local stage="compat-old-agent" vm="alma9-csf-aetherinox" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage.log"
  : >"$RAW"
  start=$(date +%s)

  local old_ref old_ver new_ver old_src old_bin fork_before
  old_ref="$(git -C "$REPO_DIR" describe --tags --abbrev=0 origin/main)"
  old_ver="${old_ref#v}"
  new_ver="$(grep -m1 'var version' "$REPO_DIR/cmd/defensia-agent/main.go" | sed -E 's/.*"([^"]*)".*/\1/')"
  fork_before="$(vm_csf_fork "$vm")"

  {
    echo "OLD_REF=$old_ref (old_ver=$old_ver, new_ver=$new_ver, fork_before=$fork_before)"

    old_src="$REPO_DIR/build/old-src"
    rm -rf "$old_src"
    mkdir -p "$old_src"
    if ! git -C "$REPO_DIR" archive "$old_ref" | tar -x -C "$old_src" 2>&1; then
      echo "FAIL git archive $old_ref failed"
      fail=$((fail + 1))
    else
      old_bin="$REPO_DIR/build/defensia-agent-old-linux-$LAB_ARCH"
      if ! (cd "$old_src" && GOOS=linux GOARCH="$LAB_ARCH" CGO_ENABLED=0 go build -o "$old_bin" ./cmd/defensia-agent) 2>&1; then
        echo "FAIL building $old_ref for linux/$LAB_ARCH"
        fail=$((fail + 1))
      else
        echo "OK built $old_ref -> $old_bin"

        # Trap now that there is something real to restore: whatever
        # happens below, put the new binary back and restart.
        CSF_OLD_AGENT_VM="$vm"
        trap csf_old_agent_restore_trap RETURN

        local since_swap since_restore
        since_swap=$(date +%s)
        vm_root "$vm" cp /usr/local/bin/defensia-agent /root/defensia-agent-new >/dev/null 2>&1
        vm_push "$vm" "$old_bin" /root/defensia-agent-old
        vm_root "$vm" bash -c 'systemctl stop defensia-agent; install -m0755 /root/defensia-agent-old /usr/local/bin/defensia-agent; systemctl start defensia-agent' >/dev/null 2>&1

        if poll 150 csf_old_agent_check "$vm" "$old_ver" "$fork_before" "$since_swap"; then
          echo "PASS $vm old agent ($old_ref) heartbeats and is ingested ($CSF_STAGE_REASON)"
          pass=$((pass + 1))
        else
          echo "FAIL $vm old agent did not heartbeat/ingest as expected within 150s ($CSF_STAGE_REASON)"
          fail=$((fail + 1))
        fi
      fi
    fi

    echo "=== restore new binary ==="
    since_restore=$(date +%s)
    csf_old_agent_restore "$vm"
    trap - RETURN
    if poll 150 csf_new_agent_check "$vm" "$new_ver" "$since_restore"; then
      echo "PASS $vm restored to the new binary and reporting tri-state fields again ($CSF_STAGE_REASON)"
      pass=$((pass + 1))
    else
      echo "FAIL $vm did not resume the new binary's full reporting within 150s ($CSF_STAGE_REASON)"
      fail=$((fail + 1))
    fi
  } >>"$RAW"

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  csf_stage_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}
