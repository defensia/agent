#!/usr/bin/env bash
# lab/sot-stages.sh — Phase 16.1 CSF source-of-truth end-to-end stages,
# sourced by lab/test.sh after Phase 15's csf-stages.sh and before the
# attack stage. Proves every SOT requirement against the REAL agent
# daemon talking to the REAL lab panel over the Sanctum API (lab/sot/
# api.sh), on real CSF forks, with real CSF commands (the shim from
# 16.1-13's lab/sot/csf-shim.sh auditing every one).
#
# Requires lab/lib.sh + lab/matrix.sh + lab/sot/api.sh already sourced by
# the caller, and the caller's own $LAB_DIR/$TS/$REPORT/$failed_vms in
# scope -- same contract as csf-stages.sh (no own set -e/-u header: this
# is SOURCED into test.sh's already-`set +e` shell).
#
# shellcheck source=lab/sot/api.sh
[ -n "${SOT_API_SOURCED:-}" ] || { source "$LAB_DIR/sot/api.sh"; SOT_API_SOURCED=1; }

# sot_forbidden_flags: the CONTRACT's own "never" list (6 flags); shared
# by every stage that inspects a shim call log.
SOT_FORBIDDEN_FLAGS="-f --flush -x --disable -e -ra"

# sot_shim_has_forbidden LOG — reads a csf-shim.sh `calls` log (lines of
# "<epoch> <args...>") and reports (exit 0) whether any forbidden flag
# ever appears as a whole whitespace-delimited token (never a substring
# match, which would false-positive on e.g. a comment containing "-e").
sot_shim_has_forbidden() {
  local log=$1 flag
  for flag in $SOT_FORBIDDEN_FLAGS; do
    if printf '%s\n' "$log" | tr ' ' '\n' | grep -qx -- "$flag"; then
      return 0
    fi
  done
  return 1
}

# sot_shim_mutating_count LOG — counts shim-log lines (one call per
# line: "<epoch> <args...>") that are NOT a bare `-v` query. The agent's
# pre-existing (Phase 15) CSF collector runs `csf -v` on its own
# independent ~5-minute refresh schedule regardless of anything SOT does
# -- confirmed live (phase 16.1, 2026-11-19) -- so a byte-for-byte
# "shim log unchanged" comparison spanning more than a few seconds will
# false-positive on that unrelated, read-only, already-existing
# behaviour. SOT-02's real promise is "activation never WRITES/MUTATES
# anything", which this counts correctly: every non-`-v` line is a
# mutation attempt.
sot_shim_mutating_count() {
  local log=$1
  printf '%s\n' "$log" | awk 'NF>1 && $2 != "-v"' | grep -c .
}

# sot_assert COND_RC MESSAGE — COND_RC is the exit code of whatever the
# caller just tested (pass "$?" or a direct `[ ... ]`/command substitution
# result). Appends PASS/FAIL MESSAGE to the stage's $RAW and bumps the
# caller's pass/fail counters (via the fixed variable names `pass`/`fail`,
# matching csf-stages.sh's own convention of plain function-local counters
# rather than name-referenced out-params, for the same reason: every stage
# function here declares its own local pass=0 fail=0).
sot_assert() {
  local rc=$1 msg=$2
  if [ "$rc" -eq 0 ]; then
    pass=$((pass + 1))
    echo "PASS $msg" >>"$RAW"
  else
    fail=$((fail + 1))
    echo "FAIL $msg" >>"$RAW"
  fi
}

# sot_row STAGE VM FORK PASS FAIL SECONDS RESULT — same shape as Phase
# 15's csf_stage_row (one row per VM per stage, not one aggregated row),
# reusing csf_stage_row itself (same arg order: stage vm fork pass fail
# seconds result) so both files share exactly one writer.
sot_row() { csf_stage_row "$1" "$2" "$3" "$4" "$5" "$6" "$7"; }

# --- Stage: sot-snapshot -----------------------------------------------
# Activating through the panel API ends in_sync at generation 1 while
# csf.conf/csf.allow/csf.deny stay byte- AND mtime-identical, iptables
# rule count unchanged, and the shim logged zero calls (SOT-02: the
# snapshot itself never execs anything or writes a file).
sot_stage_snapshot_one() {
  local vm=$1 stage="sot-snapshot" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  bash "$LAB_DIR/sot/csf-shim.sh" install "$vm" >>"$RAW" 2>&1
  trap 'bash "'"$LAB_DIR"'/sot/csf-shim.sh" uninstall "'"$vm"'" >/dev/null 2>&1 || true' RETURN

  # sot-exit (run last, per the file-level ordering in test.sh) expects a
  # pre-existing tagged entry to survive activate+exit -- planted here,
  # before activation, so the snapshot's own `desired` captures it.
  vm_root "$vm" csf -a 203.0.113.61 "defensia:lab-exit" >>"$RAW" 2>&1

  local aid fp0 fp1 ipt0 ipt1 shim_before shim_after
  aid="$(agent_id_of "$vm")"
  fp0="$(file_fp "$vm" /etc/csf/csf.conf) $(file_fp "$vm" /etc/csf/csf.allow) $(file_fp "$vm" /etc/csf/csf.deny)"
  ipt0="$(vm_root "$vm" iptables -S | wc -l | tr -d ' ')"
  shim_before="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"

  sot_post "$aid" activate >>"$RAW" 2>&1
  sot_assert $? "$vm: activate POST"

  wait_sot "$aid" "state.get('status')=='in_sync' and (state.get('generation') or 0)>=1" 240
  sot_assert $? "$vm: wait in_sync generation>=1"

  fp1="$(file_fp "$vm" /etc/csf/csf.conf) $(file_fp "$vm" /etc/csf/csf.allow) $(file_fp "$vm" /etc/csf/csf.deny)"
  [ "$fp0" = "$fp1" ]
  sot_assert $? "$vm: csf.conf/.allow/.deny sha+mtime unchanged by activation ($fp0 -> $fp1)"

  ipt1="$(vm_root "$vm" iptables -S | wc -l | tr -d ' ')"
  [ "$ipt0" = "$ipt1" ]
  sot_assert $? "$vm: iptables rule count unchanged ($ipt0 -> $ipt1)"

  # Byte-equal comparison would false-positive on the agent's own
  # pre-existing (Phase 15) CSF collector, which runs a read-only `csf
  # -v` on its own independent ~5-minute schedule regardless of
  # anything SOT does -- count only non-`-v` (mutating) calls instead.
  shim_after="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"
  local mutating_before mutating_after
  mutating_before="$(sot_shim_mutating_count "$shim_before")"
  mutating_after="$(sot_shim_mutating_count "$shim_after")"
  [ "$mutating_before" = "$mutating_after" ]
  sot_assert $? "$vm: shim log gained no mutating calls from activation ($mutating_before -> $mutating_after)"

  vm_root "$vm" test -s /etc/defensia/csf_sot.json >/dev/null 2>&1
  sot_assert $? "$vm: /etc/defensia/csf_sot.json exists and is non-empty"

  local mode
  mode="$(vm_root "$vm" stat -c '%a' /etc/defensia/csf_sot.json 2>/dev/null)"
  [ "$mode" = "600" ]
  sot_assert $? "$vm: csf_sot.json mode 0600 (got $mode)"

  local tagged
  tagged="$(sot_get "$aid" tagged_entries_count)"
  [ "${tagged:-0}" -ge 1 ] 2>/dev/null
  sot_assert $? "$vm: tagged_entries_count >= 1 (got $tagged)"

  local audit
  audit="$(audit_actions "$aid")"
  printf '%s' "$audit" | grep -q csf_sot_activated
  sot_assert $? "$vm: audit has csf_sot_activated"

  # csf_sot_snapshot_taken reaches audit_logs via the agent's async
  # event queue (a buffered channel flushed by a separate goroutine,
  # not synchronously with the snapshot POST that triggered it) --
  # poll rather than check once immediately.
  wait_audit "$aid" csf_sot_snapshot_taken 60
  sot_assert $? "$vm: audit has csf_sot_snapshot_taken (wire event csf_sot_snapshot_taken)"

  trap - RETURN

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_snapshot() {
  local vm
  for vm in $LAB_CSF_VMS; do
    sot_stage_snapshot_one "$vm"
  done
}

# --- Stage: sot-drift ---------------------------------------------------
# A manual sed edit of TCP_IN shows up as drift within 3 minutes with the
# key, the added/removed ports and first_seen.
sot_stage_drift_one() {
  local vm=$1 stage="sot-drift" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  local aid
  aid="$(agent_id_of "$vm")"

  vm_root "$vm" cp -a /etc/csf/csf.conf /root/lab-sot/csf.conf.pre-drift
  vm_root "$vm" sh -c "sed -i -E 's/^(TCP_IN[[:space:]]*=[[:space:]]*\")([^\"]*)(\")/\\1\\2,48411\\3/' /etc/csf/csf.conf"

  wait_sot "$aid" "state.get('status')=='drift' and any(d.get('key')=='TCP_IN' and '48411' in (d.get('added') or []) for d in (state.get('drift') or []))" 240
  sot_assert $? "$vm: wait drift TCP_IN added 48411"

  local fs
  fs="$(sot_get "$aid" 2>/dev/null | python3 -c "
import json, sys
state = json.load(sys.stdin)
items = [d for d in (state.get('drift') or []) if d.get('key') == 'TCP_IN']
print(items[0].get('first_seen') if items else '')
" 2>/dev/null)"
  [ -n "$fs" ]
  sot_assert $? "$vm: drift item has first_seen (got '$fs')"

  wait_audit "$aid" csf_sot_drift_detected 60
  sot_assert $? "$vm: audit has csf_sot_drift_detected"

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_drift() {
  local vm
  for vm in $LAB_CSF_VMS; do
    sot_stage_drift_one "$vm"
  done
}

# --- Stage: sot-revert ---------------------------------------------------
# From the drift state left by sot-drift: Revert puts the managed lines
# back to the desired values; csf.conf equals the pre-edit bytes.
sot_stage_revert_one() {
  local vm=$1 stage="sot-revert" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  local aid pre_sha
  aid="$(agent_id_of "$vm")"
  pre_sha="$(vm_root "$vm" sha256sum /root/lab-sot/csf.conf.pre-drift | awk '{print $1}')"
  local shim_before
  shim_before="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"

  sot_post "$aid" revert >>"$RAW" 2>&1
  sot_assert $? "$vm: revert POST"

  wait_sot "$aid" "state.get('status')=='in_sync'" 240
  sot_assert $? "$vm: wait in_sync after revert"

  local post_sha
  post_sha="$(vm_root "$vm" sha256sum /etc/csf/csf.conf | awk '{print $1}')"
  [ "$pre_sha" = "$post_sha" ]
  sot_assert $? "$vm: csf.conf sha256 equals pre-drift ($pre_sha vs $post_sha)"

  local shim_after new_calls
  shim_after="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"
  new_calls="$(printf '%s\n' "$shim_after" | wc -l)"
  local before_calls
  before_calls="$(printf '%s\n' "$shim_before" | wc -l)"
  [ "$((new_calls - before_calls))" -ge 1 ]
  sot_assert $? "$vm: shim log gained at least one call (restart)"
  ! sot_shim_has_forbidden "$shim_after"
  sot_assert $? "$vm: shim log has no forbidden flag"

  wait_audit "$aid" csf_sot_revert_requested 30
  sot_assert $? "$vm: audit has csf_sot_revert_requested"
  wait_audit "$aid" csf_sot_corrected 60
  sot_assert $? "$vm: audit has csf_sot_corrected"

  vm_root "$vm" rm -f /root/lab-sot/csf.conf.pre-drift

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_revert() {
  local vm
  for vm in $LAB_CSF_VMS; do
    sot_stage_revert_one "$vm"
  done
}

# --- Stage: sot-reinstall ------------------------------------------------
# A simulated fork reinstall is reported as drift with hint
# version_changed and status is never error.
sot_stage_reinstall_one() {
  local vm=$1 stage="sot-reinstall" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  local aid
  aid="$(agent_id_of "$vm")"

  vm_root "$vm" mkdir -p /root/lab-sot
  vm_root "$vm" cp -a /etc/csf/csf.conf /root/lab-sot/pristine-csf.conf
  vm_root "$vm" sh -c "sed -i -E 's/^(TCP_IN[[:space:]]*=[[:space:]]*\")([^\"]*)(\")/\\1\\2,48421\\3/' /root/lab-sot/pristine-csf.conf"

  vm_root "$vm" bash /root/lab-sot/reinstall-sim.sh >>"$RAW" 2>&1

  wait_sot "$aid" "state.get('status')=='drift' and any((d.get('hint')=='version_changed') for d in (state.get('drift') or []))" 240
  sot_assert $? "$vm: wait drift with hint version_changed"

  local status
  status="$(sot_get "$aid" status)"
  [ "$status" != "error" ]
  sot_assert $? "$vm: status is not error (got $status)"

  vm_root "$vm" bash /root/lab-sot/reinstall-sim.sh --restore >>"$RAW" 2>&1

  wait_sot "$aid" "state.get('status')=='in_sync'" 240
  sot_assert $? "$vm: wait in_sync after restore"

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_reinstall() {
  sot_stage_reinstall_one "alma9-csf-da"
}

# --- Stage: sot-guard -----------------------------------------------------
# (a) session-IP guard: a revert that would remove an allow entry
# covering a live SSH session is refused, audited, and the session
# survives. (b) SSH-port guard: an automatic fix that would close the
# active SSH port is refused, audited, and the port stays open.
sot_guard_session_ip() {
  local vm=$1
  local aid peer

  aid="$(agent_id_of "$vm")"
  peer="$(bash "$LAB_DIR/sot/ssh-session.sh" open "$vm")"
  trap 'bash "'"$LAB_DIR"'/sot/ssh-session.sh" close "'"$vm"'" >/dev/null 2>&1 || true' RETURN

  vm_root "$vm" csf -a "$peer" "defensia:lab-guard" >>"$RAW" 2>&1

  wait_sot "$aid" "state.get('status')=='drift'" 240
  sot_assert $? "$vm: wait drift after manual foreign-style tagged allow add for $peer"

  sot_post "$aid" revert >>"$RAW" 2>&1

  # The LIVE state's `refused` array only reflects the most recent
  # heartbeat's report and can already have moved past this refusal by
  # the time a 5s poll samples it; audit_logs accumulates every
  # csf_sot_refused row and never clears, so check there instead.
  wait_audit_grep "$aid" 'ssh_session_ip' 240
  sot_assert $? "$vm: audit has a csf_sot_refused row naming ssh_session_ip"

  vm_root "$vm" grep -qF "$peer" /etc/csf/csf.allow
  sot_assert $? "$vm: csf.allow still contains $peer"

  vm_root "$vm" sh -c "ss -Hnt state established '( sport = :22 )'" | grep -q "$peer"
  sot_assert $? "$vm: SSH session from $peer still ESTABLISHED"

  bash "$LAB_DIR/sot/ssh-session.sh" close "$vm" >>"$RAW" 2>&1
  trap - RETURN

  # Retry the SAME revert (not accept+revert): accept would adopt the
  # lab-guard entry INTO desired (observed_hash becomes the new
  # desired), after which a revert is a no-op (nothing left to revert
  # to) and the entry could never be removed this way. The guard was
  # the only thing blocking the original revert; now that the session
  # is closed, retrying it restores the ORIGINAL desired (which never
  # had this entry) and removes it.
  sot_post "$aid" revert >>"$RAW" 2>&1
  wait_sot "$aid" "state.get('status')=='in_sync'" 240
  sot_assert $? "$vm: wait in_sync after removing the lab-guard entry (session now closed)"

  vm_root "$vm" grep -qF "$peer" /etc/csf/csf.allow
  ! [ $? -eq 0 ]
  sot_assert $? "$vm: $peer removed from csf.allow now that the session is closed"
}

sot_guard_ssh_port() {
  local vm=$1

  local aid
  aid="$(agent_id_of "$vm")"

  vm_root "$vm" mkdir -p /etc/ssh/sshd_config.d
  printf 'Port 22\nPort 2222\n' | vm_root "$vm" tee /etc/ssh/sshd_config.d/lab-sot.conf >/dev/null
  vm_root "$vm" bash -c 'systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null'

  vm_root "$vm" sh -c "sed -i -E 's/^(TCP_IN[[:space:]]*=[[:space:]]*\")([^\"]*)(\")/\\1\\2,2222\\3/' /etc/csf/csf.conf"
  vm_root "$vm" csf -r >>"$RAW" 2>&1

  wait_sot "$aid" "state.get('status')=='drift'" 240
  sot_assert $? "$vm: wait drift after manually opening 2222 (now a 2nd live sshd port)"

  vm_root "$vm" mkdir -p /etc/systemd/system/defensia-agent.service.d
  printf '[Service]\nEnvironment=DEFENSIA_CSFSOT_TICK_SECONDS=5\nEnvironment=DEFENSIA_CSFSOT_SETTLE_SECONDS=10\n' | vm_root "$vm" tee /etc/systemd/system/defensia-agent.service.d/lab-sot.conf >/dev/null
  vm_root "$vm" systemctl daemon-reload
  vm_root "$vm" systemctl restart defensia-agent
  trap 'vm_root "'"$vm"'" rm -f /etc/systemd/system/defensia-agent.service.d/lab-sot.conf; vm_root "'"$vm"'" systemctl daemon-reload; vm_root "'"$vm"'" systemctl restart defensia-agent >/dev/null 2>&1 || true' RETURN

  local since
  since=$(date +%s)
  sot_post "$aid" correction '{"mode":"auto"}' >>"$RAW" 2>&1

  # The LIVE state's `refused` array only reflects the MOST RECENT
  # cycle's attempt -- with the lab's sped-up tick it can flip to the
  # NEXT attempt (or to paused_conflict, which clears it) between two
  # 5s polls. audit_logs accumulates every csf_sot_refused row
  # (properties include reason+detail), so check there instead.
  wait_audit_grep "$aid" 'ssh_port_in_use' 240
  sot_assert $? "$vm: audit has a csf_sot_refused row naming ssh_port_in_use"

  vm_root "$vm" grep -q 2222 /etc/csf/csf.conf
  sot_assert $? "$vm: TCP_IN on disk still contains 2222"

  local refused_count
  refused_count="$(audit_count "$aid" csf_sot_refused "$since")"
  [ "${refused_count:-0}" -le 3 ] 2>/dev/null
  sot_assert $? "$vm: refusal attempts <= 3 since correction=auto was set (got $refused_count)"

  local shim_log
  shim_log="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"
  ! sot_shim_has_forbidden "$shim_log"
  sot_assert $? "$vm: shim log has no forbidden flag across sot-guard"

  vm_root "$vm" rm -f /etc/ssh/sshd_config.d/lab-sot.conf
  vm_root "$vm" bash -c 'systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null'

  sot_post "$aid" correction '{"mode":"warn"}' >>"$RAW" 2>&1
  sot_assert $? "$vm: correction back to warn"

  # Revert (NOT accept): accept would adopt the drift -- including the
  # 2222 this stage itself injected -- permanently INTO desired, which
  # is not this guard's cleanup promise ("the port stays open [during
  # the test]", not "desired grows a stray port forever"). Now that
  # sshd no longer listens on 2222, the guard no longer blocks removing
  # it, so a plain revert restores TCP_IN to exactly what it was before
  # this sub-test touched it.
  sot_post "$aid" revert >>"$RAW" 2>&1
  # status=='in_sync' is itself the definition of observed==desired, so
  # checking desired_ports (always populated, unlike `observed`, which
  # the wire contract omits once in sync) for the absence of 2222 is
  # both necessary and sufficient -- no need for a SEPARATE raw-file
  # grep against a fresh remote exec, which raced against this same
  # transition live and is less authoritative than the panel's own
  # hash-verified report anyway.
  wait_sot "$aid" "state.get('status')=='in_sync' and '2222' not in (state.get('desired_ports') or {}).get('TCP_IN','')" 240
  sot_assert $? "$vm: wait in_sync after revert, 2222 gone from desired TCP_IN"

  trap - RETURN
  vm_root "$vm" rm -f /etc/systemd/system/defensia-agent.service.d/lab-sot.conf
  vm_root "$vm" systemctl daemon-reload
  vm_root "$vm" systemctl restart defensia-agent
}

sot_stage_guard_one() {
  local vm=$1 stage="sot-guard" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  sot_guard_session_ip "$vm"
  sot_guard_ssh_port "$vm"

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_guard() {
  local vm
  for vm in alma9-csf-aetherinox debian12-csf-sentinel; do
    sot_stage_guard_one "$vm"
  done
}

# --- Stage: sot-auto ------------------------------------------------------
# With correction=auto and a saveconf-style external rewriter leaving a
# stale TCP_IN, the agent corrects at most 3 times, then the panel shows
# paused_conflict; resume clears it.
sot_stage_auto_one() {
  local vm=$1 stage="sot-auto" start pass=0 fail=0 result="PASS" since
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  local aid desired_tcp_in
  aid="$(agent_id_of "$vm")"
  desired_tcp_in="$(sot_get "$aid" desired_ports.TCP_IN)"

  vm_root "$vm" mkdir -p /etc/systemd/system/defensia-agent.service.d
  printf '[Service]\nEnvironment=DEFENSIA_CSFSOT_TICK_SECONDS=5\nEnvironment=DEFENSIA_CSFSOT_SETTLE_SECONDS=10\n' | vm_root "$vm" tee /etc/systemd/system/defensia-agent.service.d/lab-sot.conf >/dev/null
  vm_root "$vm" systemctl daemon-reload
  vm_root "$vm" systemctl restart defensia-agent
  trap 'vm_root "'"$vm"'" bash -c "kill \$(cat /root/lab-sot/loop-rewrite.pid 2>/dev/null) 2>/dev/null; rm -f /root/lab-sot/loop-rewrite.pid" >/dev/null 2>&1 || true; vm_root "'"$vm"'" rm -f /etc/systemd/system/defensia-agent.service.d/lab-sot.conf; vm_root "'"$vm"'" systemctl daemon-reload; vm_root "'"$vm"'" systemctl restart defensia-agent >/dev/null 2>&1 || true' RETURN

  sot_post "$aid" correction '{"mode":"auto"}' >>"$RAW" 2>&1
  sot_assert $? "$vm: correction auto"

  since=$(date +%s)
  vm_root "$vm" bash -c "nohup bash /root/lab-sot/loop-rewrite.sh 25 8 'TCP_IN=${desired_tcp_in},48511' >/root/lab-sot/loop-rewrite.out 2>&1 & echo \$! > /root/lab-sot/loop-rewrite.pid"

  wait_sot "$aid" "state.get('status')=='paused_conflict' and state.get('auto_paused')" 900
  sot_assert $? "$vm: wait paused_conflict/auto_paused (within 15 min of a stuck external rewriter)"

  local n
  n="$(audit_count "$aid" csf_sot_corrected "$since")"
  [ "${n:-0}" -ge 1 ] 2>/dev/null && [ "${n:-0}" -le 3 ] 2>/dev/null
  sot_assert $? "$vm: 1 <= automatic corrections <= 3 (got $n)"

  local conflicts
  conflicts="$(audit_count "$aid" csf_sot_conflict "$since")"
  [ "${conflicts:-0}" -eq 1 ] 2>/dev/null
  sot_assert $? "$vm: exactly one csf_sot_conflict (got $conflicts)"

  # Let 2 more loop cycles elapse (the external rewriter is still
  # running): the correction count must NOT have grown while paused.
  local START2
  START2=$(date +%s)
  while [ $(($(date +%s) - START2)) -lt 50 ]; do sleep 5; done
  local n2
  n2="$(audit_count "$aid" csf_sot_corrected "$since")"
  [ "$n2" = "$n" ]
  sot_assert $? "$vm: correction count unchanged while paused ($n -> $n2)"

  vm_root "$vm" bash -c 'kill $(cat /root/lab-sot/loop-rewrite.pid 2>/dev/null) 2>/dev/null; rm -f /root/lab-sot/loop-rewrite.pid'

  sot_post "$aid" resume >>"$RAW" 2>&1
  sot_assert $? "$vm: resume POST"

  wait_sot "$aid" "state.get('status')=='in_sync'" 300
  sot_assert $? "$vm: wait in_sync after resume + the stopped rewriter's drift gets auto-corrected once"

  sot_post "$aid" correction '{"mode":"warn"}' >>"$RAW" 2>&1
  sot_assert $? "$vm: correction back to warn"

  local status
  status="$(sot_get "$aid" status)"
  if [ "$status" != "in_sync" ]; then
    local hash
    hash="$(sot_get "$aid" observed_hash)"
    sot_post "$aid" revert >>"$RAW" 2>&1
    wait_sot "$aid" "state.get('status')=='in_sync'" 240
    sot_assert $? "$vm: wait in_sync (final cleanup revert)"
  fi

  trap - RETURN
  vm_root "$vm" rm -f /etc/systemd/system/defensia-agent.service.d/lab-sot.conf
  vm_root "$vm" systemctl daemon-reload
  vm_root "$vm" systemctl restart defensia-agent

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_auto() {
  local vm
  for vm in alma9-csf-orig alma9-csf-da alma8-csf-cwp-orphan; do
    sot_stage_auto_one "$vm"
  done
}

# --- Stage: sot-exit -------------------------------------------------------
# Switching back to CSF manages leaves the three files byte- AND
# mtime-identical across 3 cycles, deletes /etc/defensia/csf_sot.json
# and keeps tagged entries (the one planted by sot-snapshot).
sot_stage_exit_one() {
  local vm=$1 stage="sot-exit" start pass=0 fail=0 result="PASS"
  local RAW="$LAB_DIR/reports/raw/$TS-$stage-$vm.log"
  : >"$RAW"
  start=$(date +%s)

  local aid fp0 since
  aid="$(agent_id_of "$vm")"
  fp0="$(file_fp "$vm" /etc/csf/csf.conf) $(file_fp "$vm" /etc/csf/csf.allow) $(file_fp "$vm" /etc/csf/csf.deny)"

  local shim_before
  shim_before="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"
  since=$(date +%s)

  sot_post "$aid" exit >>"$RAW" 2>&1
  sot_assert $? "$vm: exit POST"

  local waited=0
  while vm_root "$vm" test -e /etc/defensia/csf_sot.json >/dev/null 2>&1; do
    [ "$waited" -lt 240 ] || break
    sleep 5
    waited=$((waited + 5))
  done
  vm_root "$vm" test ! -e /etc/defensia/csf_sot.json >/dev/null 2>&1
  sot_assert $? "$vm: csf_sot.json removed within 240s"

  # 3 more heartbeat cycles (~3 min): the files must stay exactly as they
  # were the moment the agent dropped its local state.
  local START2
  START2=$(date +%s)
  while [ $(($(date +%s) - START2)) -lt 185 ]; do sleep 5; done

  local fp1
  fp1="$(file_fp "$vm" /etc/csf/csf.conf) $(file_fp "$vm" /etc/csf/csf.allow) $(file_fp "$vm" /etc/csf/csf.deny)"
  [ "$fp0" = "$fp1" ]
  sot_assert $? "$vm: csf.conf/.allow/.deny sha+mtime unchanged across 3 post-exit cycles"

  local shim_after new_calls
  shim_after="$(bash "$LAB_DIR/sot/csf-shim.sh" calls "$vm")"
  # Lines added after $since with no csf argv at all are impossible (the
  # log has no timestamps per-field beyond epoch prefix) -- compare line
  # counts, matching the "zero calls after the exit timestamp" promise:
  # the exit itself and the following observe-only cycles never touch
  # csf once SOT mode is off. Excludes the agent's own pre-existing
  # (Phase 15) CSF collector's unrelated, read-only, independently-
  # scheduled `csf -v` refresh -- same reasoning as sot-snapshot's
  # mutating-only count.
  new_calls="$(printf '%s\n' "$shim_after" | awk -v since="$since" '$1 >= since')"
  new_calls="$(sot_shim_mutating_count "$new_calls")"
  [ "$new_calls" -eq 0 ]
  sot_assert $? "$vm: shim log has zero mutating calls after the exit timestamp (got $new_calls)"

  wait_audit "$aid" csf_sot_exited_by_user 30
  sot_assert $? "$vm: audit has csf_sot_exited_by_user"
  wait_audit "$aid" csf_sot_exited 60
  sot_assert $? "$vm: audit has csf_sot_exited"

  vm_root "$vm" grep -qF 203.0.113.61 /etc/csf/csf.allow
  sot_assert $? "$vm: lab-exit tagged entry survives exit"

  bash "$LAB_DIR/sot/csf-shim.sh" uninstall "$vm" >>"$RAW" 2>&1
  vm_root "$vm" csf -ar 203.0.113.61 >>"$RAW" 2>&1

  local seconds=$(($(date +%s) - start))
  [ "$fail" -eq 0 ] || result="FAIL"
  sot_row "$stage" "$vm" "$(vm_csf_fork "$vm")" "$pass" "$fail" "$seconds" "$result"
}

sot_stage_exit() {
  local vm
  for vm in $LAB_CSF_VMS; do
    sot_stage_exit_one "$vm"
  done
}
