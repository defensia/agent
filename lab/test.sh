#!/usr/bin/env bash
# lab/test.sh [vm...]
#
# Integration test runner for the Phase 14 CSF test lab: pushes the
# `integration`-tagged Go suite (test/integration, built by `make
# lab-build`) into every requested VM, runs it as root, and writes a
# markdown report to lab/reports/<YYYY-MM-DD-HHMM>.md — the VM x suite
# evidence table phases 15-21 must attach. Default VMs: $LAB_AGENT_VMS
# (lab-attacker is never a suite target: no agent, no CSF to assert on).
#
# NOT `set -e`: one VM's test failure must not abort the loop before
# every VM has been tried and the report reflects the whole matrix.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"
# lib.sh/matrix.sh each `set -euo pipefail` when sourced, and `source`
# runs in this same shell — silently re-enabling `-e` here. Explicitly
# turn it back off: a single VM's non-zero test exit must not abort the
# loop before every VM has been tried (see the file header comment).
set +e

vms="$*"
[ -n "$vms" ] || vms="$LAB_AGENT_VMS"

preflight_orb

TS="$(date +%Y-%m-%d-%H%M)"
REPORT="$LAB_DIR/reports/$TS.md"
REPORT_REL="lab/reports/$TS.md"

# repo_sha DIR -> short sha, suffixed "-dirty" iff `git status --porcelain`
# is non-empty for DIR at run time — never hard-coded or assumed clean.
repo_sha() {
  local dir=$1 sha
  sha="$(git -C "$dir" rev-parse --short HEAD)"
  if [ -n "$(git -C "$dir" status --porcelain)" ]; then
    sha="$sha-dirty"
  fi
  printf '%s' "$sha"
}

# Captured BEFORE the report file is created below, not inside
# write_header: the report lands inside $REPO_DIR itself (as
# lab/reports/$TS.md), so computing `git status --porcelain` for
# $REPO_DIR AFTER that file exists would make the agent worktree look
# "-dirty" purely because of this run's own output — a self-inflicted
# false positive that would make a clean worktree impossible to ever
# report as clean.
AGENT_SHA="$(repo_sha "$REPO_DIR")"
PANEL_SHA="$(repo_sha "$PANEL_DIR")"

mkdir -p "$LAB_DIR/reports/raw"
# TS has minute granularity: two runs started in the same clock-minute
# would otherwise both >> onto the same path. Truncate up front (both
# the success and the verify-gate-fail path only ever append from here
# on) so a same-minute rerun overwrites cleanly instead of concatenating
# a second header/table onto the first run's content.
: >"$REPORT"

# expect_or_empty VALUE — lab/matrix.sh's "-" sentinel ("not applicable")
# must cross the env boundary as an empty string per the env contract
# (LAB_EXPECT_* empty means "this assertion does not apply here").
expect_or_empty() {
  if [ "$1" = "-" ]; then
    printf ''
  else
    printf '%s' "$1"
  fi
}

# csf_expect VM -> 1 if the VM's role has CSF installed at all, else 0.
csf_expect() {
  case "$(vm_role "$1")" in
    csf | csf-orphan) printf '1' ;;
    *) printf '0' ;;
  esac
}

# csfv_col VM -> the raw `csf -v` version line (CSF VMs only), or "-".
csfv_col() {
  local vm=$1 out
  case "$(vm_role "$vm")" in
    csf | csf-orphan)
      out="$(vm_root "$vm" sh -c 'csf -v 2>&1 | grep -E "v1[0-9]" | head -1' 2>/dev/null || true)"
      if [ -n "$out" ]; then printf '%s' "$out"; else printf -- '-'; fi
      ;;
    *) printf -- '-' ;;
  esac
}

write_header() {
  {
    printf '# CSF Lab report %s\n\n' "$TS"
    printf -- '- agent: %s\n' "$AGENT_SHA"
    printf -- '- forks.lock: %s\n' "$(sha256_of "$LAB_DIR/forks.lock")"
    printf -- '- orbstack: %s\n' "$(orb version 2>&1 | head -1)"
    printf -- '- panel: %s\n' "$PANEL_SHA"
    printf -- '- host arch: %s\n' "$(uname -m)"
    printf '\n'
  } >>"$1"
}

# --- Gate: a broken lab must never be blamed on the agent --------------
# verify.sh also rotates the lab panel's Sanctum token, so the api_token
# read below (via panel_api_token) always reflects the latest.
verify_out="$("$LAB_DIR/verify.sh" "$@" 2>&1)"
verify_rc=$?
if [ "$verify_rc" -ne 0 ]; then
  write_header "$REPORT"
  {
    printf '**Overall: FAIL (lab broken: verify.sh)**\n\n'
    printf '```\n%s\n```\n' "$verify_out"
  } >>"$REPORT"
  log "lab is broken (verify.sh exit $verify_rc) - see $REPORT_REL"
  printf '%s\n' "$REPORT_REL"
  exit 1
fi

TOKEN="$(panel_api_token)"
BINARY="$REPO_DIR/build/integration-linux-$LAB_ARCH.test"
[ -f "$BINARY" ] || die "integration test binary missing: $BINARY (run 'make lab-build' first)"

write_header "$REPORT"
printf '| VM | fork | csf -v | suite | pass | fail | skip | seconds | result |\n' >>"$REPORT"
printf '|----|------|--------|-------|------|------|------|---------|--------|\n' >>"$REPORT"

failed_vms=""

for vm in $vms; do
  RAW="$LAB_DIR/reports/raw/$TS-$vm.log"
  vm_push "$vm" "$BINARY" /root/integration.test

  fork="$(vm_fork "$vm")"
  expect_csf="$(csf_expect "$vm")"
  csf_version="$(expect_or_empty "$(vm_csf_version "$vm")")"
  testing_expect="$(expect_or_empty "$(vm_testing "$vm")")"
  lfd_expect="$(expect_or_empty "$(vm_lfd "$vm")")"
  fw_mode="$(expect_or_empty "$(vm_fw_mode "$vm")")"

  start=$(date +%s)
  vm_root "$vm" env \
    LAB_VM="$vm" \
    LAB_FORK="$fork" \
    LAB_EXPECT_CSF="$expect_csf" \
    LAB_EXPECT_CSF_VERSION="$csf_version" \
    LAB_EXPECT_TESTING="$testing_expect" \
    LAB_EXPECT_LFD="$lfd_expect" \
    LAB_EXPECT_FW_MODE="$fw_mode" \
    LAB_EXPECT_AGENT=1 \
    LAB_PANEL_URL="$PANEL_URL_VM" \
    LAB_PANEL_TOKEN="$TOKEN" \
    LAB_FORCE_FAIL="${LAB_FORCE_FAIL:-}" \
    /root/integration.test -test.v -test.count=1 -test.timeout 5m -test.run '^TestLab' >"$RAW" 2>&1
  rc=$?
  seconds=$(($(date +%s) - start))

  pass=$(grep -c '^--- PASS' "$RAW" || true)
  fail=$(grep -c '^--- FAIL' "$RAW" || true)
  skip=$(grep -c -- '--- SKIP' "$RAW" || true)

  # A VM-level SKIP is only legal in CI (LAB_ALLOW_SKIP=1, no lab here) —
  # inside the lab every assertion must apply, so any SKIP counts as a
  # failed row, same as rc!=0 or fail>0.
  if [ "$rc" -eq 0 ] && [ "$fail" -eq 0 ] && [ "$skip" -eq 0 ] && [ "$pass" -gt 0 ]; then
    result="PASS"
  else
    result="FAIL"
    failed_vms="$failed_vms $vm"
  fi

  csfv="$(csfv_col "$vm")"
  printf '| %s | %s | %s | lab | %s | %s | %s | %s | %s |\n' \
    "$vm" "$fork" "$csfv" "$pass" "$fail" "$skip" "$seconds" "$result" >>"$REPORT"
  log "$vm: pass=$pass fail=$fail skip=$skip seconds=${seconds}s result=$result"
done

# --- attack stage (plan 08) ---
# Runs lab/attack.sh against debian12-nocsf (real SSH/WordPress/IMAP
# brute force from lab-attacker) and asserts the resulting events/bans
# are observed in the local panel via TestAttackEventsReachPanel — not a
# fixture, not a simulated call. Only runs when debian12-nocsf is in this
# run's VM list (it is the lab's one fixed attack target); skippable via
# LAB_SKIP_ATTACK=1 (saves ~3min on a quick CSF-only run). Any failure
# here counts toward the same overall FAIL as the per-VM loop above.
attack_pass=0 attack_fail=0 attack_skip=0 attack_seconds=0 attack_result="SKIP"
case " $vms " in
  *" debian12-nocsf "*)
    if [ "${LAB_SKIP_ATTACK:-}" = "1" ]; then
      log "attack: skipped (LAB_SKIP_ATTACK=1)"
    else
      ATTACK_RAW="$LAB_DIR/reports/raw/$TS-attack.log"
      attack_start=$(date +%s)
      # attack.sh's own `all` leg only re-prepares when .state/attack.env
      # is missing or names a different target (lab/attack.sh
      # do_prepare_if_needed) — across repeated `make lab-test` runs the
      # target is always debian12-nocsf, so without this, a second run
      # would silently reuse the FIRST run's already-banned IPs and the
      # integration test would "pass" against stale panel events instead
      # of this run's own traffic. Forcing a fresh prepare every time is
      # what actually proves "fresh source IPs per run, stays green on
      # repeated runs" rather than just replaying the first run's result.
      rm -f "$LAB_DIR/.state/attack.env"
      "$LAB_DIR/attack.sh" debian12-nocsf all >"$ATTACK_RAW" 2>&1
      attack_rc=$?
      if [ "$attack_rc" -ne 0 ]; then
        attack_fail=1
        attack_result="FAIL"
        attack_seconds=$(($(date +%s) - attack_start))
        failed_vms="$failed_vms attack"
        log "attack: lab/attack.sh itself failed (rc=$attack_rc) - see reports/raw/$TS-attack.log"
      else
        # attack.sh wrote lab/.state/attack.env with the three run-specific
        # TEST-NET-3 IPs — source it so the integration test's env matches
        # exactly what was actually attacked this run (never hard-coded).
        # shellcheck disable=SC1091
        source "$LAB_DIR/.state/attack.env"
        # Re-read the token fresh here rather than reusing the $TOKEN
        # captured near the top of this script: the attack.sh run above
        # (traffic generation) takes real wall-clock time, and the lab's
        # single shared 'lab' Sanctum token is revoked+reissued by EVERY
        # lab:bootstrap call (direct, or via any concurrently-run
        # verify.sh/panel-up.sh) — observed live (2026-11-05): a token
        # captured at the top of this script 401'd by the time this stage
        # ran, after a concurrent lab:bootstrap elsewhere rotated it. This
        # narrows the staleness window to just the attack-stage test run
        # instead of this whole script's wall-clock.
        vm_root debian12-nocsf env \
          LAB_VM=debian12-nocsf \
          LAB_PANEL_URL="$PANEL_URL_VM" \
          LAB_PANEL_TOKEN="$(panel_api_token)" \
          LAB_ATTACK_SSH_IP="$LAB_ATTACK_SSH_IP" \
          LAB_ATTACK_WEB_IP="$LAB_ATTACK_WEB_IP" \
          LAB_ATTACK_MAIL_IP="$LAB_ATTACK_MAIL_IP" \
          /root/integration.test -test.v -test.count=1 -test.timeout 6m -test.run '^TestAttack' >>"$ATTACK_RAW" 2>&1
        attack_test_rc=$?
        attack_seconds=$(($(date +%s) - attack_start))
        attack_pass=$(grep -c '^--- PASS' "$ATTACK_RAW" || true)
        attack_fail=$(grep -c '^--- FAIL' "$ATTACK_RAW" || true)
        attack_skip=$(grep -c -- '--- SKIP' "$ATTACK_RAW" || true)
        if [ "$attack_test_rc" -eq 0 ] && [ "$attack_fail" -eq 0 ] && [ "$attack_skip" -eq 0 ] && [ "$attack_pass" -gt 0 ]; then
          attack_result="PASS"
        else
          attack_result="FAIL"
          failed_vms="$failed_vms attack"
        fi
      fi
      printf '| debian12-nocsf | none | - | attack(ssh,web,mail) | %s | %s | %s | %s | %s |\n' \
        "$attack_pass" "$attack_fail" "$attack_skip" "$attack_seconds" "$attack_result" >>"$REPORT"
      log "attack: pass=$attack_pass fail=$attack_fail skip=$attack_skip seconds=${attack_seconds}s result=$attack_result"
    fi
    ;;
esac

if [ -z "${failed_vms// /}" ]; then
  printf '\n**Overall: PASS**\n' >>"$REPORT"
  overall_rc=0
else
  printf '\n**Overall: FAIL**\n' >>"$REPORT"
  overall_rc=1
fi

if [ "$overall_rc" -ne 0 ]; then
  printf '\n## Failures\n' >>"$REPORT"
  for vm in $failed_vms; do
    RAW="$LAB_DIR/reports/raw/$TS-$vm.log"
    printf '\n### %s\n\n```\n' "$vm" >>"$REPORT"
    # A failure doesn't always come from the Go integration binary (which
    # prints the '--- FAIL' marker this grep targets): attack.sh itself
    # can die() before the binary ever runs (e.g. a provisioning or
    # connectivity-check failure), leaving a raw log with no such marker
    # at all — observed live (2026-11-05): that case produced a report
    # with a correctly-identified FAIL row but a completely empty
    # Failures section, no diagnostic output whatsoever. Fall back to the
    # raw log's own tail so a failure NEVER ships with zero evidence.
    snippet="$(grep -n -B5 -A20 -- '--- FAIL' "$RAW" 2>/dev/null | head -30)"
    if [ -n "$snippet" ]; then
      printf '%s\n' "$snippet" >>"$REPORT"
    else
      tail -30 "$RAW" 2>/dev/null >>"$REPORT"
    fi
    printf '```\n' >>"$REPORT"
  done
fi

log "report: $REPORT_REL"
printf '%s\n' "$REPORT_REL"
exit "$overall_rc"
