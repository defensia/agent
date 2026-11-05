#!/usr/bin/env bash
# lab/attack.sh <target-vm> <prepare|ssh|web|mail|all> [--count N]
#
# Sends real SSH, WordPress (wp-login/xmlrpc) and IMAP brute-force traffic
# from lab-attacker against <target-vm>, using fresh TEST-NET-3
# (203.0.113.0/24) source-IP aliases each run so earlier bans never mask a
# new one. Not `set -e`: a `prepare` connectivity hiccup or one failed
# attack attempt (sshpass/curl naturally return non-zero on an auth
# failure — that IS the point) must never abort the whole leg. bash 3.2
# safe (macOS ships 3.2): no associative arrays.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"
# lib.sh/matrix.sh each set -e when sourced (source runs in this shell) —
# turn it back off, same reason as lab/test.sh.
set +e

ATTACKER_VM="lab-attacker"
STATE_FILE="$LAB_DIR/.state/attack.env"

target=${1:?"usage: attack.sh <target-vm> <prepare|ssh|web|mail|all> [--count N]"}
leg=${2:?"usage: attack.sh <target-vm> <prepare|ssh|web|mail|all> [--count N]"}
shift 2

count=""
while [ $# -gt 0 ]; do
  case "$1" in
    --count)
      count=${2:?"--count needs a number"}
      shift 2
      ;;
    *)
      die "attack.sh: unknown argument '$1'"
      ;;
  esac
done

preflight_orb

# attacker_ip4 VM ALIAS -> picks one of the 3 run-specific TEST-NET-3
# aliases out of attack.env (ssh|web|mail).
load_state() {
  [ -f "$STATE_FILE" ] || die "attack.sh: no $STATE_FILE — run 'attack.sh $target prepare' first"
  # shellcheck disable=SC1090
  source "$STATE_FILE"
  [ -n "${LAB_ATTACK_SSH_IP:-}" ] || die "attack.sh: $STATE_FILE has no LAB_ATTACK_SSH_IP"
}

# ensure_active_protection VM — flips the target agent's monitor_mode off
# via a direct DB update (the same effect as a human toggling "Active
# Protection" on in the panel UI for that server).
#
# New agents are registered with monitor_mode=true by design
# (AgentService::register, app/Services/AgentService.php:58) — a brand
# new install defaults to detect-only so nobody gets locked out of their
# own box the moment the agent starts. The lab's attack target has to be
# taken out of that default, exactly as a real operator would, or every
# leg below would only ever produce a "(monitor mode)" log line and a
# `brute_force`/`wp_bruteforce`/`mail_brute_force` event — never the real
# ipset ban this plan's acceptance criteria requires. Idempotent (no-op
# once already false); takes effect on the target's next agent restart,
# which target-services.sh always performs right after this call.
ensure_active_protection() {
  local vm=$1
  panel_compose exec -T app php artisan tinker --execute="
    \$a = \App\Models\Agent::where('name', '$vm')->first();
    if (!\$a) { echo 'ERROR: no agent named $vm'; exit(1); }
    if (\$a->monitor_mode) { \$a->update(['monitor_mode' => false]); echo 'toggled-off'; } else { echo 'already-off'; }
  " 2>&1 | tail -1
}

# --- prepare: fresh TEST-NET-3 aliases + routing + state file ------------
do_prepare() {
  log "attack: preparing $target (active protection + target-services + fresh 203.0.113.x aliases)"

  local ap_out
  ap_out="$(ensure_active_protection "$target")"
  case "$ap_out" in
    toggled-off|already-off) log "attack: $target active protection: $ap_out" ;;
    *) die "attack.sh: ensure_active_protection($target) failed: $ap_out" ;;
  esac

  local family
  family="$(vm_family "$target")"
  vm_push "$target" "$LAB_DIR/provision/target-services.sh" /root/lab-provision/target-services.sh
  vm_root "$target" bash /root/lab-provision/target-services.sh "$family" \
    || die "attack.sh: target-services.sh failed on $target"

  local target_ip
  target_ip="$(vm_ip "$target")"
  [ -n "$target_ip" ] || die "attack.sh: could not read $target's IPv4"

  # Remove any TEST-NET-3 aliases left by a previous run (bash 3.2: no
  # readarray; a plain for-loop over command output is fine here).
  vm_root "$ATTACKER_VM" bash -c '
    for a in $(ip -4 -o addr show dev eth0 | awk "{print \$4}" | grep "^203\.0\.113\."); do
      ip addr del "$a" dev eth0
    done
  '

  # Three distinct random octets in 20..250 (bash 3.2-safe: $RANDOM, no
  # arrays with set -u traps on an empty expansion).
  local o1 o2 o3
  o1=$((20 + RANDOM % 231))
  o2=$o1
  while [ "$o2" = "$o1" ]; do o2=$((20 + RANDOM % 231)); done
  o3=$o1
  while [ "$o3" = "$o1" ] || [ "$o3" = "$o2" ]; do o3=$((20 + RANDOM % 231)); done

  local ssh_ip="203.0.113.$o1" web_ip="203.0.113.$o2" mail_ip="203.0.113.$o3"

  for ip in "$ssh_ip" "$web_ip" "$mail_ip"; do
    vm_root "$ATTACKER_VM" ip addr add "$ip/32" dev eth0 \
      || die "attack.sh: could not add alias $ip on $ATTACKER_VM"
  done

  vm_root "$ATTACKER_VM" ip route replace "$target_ip/32" dev eth0
  vm_root "$target" ip route replace 203.0.113.0/24 dev eth0

  mkdir -p "$(dirname "$STATE_FILE")"
  {
    printf 'LAB_ATTACK_TARGET=%s\n' "$target"
    printf 'LAB_ATTACK_TARGET_IP=%s\n' "$target_ip"
    printf 'LAB_ATTACK_SSH_IP=%s\n' "$ssh_ip"
    printf 'LAB_ATTACK_WEB_IP=%s\n' "$web_ip"
    printf 'LAB_ATTACK_MAIL_IP=%s\n' "$mail_ip"
    printf 'LAB_ATTACK_SINCE=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >"$STATE_FILE"

  # Connectivity check: an alias that doesn't actually route would make
  # every later leg fail with "connection refused/timeout" that looks
  # identical to "the agent isn't detecting this" — catch it here instead.
  #
  # One retry, not a silent pass: target-services.sh just (synchronously,
  # above in this same prepare()) restarted nginx on $target, and a
  # `systemctl restart` can return before the new process has actually
  # bound its listening socket — observed live (2026-11-05): the first
  # curl got '000' immediately after a restart, a manual re-run moments
  # later succeeded with no code change. Re-check once after a short pause
  # before declaring real alias/routing brokenness.
  local code
  code="$(vm_root "$ATTACKER_VM" curl -s -o /dev/null -w '%{http_code}' --interface "$web_ip" --max-time 5 "http://$target_ip/" 2>/dev/null)"
  case "$code" in
    200|301|302|403|404) ;;
    *)
      sleep 2
      code="$(vm_root "$ATTACKER_VM" curl -s -o /dev/null -w '%{http_code}' --interface "$web_ip" --max-time 5 "http://$target_ip/" 2>/dev/null)"
      case "$code" in
        200|301|302|403|404) ;;
        *) die "attack.sh: alias routing broken (curl --interface $web_ip http://$target_ip/ -> '$code', expected 2xx/3xx/4xx, retried once)" ;;
      esac
      ;;
  esac

  log "attack: prepared (ssh=$ssh_ip web=$web_ip mail=$mail_ip -> $target_ip)"
}

# do_prepare_if_needed: only re-prepare if attack.env is missing or points
# at a different target — `all` runs prepare+ssh+web+mail in one call and
# must not burn 3 fresh IP sets for what the caller sees as one run.
do_prepare_if_needed() {
  if [ ! -f "$STATE_FILE" ]; then
    do_prepare
    return
  fi
  # shellcheck disable=SC1090
  ( source "$STATE_FILE"; [ "${LAB_ATTACK_TARGET:-}" = "$target" ] )
  if [ $? -ne 0 ]; then
    do_prepare
  fi
}

# --- ssh: real failed-password brute force --------------------------------
# Default 8: the agent's SSH threshold is 5 failures/5min (authlog.go) —
# 8 reliably crosses it once while leaving margin for one dropped attempt
# (calibrated 2026-11-05 against the live lab, see 14-08-SUMMARY.md).
do_ssh() {
  load_state
  local n=${count:-8}
  log "ATTACK ssh from $LAB_ATTACK_SSH_IP -> $LAB_ATTACK_TARGET x$n"
  # SSHPASS env var (sshpass -e), not `-p <literal>` on the command line:
  # avoids exposing the fake password in `ps aux` on the attacker VM, and
  # avoids tripping this repo's .gitleaks.toml `sshpass-literal` rule
  # (added after the real prod-password leak in scripts/release.sh,
  # Oct 2026) — the rule can't distinguish an obviously-fake lab-only
  # value from a real credential, so the fix is to not match its shape.
  vm_root "$ATTACKER_VM" bash -c "
    export SSHPASS=labwrong1
    for i in \$(seq 1 $n); do
      sshpass -e ssh -b '$LAB_ATTACK_SSH_IP' \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o ConnectTimeout=5 invalid\$i@'$LAB_ATTACK_TARGET_IP' true \
        >/dev/null 2>&1
      sleep 0.3
    done
  "
}

# --- web: xmlrpc.php abuse (first) + wp-login.php brute force (second) ----
# xmlrpc runs FIRST: once wp-login's own crossings ban the IP (below), the
# WebWatcher's `if w.banned[ip] { return }` early-return would silently
# swallow every later xmlrpc request — running it first guarantees its own
# event is real, observed traffic, not traffic the agent never looked at.
#
# Defaults 10 + 40, calibrated 2026-11-05 against the live lab (see
# 14-08-SUMMARY.md):
#   - xmlrpc_abuse: 25pts per 5-POST/1min crossing (weblog.go ruleXMLRPC);
#     10 POSTs cross it at least once — enough for one real xmlrpc_abuse
#     event. Not depended upon for the ban (wp-login provides that).
#   - wp_bruteforce: 30pts per 10-POST/2min crossing (ruleWPLogin);
#     thresholdObserve=30 reports the event on the FIRST crossing (10
#     POSTs), thresholdBlock=80 bans on the THIRD (30 POSTs) — 40 leaves
#     one full crossing of margin. The 0.3s inter-request sleep is load-
#     bearing, not cosmetic: addScore() dedupes repeat crossings of the
#     same (ip, eventType) within a 2s window, so a crossing cadence
#     faster than ~2s (e.g. the 0.2s/request pacing originally tried)
#     collapses all 4 crossings into the FIRST one only — the score never
#     leaves "observe" (30) and no ban ever fires. 10 POSTs * 0.3s = 3s
#     between crossings clears that window with margin.
#   - xmlrpc_abuse itself scores only 25pts/crossing — BELOW
#     thresholdObserve (30) on a single crossing, so it never reports an
#     event alone; it needs a SECOND crossing (50pts total) to clear 30,
#     and that second crossing must land >2s after the first or
#     addScore()'s dedup silently drops it (score never even added). 10
#     POSTs at 0.5s/request space the two 5-POST crossings ~2.5s apart,
#     clearing that window.
# A spoofed browser UA, not curl's real one: curl/python-requests/Go-http-
# client/etc. are all pre-seeded `security_scanner` bot fingerprints
# (database/seeders/BotFingerprintsSeeder.php, action=log) that the
# WebWatcher matches BEFORE it ever reaches the wp-login/xmlrpc threshold
# logic (internal/watcher/weblog.go: bot-fingerprint loop runs earlier in
# processLine and `return`s on a match) — found empirically during
# calibration 2026-11-05: every POST was logged as a `bot_detected` event
# and the wp_bruteforce/xmlrpc_abuse code path was never reached at all,
# no matter the volume. A spoofed browser UA is also simply more
# realistic credential-stuffing traffic (real attackers evade exactly
# this kind of fingerprinting the same way) — this is attack-script
# traffic shape, not a change to any agent detection code.
LAB_WEB_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

do_web() {
  load_state
  local xml_n=10 wp_n=${count:-40}
  log "ATTACK web(xmlrpc) from $LAB_ATTACK_WEB_IP -> $LAB_ATTACK_TARGET x$xml_n"
  vm_root "$ATTACKER_VM" bash -c "
    for i in \$(seq 1 $xml_n); do
      curl -s -o /dev/null --interface '$LAB_ATTACK_WEB_IP' --max-time 2 \
        -A '$LAB_WEB_UA' \
        -X POST 'http://$LAB_ATTACK_TARGET_IP/xmlrpc.php' >/dev/null 2>&1
      sleep 0.5
    done
  "
  log "ATTACK web(wp-login) from $LAB_ATTACK_WEB_IP -> $LAB_ATTACK_TARGET x$wp_n"
  vm_root "$ATTACKER_VM" bash -c "
    for i in \$(seq 1 $wp_n); do
      curl -s -o /dev/null --interface '$LAB_ATTACK_WEB_IP' --max-time 2 \
        -A '$LAB_WEB_UA' \
        -X POST -d 'log=admin&pwd=bad' 'http://$LAB_ATTACK_TARGET_IP/wp-login.php' >/dev/null 2>&1
      sleep 0.3
    done
  "
}

# --- mail: IMAP password-mismatch brute force ------------------------------
# Default 8: mail_brute_force threshold is 5/5min (maillog.go); 8 leaves
# margin for one line lost to log-rotation/buffering timing (calibrated
# 2026-11-05 against the live lab, see 14-08-SUMMARY.md).
do_mail() {
  load_state
  local n=${count:-8}
  log "ATTACK mail from $LAB_ATTACK_MAIL_IP -> $LAB_ATTACK_TARGET x$n"
  vm_root "$ATTACKER_VM" bash -c "
    for i in \$(seq 1 $n); do
      curl -s --interface '$LAB_ATTACK_MAIL_IP' --max-time 5 \
        --url 'imap://$LAB_ATTACK_TARGET_IP/' --user 'labmail:wrong'\$i \
        >/dev/null 2>&1
      sleep 0.3
    done
  "
}

case "$leg" in
  prepare) do_prepare ;;
  ssh) do_ssh ;;
  web) do_web ;;
  mail) do_mail ;;
  all)
    do_prepare_if_needed
    do_ssh
    do_web
    do_mail
    ;;
  *)
    die "attack.sh: unknown leg '$leg' (expected prepare|ssh|web|mail|all)"
    ;;
esac
