#!/usr/bin/env bash
# lab/diagnose-firewall.sh [--expect-enforced] <vm>...
#
# NFT-01 diagnosis: for each VM, measures (not predicts) whether IPv4 bans,
# IPv6 bans, watcher-path bans and geoblocking are actually enforced in the
# kernel with the CURRENT (unmodified at the time of the first run) agent,
# and whether the panel's view agrees with the kernel. Writes
# lab/reports/nft-diagnosis-<TS>.md (one section per VM) plus a raw command
# log per VM under lab/reports/raw/. bash 3.2 safe (macOS ships 3.2).
#
# Not `set -e`: most of the interesting evidence here comes from commands
# that are EXPECTED to fail on some scenarios (ipset test, iptables -C,
# panel_post 422) — a single such failure must never abort the whole run
# before every VM and every check has been attempted.
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=lab/matrix.sh
source "$LAB_DIR/matrix.sh"
set +e

expect_enforced=0
vms=""
for arg in "$@"; do
  case "$arg" in
    --expect-enforced) expect_enforced=1 ;;
    *) vms="$vms $arg" ;;
  esac
done
vms="${vms# }"
[ -n "$vms" ] || die "usage: diagnose-firewall.sh [--expect-enforced] <vm>..."

preflight_orb

TS="$(date +%Y-%m-%d-%H%M)"
REPORT="$LAB_DIR/reports/nft-diagnosis-$TS.md"
RAW_DIR="$LAB_DIR/reports/raw"
mkdir -p "$RAW_DIR"
: >"$REPORT"

violations=0
created_ban_ids=""

printf '# NFT-01 firewall diagnosis %s\n\n' "$TS" >>"$REPORT"
printf -- '- agent: %s\n' "$(git -C "$LAB_DIR/.." rev-parse --short HEAD)" >>"$REPORT"
printf -- '- orbstack: %s\n\n' "$(orb version 2>&1 | head -1)" >>"$REPORT"

# --- facts (per VM, raw log only, summarised line in report) --------------
diag_facts() {
  local vm=$1 raw=$2
  {
    echo "== facts: $vm =="
    vm_root "$vm" grep PRETTY_NAME /etc/os-release
    vm_root "$vm" uname -r
    echo "-- tool presence --"
    vm_root "$vm" sh -c 'command -v ipset iptables ip6tables nft firewall-cmd csf || true'
    vm_root "$vm" sh -c 'ipset --version 2>&1 || true'
    vm_root "$vm" sh -c 'iptables --version 2>&1 || true'
    vm_root "$vm" sh -c 'nft --version 2>&1 || true'
    echo "-- daemons --"
    vm_root "$vm" systemctl is-active firewalld csf lfd defensia-agent
    echo "-- kernel netfilter config --"
    vm_root "$vm" sh -c "zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(NF_TABLES|IP_SET|NFT_COMPAT|NETFILTER_XT_SET)=' || echo 'no /proc/config.gz'"
    echo "-- nft tables --"
    vm_root "$vm" sh -c 'nft list tables 2>&1 || true'
    echo "-- firewalld hook priority (Open Question 2) --"
    vm_root "$vm" sh -c 'nft -a list chain inet firewalld filter_INPUT 2>/dev/null | grep -E "hook|priority" || echo "n/a (no firewalld chain)"'
    echo "-- dnf iptables resolution (Open Question 6) --"
    vm_root "$vm" sh -c 'dnf -q repoquery --whatprovides iptables 2>&1 || true'
    vm_root "$vm" sh -c "dnf -q --assumeno install iptables 2>&1 | grep -Ei iptables | head -5 || true"
    echo "-- agent version + firewall/geoblock journal --"
    vm_root "$vm" sh -c '/usr/local/bin/defensia-agent version 2>&1 | head -1 || /usr/local/bin/defensia-agent --version 2>&1 | head -1'
    vm_root "$vm" sh -c "journalctl -u defensia-agent --no-pager 2>/dev/null | grep -E '\[firewall\]|\[geoblock\]|\[geoip\]' | tail -30"
  } >"$raw" 2>&1
}

# --- panel view -------------------------------------------------------------
panel_view() {
  local agent_id=$1 tmp
  tmp="$(mktemp)"
  panel_get "/api/v1/servers/$agent_id" >"$tmp" 2>/dev/null
  printf '%s|%s|%s' \
    "$(json_get "$tmp" firewall_mode 2>/dev/null)" \
    "$(json_get "$tmp" ban_capacity 2>/dev/null)" \
    "$(json_get "$tmp" active_bans_count 2>/dev/null)"
  rm -f "$tmp"
}

# --- kernel_has_ban VM IP -> 0 if the kernel enforces a block on IP --------
kernel_has_ban() {
  local vm=$1 ip=$2
  vm_root "$vm" sh -c "ipset test defensia-bans '$ip' 2>/dev/null" && return 0
  vm_root "$vm" sh -c "ipset test defensia-bans6 '$ip' 2>/dev/null" && return 0
  vm_root "$vm" sh -c "iptables -C INPUT -s '$ip' -j DROP 2>/dev/null" && return 0
  vm_root "$vm" sh -c "ip6tables -C INPUT -s '$ip' -j DROP 2>/dev/null" && return 0
  vm_root "$vm" sh -c "nft list ruleset 2>/dev/null | grep -qF '$ip'" && return 0
  return 1
}

# --- sync_ban_check VM AGENT_ID FAMILY(v4|v6) -> prints "VERDICT|BAN_ID|IP" -
sync_ban_check() {
  local vm=$1 agent_id=$2 family=$3 candidates ip post_out ban_id verdict waited

  if [ "$family" = v4 ]; then
    candidates="198.51.100.$((RANDOM % 231 + 20)) 203.0.113.$((RANDOM % 254 + 1)) 192.0.2.$((RANDOM % 254 + 1))"
  else
    candidates="2001:db8:d1a9::$(printf '%x' $((RANDOM % 65535))) 3fff:d1a9::$((RANDOM % 254 + 1))"
  fi

  ban_id="" ip="" verdict="PANEL REFUSED"
  for cand in $candidates; do
    post_out="$(panel_post "/api/v1/bans" "{\"ip_address\":\"$cand\",\"server_id\":$agent_id,\"reason\":\"phase17-diagnosis\"}" 2>/dev/null)"
    ban_id="$(printf '%s' "$post_out" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' 2>/dev/null)"
    if [ -n "$ban_id" ]; then
      ip="$cand"
      break
    fi
  done

  if [ -z "$ban_id" ]; then
    printf '%s|%s|%s' "PANEL REFUSED" "" ""
    return 0
  fi

  vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1

  waited=0
  while [ "$waited" -lt 120 ]; do
    if kernel_has_ban "$vm" "$ip"; then
      verdict="ENFORCED"
      break
    fi
    verdict="NOT ENFORCED"
    sleep 5
    waited=$((waited + 5))
  done

  printf '%s|%s|%s' "$verdict" "$ban_id" "$ip"
}

# --- watcher_ban_check VM AGENT_ID -> "VERDICT" ----------------------------
watcher_ban_check() {
  local vm=$1 agent_id=$2 waited panel_has_ban kernel_enforced attack_ip tmp rc_prepare

  "$LAB_DIR/attack.sh" "$vm" prepare >/dev/null 2>&1
  rc_prepare=$?
  "$LAB_DIR/attack.sh" "$vm" ssh >/dev/null 2>&1

  if [ "$rc_prepare" -ne 0 ] || [ ! -f "$LAB_DIR/.state/attack.env" ]; then
    printf '%s' "N/A (attack.sh: prepare failed)"
    return 0
  fi
  # shellcheck disable=SC1091
  attack_ip="$(grep '^LAB_ATTACK_SSH_IP=' "$LAB_DIR/.state/attack.env" | cut -d= -f2)"
  [ -n "$attack_ip" ] || { printf '%s' "N/A (attack.sh: no LAB_ATTACK_SSH_IP)"; return 0; }

  panel_has_ban=0
  waited=0
  while [ "$waited" -lt 120 ]; do
    tmp="$(mktemp)"
    panel_get "/api/v1/bans?server_id=$agent_id" >"$tmp" 2>/dev/null
    if grep -qF "\"$attack_ip\"" "$tmp" 2>/dev/null; then
      panel_has_ban=1
      rm -f "$tmp"
      break
    fi
    rm -f "$tmp"
    sleep 5
    waited=$((waited + 5))
  done

  if [ "$panel_has_ban" -eq 0 ]; then
    printf '%s' "NO BAN"
    return 0
  fi

  if kernel_has_ban "$vm" "$attack_ip"; then
    kernel_enforced=1
  else
    kernel_enforced=0
  fi

  if [ "$kernel_enforced" -eq 1 ]; then
    printf '%s' "WATCHER BAN ENFORCED"
  else
    printf '%s' "PANEL SHOWS BAN, KERNEL DOES NOT"
  fi
}

# --- geoblock_check VM AGENT_ID -> "VERDICT" -------------------------------
# Kernel evidence must look for the COUNTRY set, never for the backend's own
# always-present table/chain (REVIEW.md WARN-01, 2026-11-18): nftBackend's
# Ensure() creates the `inet defensia` table and its `geo` CHAIN on every
# nftables host regardless of whether any country is actually blocked
# (nft_script.go's nftEnsureScript), so `nft list tables | grep defensia`
# is true unconditionally and can never return SILENT/REPORTED on an
# nftables VM - it was measuring backend selection, not geoblocking. The
# per-country SET (`geo_<cc>`, nft_script.go's nftGeoReplaceScript) is only
# ever created when a country is actually configured, which is the nftables
# equivalent of the ipset branch's `defensia-geo-<cc>` set check below.
geoblock_check() {
  local vm=$1 agent_id=$2 fw_mode kernel_evidence panel_evidence tmp

  fw_mode="$(vm_fw_mode "$vm")"

  panel_tinker "\$a = App\\Models\\Agent::find($agent_id); \$a->blocked_countries = ['CN']; \$a->save();" >/dev/null 2>&1
  vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1
  sleep 60

  case "$fw_mode" in
    nftables)
      kernel_evidence="$(vm_root "$vm" sh -c "nft list sets inet defensia 2>/dev/null | grep 'set geo_'")"
      ;;
    *)
      kernel_evidence="$(vm_root "$vm" sh -c "ipset list -n 2>/dev/null | grep defensia-geo")"
      ;;
  esac

  tmp="$(mktemp)"
  panel_get "/api/v1/events?server_id=$agent_id&type=firewall_unavailable&since=1%20hour&per_page=100" >"$tmp" 2>/dev/null
  panel_evidence="$(grep -i 'geoblock' "$tmp" 2>/dev/null)"
  rm -f "$tmp"

  panel_tinker "\$a = App\\Models\\Agent::find($agent_id); \$a->blocked_countries = []; \$a->save();" >/dev/null 2>&1
  vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1

  if [ -n "$kernel_evidence" ]; then
    printf '%s' "ENFORCED"
  elif [ -n "$panel_evidence" ]; then
    printf '%s' "REPORTED"
  else
    printf '%s' "SILENT"
  fi
}

# ensure_active_protection is defined in lib.sh (shared with attack.sh and
# test.sh) — without it, syncAndApply's own
# `if !sync.Config.MonitorMode { firewall.ApplyBans(...) }` guard skips
# every single ban regardless of backend, which would make this whole
# diagnosis report "NOT ENFORCED" uniformly and hide the real ipset vs
# iptables vs nftables difference it exists to measure.

# --- main loop --------------------------------------------------------------
for vm in $vms; do
  RAW="$RAW_DIR/nft-diagnosis-$TS-$vm.log"
  diag_facts "$vm" "$RAW"

  agent_id="$(config_agent_id "$vm")"
  fw_variant="$(vm_fw_variant "$vm")"

  printf '## %s (variant: %s)\n\n' "$vm" "$fw_variant" >>"$REPORT"

  if [ -z "$agent_id" ]; then
    printf 'No agent_id in /etc/defensia/config.json — skipping.\n\n' >>"$REPORT"
    continue
  fi

  ap_out="$(ensure_active_protection "$vm")"
  case "$ap_out" in
    toggled-off|already-off) : ;;
    *) die "diagnose-firewall.sh: ensure_active_protection($vm) failed: $ap_out" ;;
  esac
  vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1
  sleep 5

  pv_out="$(panel_view "$agent_id")"
  pv_mode="${pv_out%%|*}"
  pv_rest="${pv_out#*|}"
  pv_capacity="${pv_rest%%|*}"
  pv_bans="${pv_rest#*|}"

  v4_result="$(sync_ban_check "$vm" "$agent_id" v4)"
  v4_verdict="${v4_result%%|*}"
  v4_ban_id="$(printf '%s' "$v4_result" | cut -d'|' -f2)"
  [ -n "$v4_ban_id" ] && created_ban_ids="$created_ban_ids $v4_ban_id"
  v6_result="$(sync_ban_check "$vm" "$agent_id" v6)"
  v6_verdict="${v6_result%%|*}"
  v6_ban_id="$(printf '%s' "$v6_result" | cut -d'|' -f2)"
  [ -n "$v6_ban_id" ] && created_ban_ids="$created_ban_ids $v6_ban_id"
  watcher_verdict="$(watcher_ban_check "$vm" "$agent_id")"
  geoblock_verdict="$(geoblock_check "$vm" "$agent_id")"

  {
    printf '| check | observed | verdict |\n'
    printf '|-------|----------|---------|\n'
    printf '| firewall_mode reported | %s | - |\n' "${pv_mode:-<empty>}"
    printf '| capacity reported | %s | - |\n' "${pv_capacity:-<empty>}"
    printf '| IPv4 sync ban | %s | %s |\n' "$(printf '%s' "$v4_result" | cut -d'|' -f3)" "$v4_verdict"
    printf '| IPv6 sync ban | %s | %s |\n' "$(printf '%s' "$v6_result" | cut -d'|' -f3)" "$v6_verdict"
    printf '| watcher ban | - | %s |\n' "$watcher_verdict"
    printf '| panel-vs-kernel consistency | - | %s |\n' \
      "$([ "$watcher_verdict" = "PANEL SHOWS BAN, KERNEL DOES NOT" ] && echo "INCONSISTENT" || echo "consistent")"
    printf '| geoblock | - | %s |\n' "$geoblock_verdict"
    printf '| backend log line | see raw log %s | - |\n' "$(basename "$RAW")"
    printf '\n'
  } >>"$REPORT"

  case "$v4_verdict" in "NOT ENFORCED") violations=$((violations + 1)) ;; esac
  case "$v6_verdict" in "NOT ENFORCED") violations=$((violations + 1)) ;; esac
  case "$watcher_verdict" in
    "PANEL SHOWS BAN, KERNEL DOES NOT"|"NO BAN") violations=$((violations + 1)) ;;
  esac
  case "$geoblock_verdict" in "SILENT") violations=$((violations + 1)) ;; esac
done

# --- cleanup: remove every ban this run created ----------------------------
for id in $created_ban_ids; do
  panel_delete "/api/v1/bans/$id" >/dev/null 2>&1
done
for vm in $vms; do
  vm_root "$vm" systemctl restart defensia-agent >/dev/null 2>&1
done

printf '## Cleanup\n\n%s ban(s) created this run, all deleted via panel_delete.\n' "$(printf '%s' "$created_ban_ids" | wc -w | tr -d ' ')" >>"$REPORT"

log "report: $(basename "$REPORT")"
printf '%s\n' "lab/reports/$(basename "$REPORT")"

if [ "$expect_enforced" -eq 1 ] && [ "$violations" -gt 0 ]; then
  exit 1
fi
exit 0
