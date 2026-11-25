#!/usr/bin/env bash
# lab/csf-bench.sh — LAB ONLY. Benchmarks `csf -td`/`-tr` latency per CSF
# fork, captures real command outputs as test fixtures, and probes which
# test IP ranges each fork accepts for `csf -td`.
#
# LAB ONLY: edits /etc/csf/csf.conf and uses `csf -tf` inside the lab VMs
# for setup/cleanup/restore. The agent itself never does either of those —
# see internal/firewall/csf_cli.go's locked CLI surface (-v/-t/-td/-tr only).
#
# Usage: lab/csf-bench.sh [vm...]   (default: $LAB_CSF_VMS)
set -uo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
# shellcheck source=lib.sh
source "$LAB_DIR/lib.sh"
# shellcheck source=matrix.sh
source "$LAB_DIR/matrix.sh"

preflight_orb

# fixture_dir_for VM -> internal/firewall/testdata/ subdirectory name.
# vm_fork() answers "what CSF release is this" (original-15.00 for both
# alma9-csf-orig and alma8-csf-cwp-orphan, since they run the identical
# release) — but Phase 14 already keeps the orphan capture in its own
# testdata/cwp-orphan-15.00/ directory (distinct TESTING/downloadservers
# behaviour is the whole point of that fixture). Mirror that convention
# here instead of merging the orphan's captures into original-15.00/.
fixture_dir_for() {
  case "$1" in
    alma8-csf-cwp-orphan) echo "cwp-orphan-15.00" ;;
    *) vm_fork "$1" ;;
  esac
}

VMS="${*:-$LAB_CSF_VMS}"
TS="$(date +%Y-%m-%d-%H%M)"
REPORT="$LAB_DIR/reports/${TS}-csf-td-bench.md"
ENV_FILE="$LAB_DIR/ban-sync.env"
mkdir -p "$LAB_DIR/reports"

ROWS=""
PREFIXES_TMP="$(mktemp)"
trap 'rm -f "$PREFIXES_TMP"' EXIT

for vm in $VMS; do
  fork="$(vm_fork "$vm")"
  log "bench: $vm (fork=$fork)"

  testdata_dir="$REPO_DIR/internal/firewall/testdata/$(fixture_dir_for "$vm")"
  mkdir -p "$testdata_dir"

  # --- One VM session: setup, probe, fixtures, latency, restore ---------
  OUT="$(vm_root "$vm" bash -s <<'REMOTE'
set -uo pipefail
CONF=/etc/csf/csf.conf
BAK=/root/csf.conf.bench-bak
ORIG_LINE="$(grep '^DENY_TEMP_IP_LIMIT' "$CONF")"
# alma8-csf-cwp-orphan (TESTING=1) is DESIGNED so lfd never daemonises:
# matrix.sh own vm_lfd() expects it inactive, not active. Blindly running
# systemctl restart lfd on such a VM leaves it failed (killed) instead of
# inactive after this script exits, which trips lab/verify.sh. Record the
# real pre-bench state and restore exactly that, not just a plain restart.
# NOTE: no apostrophes anywhere in this heredoc body (even in comments):
# this whole block is nested inside a dollar-paren command substitution,
# so bash still quote-balance-checks every line, comments included.
LFD_WAS_ACTIVE=0
systemctl is-active lfd >/dev/null 2>&1 && LFD_WAS_ACTIVE=1
restore_lfd() {
  if [ "$LFD_WAS_ACTIVE" = "1" ]; then
    systemctl restart lfd >/dev/null 2>&1 || true
  else
    systemctl stop lfd >/dev/null 2>&1 || true
    systemctl reset-failed lfd >/dev/null 2>&1 || true
  fi
}

cp "$CONF" "$BAK"
sed -i 's/^DENY_TEMP_IP_LIMIT = .*/DENY_TEMP_IP_LIMIT = "2000"/' "$CONF"
csf -r >/dev/null 2>&1
restore_lfd
csf -tf >/dev/null 2>&1

echo "===PROBE==="
for p in 203.0.113.10 198.51.100.10 192.0.2.10 11.22.0.10; do
  echo "--p=$p--"
  csf -td "$p" 600 bench_probe 2>&1
done
echo "--p6=2001:db8::10--"
csf -td 2001:db8::10 600 bench_probe 2>&1
csf -tf >/dev/null 2>&1

echo "===PREFIX_DONE==="

echo "===FIXTURES==="
echo "---csf-v---"
csf -v 2>&1; echo "#exit=$?"
echo "---fixtures-end---"

echo "===LATENCY_DONE==="

cp "$BAK" "$CONF"
csf -tf >/dev/null 2>&1
csf -r >/dev/null 2>&1
restore_lfd
NEW_LINE="$(grep '^DENY_TEMP_IP_LIMIT' "$CONF")"
echo "===RESTORE_CHECK==="
echo "orig=$ORIG_LINE"
echo "new=$NEW_LINE"
REMOTE
)"
  echo "$OUT" > "/tmp/csf-bench-${vm}.raw.txt"
  log "$vm: probe+setup done, raw output saved to /tmp/csf-bench-${vm}.raw.txt"
done

log "First pass (probe) complete for: $VMS"
log "NOTE: fixture capture + latency timing continues below per VM."

# --- Pass 2: per-VM IP prefix determination from the saved raw output ---
LAB_BAN_PREFIX=""
LAB_BAN_PREFIX6=""
for vm in $VMS; do
  raw="/tmp/csf-bench-${vm}.raw.txt"
  [ -f "$raw" ] || continue
  for p in "203.0.113." "198.51.100." "192.0.2." "11.22.0."; do
    ip="${p}10"
    if grep -A2 -- "--p=${ip}--" "$raw" | grep -q "blocked on port"; then
      printf '%s\t%s\n' "$vm" "$p" >> "$PREFIXES_TMP"
    fi
  done
  if grep -A2 -- "--p6=2001:db8::10--" "$raw" | grep -q "blocked on port"; then
    printf '%s\t%s\n' "$vm" "2001:db8::" >> "$PREFIXES_TMP"
  fi
done

# Common prefix accepted by every working CSF VM. Tab-separated vm<TAB>prefix
# lines (tab, not colon, specifically so an IPv6 prefix like "2001:db8::"
# never confuses field-splitting).
ALL_PREFIXES="$(awk -F'\t' '{print $2}' "$PREFIXES_TMP" | sort -u)"
VM_COUNT_OK=0
for vm in $VMS; do
  [ "$(vm_fork "$vm")" = "none" ] && continue
  VM_COUNT_OK=$((VM_COUNT_OK + 1))
done
while IFS= read -r p; do
  [ -z "$p" ] && continue
  [[ "$p" == *":"* ]] && continue
  cnt="$(awk -F'\t' -v p="$p" '$2 == p' "$PREFIXES_TMP" | wc -l | tr -d ' ')"
  if [ "$cnt" -ge "$VM_COUNT_OK" ]; then
    LAB_BAN_PREFIX="$p"
    break
  fi
done <<< "$ALL_PREFIXES"
while IFS= read -r p; do
  [ -z "$p" ] && continue
  [[ "$p" != *":"* ]] && continue
  cnt="$(awk -F'\t' -v p="$p" '$2 == p' "$PREFIXES_TMP" | wc -l | tr -d ' ')"
  if [ "$cnt" -ge "$VM_COUNT_OK" ]; then
    LAB_BAN_PREFIX6="$p"
    break
  fi
done <<< "$ALL_PREFIXES"

if [ -z "$LAB_BAN_PREFIX" ]; then
  die "No IPv4 test prefix accepted by every working CSF VM — see /tmp/csf-bench-*.raw.txt" 1
fi
log "LAB_BAN_PREFIX=$LAB_BAN_PREFIX LAB_BAN_PREFIX6=${LAB_BAN_PREFIX6:-<none>}"

{
  echo "LAB_BAN_PREFIX=$LAB_BAN_PREFIX"
  echo "LAB_BAN_PREFIX6=$LAB_BAN_PREFIX6"
} > "$ENV_FILE"

# --- Pass 3: fixtures + latency per VM, now that we know the prefix -----
echo "| VM | fork | existing temp bans | -td p50 ms | -td p95 ms | -td max ms | -tr ms |" > "$REPORT.body"
echo "|----|------|---------------------|------------|------------|------------|--------|" >> "$REPORT.body"

for vm in $VMS; do
  fork="$(vm_fork "$vm")"
  testdata_dir="$REPO_DIR/internal/firewall/testdata/$(fixture_dir_for "$vm")"
  mkdir -p "$testdata_dir"
  P="$LAB_BAN_PREFIX"

  log "fixtures+latency: $vm"
  OUT2="$(vm_root "$vm" env P="$P" bash -s <<'REMOTE2'
set -uo pipefail
P="${P}"
csf -tf >/dev/null 2>&1

capture() { # name cmd...
  local name="$1"; shift
  "$@" > "/root/${name}.txt" 2>&1
  echo "#exit=$?" >> "/root/${name}.txt"
}

capture csf-td-ok csf -td "${P}20" 600 "defensia:bench"
capture csf-td-already csf -td "${P}20" 600 "defensia:bench"
capture csf-td-private csf -td 10.0.0.5 600 x
OWNIP="$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1 | head -1)"
capture csf-td-own csf -td "$OWNIP" 600 x
capture csf-t csf -t
cp /var/lib/csf/csf.tempban /root/csf-tempban.txt 2>/dev/null || echo "" > /root/csf-tempban.txt
capture csf-tr-ok csf -tr "${P}20"
capture csf-tr-notfound csf -tr "${P}20"
csf -tf >/dev/null 2>&1
capture csf-tr-empty csf -tr "${P}20"
capture csf-v csf -v

echo "===BENCH_START==="
for N in 100 500 1000; do
  csf -tf >/dev/null 2>&1
  # pre-fill to N entries (untimed)
  i=1
  base_octet3=1
  while [ "$i" -le "$N" ]; do
    oct2=$(( (i / 250) % 250 ))
    oct4=$(( i % 250 + 1 ))
    csf -td "10.${oct2}.${base_octet3}.${oct4}" 3600 prefill >/dev/null 2>&1
    i=$((i + 1))
  done
  echo "---N=$N---"
  j=1
  while [ "$j" -le 50 ]; do
    t0=$(date +%s%N)
    csf -td "${P}$((100 + j))" 600 benchlat >/dev/null 2>&1
    t1=$(date +%s%N)
    echo "td $(( (t1 - t0) / 1000000 ))"
    j=$((j + 1))
  done
  t0=$(date +%s%N)
  csf -tr "${P}150" >/dev/null 2>&1
  t1=$(date +%s%N)
  echo "tr $(( (t1 - t0) / 1000000 ))"
done
echo "===BENCH_END==="
csf -tf >/dev/null 2>&1

for f in csf-td-ok csf-td-already csf-td-private csf-td-own csf-t csf-tempban csf-tr-ok csf-tr-notfound csf-tr-empty csf-v; do
  echo "===FILE:${f}.txt==="
  cat "/root/${f}.txt" 2>/dev/null
done
REMOTE2
)"
  echo "$OUT2" > "/tmp/csf-bench-${vm}.pass3.txt"

  # Split FILE blocks into testdata/<fork>/
  python3 - "$testdata_dir" <<PYEOF
import re, sys
outdir = sys.argv[1]
with open("/tmp/csf-bench-${vm}.pass3.txt") as f:
    content = f.read()
blocks = re.split(r'===FILE:(\S+)===\n', content)
for i in range(1, len(blocks), 2):
    fname = blocks[i]
    body = blocks[i+1].split("===BENCH_START===")[0] if "===BENCH_START===" in blocks[i+1] else blocks[i+1]
    with open(outdir + "/" + fname, "w") as out:
        out.write(body.split("===FILE:")[0])
PYEOF

  # Compute p50/p95/max for existing-bans sizes from the bench markers
  python3 - "$vm" "$fork" <<PYEOF >> "$REPORT.body"
import re, sys
vm, fork = sys.argv[1], sys.argv[2]
with open("/tmp/csf-bench-${vm}.pass3.txt") as f:
    content = f.read()
sections = re.split(r'---N=(\d+)---', content)
for i in range(1, len(sections), 2):
    n = sections[i]
    body = sections[i+1]
    tds = [int(m) for m in re.findall(r'^td (\d+)', body, re.M)]
    trs = [int(m) for m in re.findall(r'^tr (\d+)', body, re.M)]
    tds.sort()
    if tds:
        p50 = tds[len(tds)//2]
        p95 = tds[int(len(tds)*0.95)-1] if len(tds) > 1 else tds[0]
        mx = tds[-1]
    else:
        p50 = p95 = mx = 0
    tr = trs[0] if trs else 0
    print(f"| {vm} | {fork} | {n} | {p50} | {p95} | {mx} | {tr} |")
PYEOF
done

{
  echo "# CSF -td latency benchmark"
  echo
  echo "Agent worktree: $(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null)$( [ -n "$(git -C "$REPO_DIR" status --porcelain 2>/dev/null)" ] && echo -dirty )"
  echo "forks.lock: $(sha256_of "$LAB_DIR/forks.lock" 2>/dev/null)"
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo
  cat "$REPORT.body"
  echo
  echo "LAB_BAN_PREFIX=$LAB_BAN_PREFIX"
  echo "LAB_BAN_PREFIX6=${LAB_BAN_PREFIX6:-}"
} > "$REPORT"
rm -f "$REPORT.body"

log "Report: $REPORT"
log "Env: $ENV_FILE"

# --- Restore checks -------------------------------------------------------
FAIL=0
for vm in $VMS; do
  raw="/tmp/csf-bench-${vm}.raw.txt"
  orig="$(grep '^orig=' "$raw" | sed 's/^orig=//')"
  new="$(grep '^new=' "$raw" | sed 's/^new=//')"
  if [ "$orig" != "$new" ]; then
    log "WARN: $vm DENY_TEMP_IP_LIMIT not restored exactly (orig='$orig' new='$new')"
    FAIL=1
  fi
done

exit $FAIL
