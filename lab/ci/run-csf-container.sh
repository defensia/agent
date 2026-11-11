#!/usr/bin/env bash
# lab/ci/run-csf-container.sh <test-binary-path>
#
# Boots a privileged systemd container (image pinned below), installs the
# pinned, sha256-verified CSF v15.00 (original-15.00) fork using the SAME
# lab/provision/{base,csf}.sh scripts the OrbStack lab uses (never a
# parallel copy), then runs the integration test binary (built with
# `-tags integration`) inside it against the CSF-only LAB_EXPECT_*
# contract. Runnable identically on a developer's Mac (OrbStack Docker,
# arm64) and on a GitHub Actions ubuntu-latest runner (amd64) — LAB-05.
#
# The ipset/xt_set diagnostic below is informational only: whether
# GitHub's hosted-runner kernel supports those modules inside a container
# was unverified at the time this script was written (14-RESEARCH.md
# "Open Q1"), so LAB_EXPECT_FW_MODE is left empty here and
# TestLabFirewallMode is allowed to skip (LAB_ALLOW_SKIP=1) rather than
# hard-gated like the 5 CSF tests below. Promote it to blocking only once
# a real CI run has recorded IPSET_OK.
set -euo pipefail

TEST_BIN=${1:?"usage: run-csf-container.sh <test-binary-path>"}
[ -f "$TEST_BIN" ] || { echo "ERROR: test binary not found: $TEST_BIN" >&2; exit 1; }

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_DIR="$(cd "$LAB_DIR/.." && pwd)"
NAME="${CSF_CONTAINER:-defensia-csf-ci}"
NOCSF_NAME="${NOCSF_CONTAINER:-defensia-nocsf-ci}"
LOG="$REPO_DIR/build/ci-integration.log"
NOCSF_LOG="$REPO_DIR/build/ci-integration-nocsf.log"
mkdir -p "$(dirname "$LOG")"

cleanup() {
  if [ "${KEEP_CONTAINER:-0}" != "1" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker rm -f "$NOCSF_NAME" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker rm -f "$NAME" >/dev/null 2>&1 || true

echo "[run-csf-container] fetching pinned original-15.00 fork tarball"
"$LAB_DIR/fetch-forks.sh" original-15.00

echo "[run-csf-container] starting $NAME (privileged systemd container)"
docker run -d --name "$NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  almalinux/9-init >/dev/null

# Shared by both passes (CSF and no-CSF) so they boot identically.
wait_systemd() {
  _c="$1"
  echo "[run-csf-container] waiting for systemd in $_c to report running/degraded (up to 120s)"
  _state=""
  _ready=0
  for _ in $(seq 1 24); do
    _state="$(docker exec "$_c" systemctl is-system-running --wait 2>&1 || true)"
    case "$_state" in
      running|degraded) _ready=1; break ;;
    esac
    sleep 5
  done
  if [ "$_ready" != 1 ]; then
    echo "ERROR: systemd in $_c never reached running/degraded (last state: $_state)" >&2
    docker logs "$_c" >&2 || true
    exit 1
  fi
  echo "[run-csf-container] $_c systemd state: $_state"
}

wait_systemd "$NAME"

docker cp "$LAB_DIR/provision" "$NAME:/root/lab-provision"
docker cp "$LAB_DIR/cache/original-15.00.tgz" "$NAME:/root/csf-original-15.00.tgz"

# The *-init systemd Docker images (unlike a real OrbStack VM install)
# pre-ship curl-minimal, which conflicts with the full `curl` package
# base.sh installs ("package curl-minimal ... conflicts with curl").
# Swap it before calling the shared script — this is a container-image
# accommodation, not a change to base.sh/csf.sh itself (LAB-05: reuse the
# lab's own provisioning scripts unmodified).
echo "[run-csf-container] swapping curl-minimal for curl (container-image quirk, base.sh itself is untouched)"
docker exec "$NAME" dnf -y swap curl-minimal curl

echo "[run-csf-container] provisioning base packages (same script as the OrbStack lab)"
docker exec "$NAME" bash /root/lab-provision/base.sh alma yes

echo "[run-csf-container] installing CSF v15.00 original-15.00 (same script as the OrbStack lab)"
docker exec "$NAME" bash /root/lab-provision/csf.sh original-15.00

echo "[run-csf-container] csf/lfd status:"
docker exec "$NAME" sh -c 'csf -v; systemctl is-active csf lfd; grep ^LF_IPSET /etc/csf/csf.conf'

echo "[run-csf-container] ipset/xt_set diagnostic (non-blocking, resolves 14-RESEARCH.md Open Q1):"
docker exec "$NAME" sh -c 'ipset create lab-diag hash:ip && ipset destroy lab-diag && echo IPSET_OK || echo IPSET_UNAVAILABLE' || true

docker cp "$TEST_BIN" "$NAME:/root/it.test"

echo "[run-csf-container] running integration tests (^TestLab)"
: >"$LOG"
set +e
docker exec \
  -e LAB_ALLOW_SKIP=1 \
  -e LAB_VM=ci-almalinux9 \
  -e LAB_FORK=original-15.00 \
  -e LAB_EXPECT_CSF=1 \
  -e LAB_EXPECT_CSF_VERSION=15.00 \
  -e LAB_EXPECT_TESTING=0 \
  -e LAB_EXPECT_LFD=active \
  -e LAB_EXPECT_FW_MODE= \
  -e LAB_EXPECT_CSF_FORK=original-15.00 \
  -e LAB_EXPECT_DL_CONFIGSERVER=0 \
  -e LAB_CSF_IPV6_TEST=0 \
  "$NAME" /root/it.test -test.v -test.count=1 -test.run '^TestLab' | tee "$LOG"
test_rc=${PIPESTATUS[0]}
set -e

echo "[run-csf-container] hard gate: these tests must PASS, not SKIP or FAIL"
for t in TestLabCSFDetection TestLabCSFVersion TestLabCSFTestingFlag TestLabLFDState TestLabCSFListsReadable \
  TestLabCSFCollectorFork TestLabCSFCollectorState TestLabCSFPortAddRemove TestLabCSFPortSSHGuard \
  TestLabCSFPortRollback TestLabNoCSFNoExec; do
  if ! grep -q -- "--- PASS: $t " "$LOG"; then
    echo "ERROR: $t did not PASS (missing, skipped or failed) — see $LOG" >&2
    exit 1
  fi
done

if grep -q -- '--- FAIL' "$LOG"; then
  echo "ERROR: at least one test FAILed — see $LOG" >&2
  exit 1
fi

if [ "$test_rc" != 0 ]; then
  echo "ERROR: integration test binary exited $test_rc" >&2
  exit 1
fi

echo "[run-csf-container] OK: CSF v15.00 integration suite passed in $NAME"

# --- COL-06 pass: the same image WITHOUT CSF -------------------------------
#
# TestLabNoCSFNoExec is in the gate above, but on a CSF host it takes its
# other branch and all it proves there is that CollectCSF returns non-nil —
# nothing about COL-06. The branch that matters (zero commands run, no
# csf-seen marker) needs a host with no CSF on it, and the only one in the
# OrbStack lab is debian12-nocsf. Debian has no rpm, so the one command
# CollectCSF could reach for on an RPM host before deciding CSF is absent
# (`rpm -q cpanel-csf`) was never exercised anywhere: not in the lab, not in
# CI. This second pass is that missing host — same AlmaLinux image, base.sh
# only, csf.sh deliberately not run.
echo "[run-csf-container] starting $NOCSF_NAME (same image, CSF never installed — COL-06)"
docker rm -f "$NOCSF_NAME" >/dev/null 2>&1 || true
docker run -d --name "$NOCSF_NAME" --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  almalinux/9-init >/dev/null

wait_systemd "$NOCSF_NAME"

docker cp "$LAB_DIR/provision" "$NOCSF_NAME:/root/lab-provision"
docker exec "$NOCSF_NAME" dnf -y swap curl-minimal curl
echo "[run-csf-container] provisioning base packages only (no csf.sh — that is the point)"
docker exec "$NOCSF_NAME" bash /root/lab-provision/base.sh alma yes

echo "[run-csf-container] confirming the host really has no CSF before trusting the result"
docker exec "$NOCSF_NAME" sh -c '
  if command -v csf >/dev/null 2>&1 || [ -e /etc/csf/csf.conf ] || [ -d /usr/local/csf ]; then
    echo "ERROR: CSF is present in the no-CSF container — the COL-06 assertion would be vacuous" >&2
    exit 1
  fi
  command -v rpm >/dev/null 2>&1 || { echo "ERROR: no rpm here, so this adds nothing over debian12-nocsf" >&2; exit 1; }
  echo "no-CSF host confirmed, and rpm IS available"
'

docker cp "$TEST_BIN" "$NOCSF_NAME:/root/it.test"

echo "[run-csf-container] running the no-CSF slice"
: >"$NOCSF_LOG"
set +e
docker exec \
  -e LAB_ALLOW_SKIP=1 \
  -e LAB_VM=ci-almalinux9-nocsf \
  -e LAB_FORK=none \
  -e LAB_EXPECT_CSF=0 \
  "$NOCSF_NAME" /root/it.test -test.v -test.count=1 -test.run '^TestLabNoCSFNoExec$' | tee "$NOCSF_LOG"
nocsf_rc=${PIPESTATUS[0]}
set -e

echo "[run-csf-container] hard gate: TestLabNoCSFNoExec must PASS here, where it means COL-06"
if ! grep -q -- "--- PASS: TestLabNoCSFNoExec" "$NOCSF_LOG"; then
  echo "ERROR: TestLabNoCSFNoExec did not PASS on the no-CSF host — see $NOCSF_LOG" >&2
  exit 1
fi
if grep -q -- '--- FAIL' "$NOCSF_LOG"; then
  echo "ERROR: the no-CSF slice FAILed — see $NOCSF_LOG" >&2
  exit 1
fi
if [ "$nocsf_rc" != 0 ]; then
  echo "ERROR: no-CSF test binary exited $nocsf_rc" >&2
  exit 1
fi

echo "[run-csf-container] OK: COL-06 verified on an RPM host with no CSF ($NOCSF_NAME)"
