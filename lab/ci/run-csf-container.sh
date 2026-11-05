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
LOG="$REPO_DIR/build/ci-integration.log"
mkdir -p "$(dirname "$LOG")"

cleanup() {
  if [ "${KEEP_CONTAINER:-0}" != "1" ]; then
    docker rm -f "$NAME" >/dev/null 2>&1 || true
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

echo "[run-csf-container] waiting for systemd to report running/degraded (up to 120s)"
state=""
ready=0
for _ in $(seq 1 24); do
  state="$(docker exec "$NAME" systemctl is-system-running --wait 2>&1 || true)"
  case "$state" in
    running|degraded) ready=1; break ;;
  esac
  sleep 5
done
if [ "$ready" != 1 ]; then
  echo "ERROR: systemd never reached running/degraded (last state: $state)" >&2
  docker logs "$NAME" >&2 || true
  exit 1
fi
echo "[run-csf-container] systemd state: $state"

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
