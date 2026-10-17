#!/usr/bin/env bash
#
# Tests check-installer-sync.sh against a fake "served" installer.
#
# A check nobody has watched fail is a check you do not know works, and this one
# can fail in the direction that costs you: a normaliser that stops matching
# would compare the wrong bytes and pass. So the cases below include drift it
# must catch, injected differences it must tolerate, and a broken normaliser it
# must refuse to work around.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${HERE}/check-installer-sync.sh"
SOURCE="${1:-${HERE}/../../install.sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# Serve a file over the filesystem; the check takes any URL curl understands.
serve() { cp "$1" "$work/served.sh"; echo "file://$work/served.sh"; }

run_check() {
    SERVED_URL="$1" bash "$CHECK" "$2" > "$work/out" 2>&1
    echo $?
}

expect() {
    local name="$1" want="$2" got="$3"
    if [[ "$want" == "$got" ]]; then
        echo "  ok    $name"
        pass=$((pass + 1))
    else
        echo "  FAIL  $name: expected exit $want, got $got"
        sed 's/^/          /' "$work/out" | head -6
        fail=$((fail + 1))
    fi
}

[[ -f "$SOURCE" ]] || { echo "no installer at $SOURCE" >&2; exit 1; }

echo "A) identical files: passes"
expect "exit 0" 0 "$(run_check "$(serve "$SOURCE")" "$SOURCE")"

echo "B) the panel's own injections are tolerated"
sed -e 's#^\( *local server_url="${DEFENSIA_SERVER_URL:-\)\(}"\)$#\1https://api.defensia.cloud\2#' \
    -e 's#^RELEASE_BASE=.*#RELEASE_BASE="${RELEASE_BASE:-https://defensia.cloud/downloads}"#' \
    -e 's#^RELEASE_FALLBACK=.*#RELEASE_FALLBACK="${RELEASE_FALLBACK:-https://github.com/${GITHUB_REPO}/releases/latest/download}"#' \
    "$SOURCE" > "$work/injected.sh"
expect "exit 0" 0 "$(run_check "$(serve "$work/injected.sh")" "$SOURCE")"

echo "C) a changed line of real logic is caught"
sed 's|recover-download-stamp|recover-download-stamp-DRIFTED|' \
    "$work/injected.sh" > "$work/drifted.sh"
[[ -s "$work/drifted.sh" ]] || { echo "  FAIL  fixture not built"; fail=$((fail + 1)); }
cmp -s "$work/drifted.sh" "$work/injected.sh" && { echo "  FAIL  fixture is not actually drifted"; fail=$((fail + 1)); }
expect "exit 1" 1 "$(run_check "$(serve "$work/drifted.sh")" "$SOURCE")"
if grep -q "drifted from this repository" "$work/out"; then
    echo "  ok    reports drift"; pass=$((pass + 1))
else
    echo "  FAIL  does not explain the drift"; fail=$((fail + 1))
fi

echo "D) a whole function missing from the served copy is caught"
awk '/^install_recovery_script\(\) \{/{s=1} /^RECOVEREOF$/{if(s){s=2;next}} s==1{next} s==2&&/^\}/{s=0;next} {print}' \
    "$work/injected.sh" > "$work/gutted.sh"
expect "exit 1" 1 "$(run_check "$(serve "$work/gutted.sh")" "$SOURCE")"

echo "E) an empty served file is refused, not silently matched"
: > "$work/empty.sh"
expect "exit 1" 1 "$(run_check "$(serve "$work/empty.sh")" "$SOURCE")"

echo "F) an unreachable URL fails rather than passing"
expect "exit 1" 1 "$(run_check "file://$work/does-not-exist.sh" "$SOURCE")"

echo "G) a normalisation anchor that no longer matches makes the check refuse"
# Simulates someone reshaping the RELEASE_BASE line without updating the check.
sed 's#^RELEASE_BASE="${RELEASE_BASE:-#RELEASE_SOURCE="${RELEASE_SOURCE:-#' "$SOURCE" > "$work/reshaped.sh"
expect "exit 1" 1 "$(run_check "$(serve "$work/reshaped.sh")" "$work/reshaped.sh")"
if grep -q "normalisation anchor missing" "$work/out"; then
    echo "  ok    refuses instead of comparing wrongly"; pass=$((pass + 1))
else
    echo "  FAIL  did not say the anchor was missing"; fail=$((fail + 1))
fi

echo
echo "pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
