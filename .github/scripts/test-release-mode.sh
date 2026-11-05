#!/bin/bash
#
# Stubbed tests for .github/scripts/release-mode.sh, plus static wiring
# checks on .github/workflows/release.yml. No network, no real GitHub token.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RELEASE_MODE="$SCRIPT_DIR/release-mode.sh"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

FAILED=0
fail() { echo "FAIL: $1" >&2; FAILED=1; }

write_gh_stub() {
    # $1 = stub body (written verbatim as the script after the shebang)
    printf '#!/bin/bash\n%s\n' "$1" > "$T/bin/gh"
    chmod +x "$T/bin/gh"
}

# run_mode <tag> <repo> -> sets $RC, writes $T/out (GITHUB_OUTPUT content),
# $T/stdout, $T/stderr.
run_mode() {
    local tag="$1" repo="$2"
    : > "$T/out"
    TAG="$tag" REPO="$repo" GITHUB_OUTPUT="$T/out" RELEASE_MODE_SLEEP=0 PATH="$T/bin:$PATH" \
        bash "$RELEASE_MODE" > "$T/stdout" 2> "$T/stderr" && RC=0 || RC=$?
}

count_lines() { grep -c "$1" "$2" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
test_unpromoted() {
    write_gh_stub 'echo true; exit 0'
    run_mode v9.9.9 defensia/agent

    [ "$RC" = "0" ] || { fail "unpromoted: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=false$' "$T/out" || { fail "unpromoted: promoted != false"; cat "$T/out" >&2; return; }
    grep -q '^make_latest=false$' "$T/out" || { fail "unpromoted: make_latest != false"; return; }
    grep -q '^prerelease=true$' "$T/out" || { fail "unpromoted: prerelease != true"; return; }

    local n_tags n_latest
    n_tags="$(awk '/^docker_tags<<EOF$/{f=1;next} /^EOF$/{f=0} f' "$T/out" | grep -c . || true)"
    n_latest="$(awk '/^docker_tags<<EOF$/{f=1;next} /^EOF$/{f=0} f' "$T/out" | grep -c ':latest$' || true)"
    [ "$n_tags" = "2" ] || { fail "unpromoted: docker_tags has $n_tags lines, want 2"; cat "$T/out" >&2; return; }
    [ "$n_latest" = "0" ] || { fail "unpromoted: docker_tags has a :latest line"; return; }

    echo "  ok: unpromoted"
}

# ---------------------------------------------------------------------------
test_promoted() {
    write_gh_stub 'echo false; exit 0'
    run_mode v9.9.9 defensia/agent

    [ "$RC" = "0" ] || { fail "promoted: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=true$' "$T/out" || { fail "promoted: promoted != true"; return; }
    grep -q '^make_latest=true$' "$T/out" || { fail "promoted: make_latest != true"; return; }
    grep -q '^prerelease=false$' "$T/out" || { fail "promoted: prerelease != false"; return; }

    local n_tags n_latest
    n_tags="$(awk '/^docker_tags<<EOF$/{f=1;next} /^EOF$/{f=0} f' "$T/out" | grep -c . || true)"
    n_latest="$(awk '/^docker_tags<<EOF$/{f=1;next} /^EOF$/{f=0} f' "$T/out" | grep -c ':latest$' || true)"
    [ "$n_tags" = "4" ] || { fail "promoted: docker_tags has $n_tags lines, want 4"; cat "$T/out" >&2; return; }
    [ "$n_latest" = "2" ] || { fail "promoted: docker_tags has $n_latest :latest lines, want 2"; return; }

    echo "  ok: promoted"
}

# ---------------------------------------------------------------------------
test_not_found() {
    write_gh_stub 'echo "release not found" >&2; exit 1'
    run_mode v9.9.9 defensia/agent

    [ "$RC" = "0" ] || { fail "not_found: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=true$' "$T/out" || { fail "not_found: promoted != true (default/promoted-path behavior)"; cat "$T/out" >&2; return; }
    grep -q '^make_latest=true$' "$T/out" || { fail "not_found: make_latest != true"; return; }

    echo "  ok: not_found"
}

# ---------------------------------------------------------------------------
test_api_error() {
    write_gh_stub 'echo "$$" >> "'"$T"'/gh-calls"; echo "HTTP 502" >&2; exit 1'
    rm -f "$T/gh-calls"
    run_mode v9.9.9 defensia/agent

    [ "$RC" != "0" ] || { fail "api_error: expected non-zero exit"; return; }
    if grep -q '^promoted=' "$T/out"; then
        fail "api_error: no promoted= line should be written on failure"
        cat "$T/out" >&2
        return
    fi
    local calls
    calls="$(wc -l < "$T/gh-calls" | tr -d ' ')"
    [ "$calls" = "3" ] || { fail "api_error: expected 3 gh attempts, got $calls"; return; }

    echo "  ok: api_error"
}

# ---------------------------------------------------------------------------
test_bad_tag() {
    write_gh_stub 'echo "$$" >> "'"$T"'/gh-calls-badtag"; echo true; exit 0'
    rm -f "$T/gh-calls-badtag"

    for bad in "v1.4" "main" "v1.4.5;id"; do
        run_mode "$bad" defensia/agent
        [ "$RC" != "0" ] || { fail "bad_tag: '$bad' should be non-zero"; return; }
    done
    if [ -f "$T/gh-calls-badtag" ]; then
        fail "bad_tag: gh must never be called for an invalid tag"
        return
    fi

    echo "  ok: bad_tag"
}

# ---------------------------------------------------------------------------
test_release_yml_wiring() {
    [ -f "$RELEASE_YML" ] || { fail "release_yml_wiring: $RELEASE_YML missing"; return; }

    local n
    n="$(count_lines 'agent:latest' "$RELEASE_YML")"
    [ "$n" = "0" ] || { fail "release_yml_wiring: 'agent:latest' literal still present ($n)"; return; }

    n="$(count_lines 'make_latest: true' "$RELEASE_YML")"
    [ "$n" = "0" ] || { fail "release_yml_wiring: 'make_latest: true' literal still present ($n)"; return; }

    grep -q 'release-mode.sh' "$RELEASE_YML" || { fail "release_yml_wiring: release-mode.sh not referenced"; return; }
    grep -q 'make_latest: \${{ steps.mode.outputs.make_latest }}' "$RELEASE_YML" \
        || { fail "release_yml_wiring: make_latest output wiring missing"; return; }
    grep -q "prerelease: \${{ steps.mode.outputs.prerelease == 'true' }}" "$RELEASE_YML" \
        || { fail "release_yml_wiring: prerelease output wiring missing"; return; }
    grep -q '\${{ needs.build.outputs.docker_tags }}' "$RELEASE_YML" \
        || { fail "release_yml_wiring: docker_tags output wiring missing"; return; }
    grep -q "needs.build.outputs.promoted == 'true'" "$RELEASE_YML" \
        || { fail "release_yml_wiring: helm job promoted-gate missing"; return; }

    echo "  ok: release_yml_wiring"
}

echo "== release-mode tests =="
test_unpromoted
test_promoted
test_not_found
test_api_error
test_bad_tag
test_release_yml_wiring

if [ "$FAILED" != "0" ]; then
    echo "release-mode tests: FAILED" >&2
    exit 1
fi

echo "release-mode tests: OK"
