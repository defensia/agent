#!/bin/bash
#
# Stubbed tests for .github/scripts/release-promote.sh. No network, no real
# GitHub token, no real docker daemon. Stubs `gh` and `docker` on PATH.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RELEASE_PROMOTE="$SCRIPT_DIR/release-promote.sh"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin"

FAILED=0
fail() { echo "FAIL: $1" >&2; FAILED=1; }

# ---------------------------------------------------------------------------
# Stubs. Driven by fixture files under $T so each test case can configure
# behaviour without rewriting the stub scripts themselves.
#   $T/release-json      body for `gh release view ... --json isPrerelease,assets`
#                         (absent = release not found)
#   $T/latest-tag         body for `gh api .../releases/latest -q .tag_name`
#                         ("404" or absent = no latest release yet)
#   $T/missing-images     newline list of image refs whose `imagetools inspect` fails
# ---------------------------------------------------------------------------
cat > "$T/bin/gh" <<STUB
#!/bin/bash
echo "gh \$*" >> "$T/log"
case "\$1 \$2" in
  "release view")
    if [ -f "$T/release-json" ]; then
      cat "$T/release-json"
      exit 0
    else
      echo "release not found" >&2
      exit 1
    fi
    ;;
  "api repos/defensia/agent/releases/latest"|"api repos/defensia/agent/releases/latest -q")
    ;;
esac
case "\$*" in
  "api "*"/releases/latest -q .tag_name")
    if [ -f "$T/latest-tag" ] && [ "\$(cat "$T/latest-tag")" != "404" ]; then
      cat "$T/latest-tag"
      exit 0
    else
      echo "HTTP 404: Not Found" >&2
      exit 1
    fi
    ;;
  "release edit "*)
    exit 0
    ;;
  *)
    echo "gh-stub: unhandled args: \$*" >&2
    exit 9
    ;;
esac
STUB
chmod +x "$T/bin/gh"

cat > "$T/bin/docker" <<STUB
#!/bin/bash
echo "docker \$*" >> "$T/log"
case "\$1 \$2 \$3" in
  "buildx imagetools inspect")
    IMG="\$4"
    if [ -f "$T/missing-images" ] && grep -qxF "\$IMG" "$T/missing-images"; then
      echo "no such manifest: \$IMG" >&2
      exit 1
    fi
    exit 0
    ;;
  "buildx imagetools create")
    exit 0
    ;;
  *)
    echo "docker-stub: unhandled args: \$*" >&2
    exit 9
    ;;
esac
STUB
chmod +x "$T/bin/docker"

GOOD_RELEASE_JSON='{"isPrerelease":true,"assets":[{"name":"defensia-agent"},{"name":"defensia-agent-linux-arm64"},{"name":"defensia-agent-linux-amd64.sha256"},{"name":"defensia-agent-linux-arm64.sha256"}]}'

reset_fixtures() {
    rm -f "$T/release-json" "$T/latest-tag" "$T/missing-images"
    : > "$T/log"
}

# run_promote <tag> <promote> [repo] -> sets $RC, $T/out (GITHUB_OUTPUT), $T/log
run_promote() {
    local tag="$1" promote="$2" repo="${3:-defensia/agent}"
    : > "$T/out"
    TAG="$tag" PROMOTE="$promote" REPO="$repo" GITHUB_OUTPUT="$T/out" GH_TOKEN="x" PATH="$T/bin:$PATH" \
        bash "$RELEASE_PROMOTE" > "$T/stdout" 2> "$T/stderr" && RC=0 || RC=$?
}

count_lines() { grep -c "$1" "$2" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
test_promote_ok() {
    reset_fixtures
    echo "$GOOD_RELEASE_JSON" > "$T/release-json"
    echo "v9.9.8" > "$T/latest-tag"

    run_promote v9.9.9 true

    [ "$RC" = "0" ] || { fail "promote_ok: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=true$' "$T/out" || { fail "promote_ok: promoted != true"; cat "$T/out" >&2; return; }
    grep -q '^version=9.9.9$' "$T/out" || { fail "promote_ok: version != 9.9.9"; cat "$T/out" >&2; return; }

    local l1 l2 l3 l4 l5
    l1="$(grep -n 'imagetools inspect ghcr.io/defensia/agent:9.9.9' "$T/log" | head -1 | cut -d: -f1 || true)"
    l2="$(grep -n 'imagetools inspect defensiacloud/agent:9.9.9' "$T/log" | head -1 | cut -d: -f1 || true)"
    l3="$(grep -n 'imagetools create -t ghcr.io/defensia/agent:latest ghcr.io/defensia/agent:9.9.9' "$T/log" | head -1 | cut -d: -f1 || true)"
    l4="$(grep -n 'imagetools create -t defensiacloud/agent:latest defensiacloud/agent:9.9.9' "$T/log" | head -1 | cut -d: -f1 || true)"
    l5="$(grep -n 'release edit v9.9.9 --repo defensia/agent --prerelease=false --latest' "$T/log" | head -1 | cut -d: -f1 || true)"

    for v in l1 l2 l3 l4 l5; do
        [ -n "${!v}" ] || { fail "promote_ok: missing expected log line ($v)"; cat "$T/log" >&2; return; }
    done
    if ! { [ "$l1" -lt "$l2" ] && [ "$l2" -lt "$l3" ] && [ "$l3" -lt "$l4" ] && [ "$l4" -lt "$l5" ]; }; then
        fail "promote_ok: log lines out of order"
        cat "$T/log" >&2
        return
    fi

    echo "  ok: promote_ok"
}

# ---------------------------------------------------------------------------
test_preflight_only() {
    reset_fixtures
    echo "$GOOD_RELEASE_JSON" > "$T/release-json"
    echo "v9.9.8" > "$T/latest-tag"

    run_promote v9.9.9 false

    [ "$RC" = "0" ] || { fail "preflight_only: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=false$' "$T/out" || { fail "preflight_only: promoted != false"; cat "$T/out" >&2; return; }
    grep -q 'preflight OK (promote=false): nothing changed' "$T/stdout" || { fail "preflight_only: missing preflight message"; cat "$T/stdout" >&2; return; }
    [ "$(count_lines 'imagetools create' "$T/log")" = "0" ] || { fail "preflight_only: imagetools create ran"; return; }
    [ "$(count_lines 'release edit' "$T/log")" = "0" ] || { fail "preflight_only: release edit ran"; return; }

    echo "  ok: preflight_only"
}

# ---------------------------------------------------------------------------
test_idempotent() {
    reset_fixtures
    echo '{"isPrerelease":false,"assets":[{"name":"defensia-agent"},{"name":"defensia-agent-linux-arm64"},{"name":"defensia-agent-linux-amd64.sha256"},{"name":"defensia-agent-linux-arm64.sha256"}]}' > "$T/release-json"
    echo "v9.9.9" > "$T/latest-tag"

    run_promote v9.9.9 true

    [ "$RC" = "0" ] || { fail "idempotent: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=true$' "$T/out" || { fail "idempotent: promoted != true"; cat "$T/out" >&2; return; }

    echo "  ok: idempotent"
}

# ---------------------------------------------------------------------------
test_bad_tag() {
    for bad in "main" "v1.4" "v1.4.5;rm -rf /"; do
        reset_fixtures
        echo "$GOOD_RELEASE_JSON" > "$T/release-json"
        run_promote "$bad" true
        [ "$RC" != "0" ] || { fail "bad_tag: '$bad' should be non-zero"; return; }
        [ ! -s "$T/log" ] || { fail "bad_tag: '$bad' must never call gh/docker"; cat "$T/log" >&2; return; }
    done

    echo "  ok: bad_tag"
}

# ---------------------------------------------------------------------------
test_not_found() {
    reset_fixtures
    # no release-json -> gh release view fails "release not found"

    run_promote v9.9.9 true

    [ "$RC" != "0" ] || { fail "not_found: expected non-zero exit"; return; }
    [ "$(count_lines 'imagetools create' "$T/log")" = "0" ] || { fail "not_found: imagetools create ran"; return; }
    [ "$(count_lines 'release edit' "$T/log")" = "0" ] || { fail "not_found: release edit ran"; return; }

    echo "  ok: not_found"
}

# ---------------------------------------------------------------------------
test_missing_assets() {
    reset_fixtures
    echo '{"isPrerelease":true,"assets":[{"name":"defensia-agent"},{"name":"defensia-agent-linux-arm64"},{"name":"defensia-agent-linux-amd64.sha256"}]}' > "$T/release-json"
    echo "v9.9.8" > "$T/latest-tag"

    run_promote v9.9.9 true

    [ "$RC" != "0" ] || { fail "missing_assets: expected non-zero exit"; return; }
    [ "$(count_lines 'imagetools create' "$T/log")" = "0" ] || { fail "missing_assets: imagetools create ran"; return; }
    [ "$(count_lines 'release edit' "$T/log")" = "0" ] || { fail "missing_assets: release edit ran"; return; }

    echo "  ok: missing_assets"
}

# ---------------------------------------------------------------------------
test_missing_image() {
    reset_fixtures
    echo "$GOOD_RELEASE_JSON" > "$T/release-json"
    echo "v9.9.8" > "$T/latest-tag"
    echo "defensiacloud/agent:9.9.9" > "$T/missing-images"

    run_promote v9.9.9 true

    [ "$RC" != "0" ] || { fail "missing_image: expected non-zero exit"; return; }
    [ "$(count_lines 'imagetools create' "$T/log")" = "0" ] || { fail "missing_image: imagetools create ran"; return; }
    [ "$(count_lines 'release edit' "$T/log")" = "0" ] || { fail "missing_image: release edit ran"; return; }

    echo "  ok: missing_image"
}

# ---------------------------------------------------------------------------
test_downgrade() {
    reset_fixtures
    echo "$GOOD_RELEASE_JSON" > "$T/release-json"
    echo "v9.10.0" > "$T/latest-tag"

    run_promote v9.9.9 true

    [ "$RC" != "0" ] || { fail "downgrade: expected non-zero exit"; return; }
    grep -q 'refusing to move latest backwards' "$T/stderr" || { fail "downgrade: missing message"; cat "$T/stderr" >&2; return; }
    [ "$(count_lines 'imagetools create' "$T/log")" = "0" ] || { fail "downgrade: imagetools create ran"; return; }
    [ "$(count_lines 'release edit' "$T/log")" = "0" ] || { fail "downgrade: release edit ran"; return; }

    echo "  ok: downgrade"
}

echo "== release-promote tests =="
test_promote_ok
test_preflight_only
test_idempotent
test_bad_tag
test_not_found
test_missing_assets
test_missing_image
test_downgrade

if [ "$FAILED" != "0" ]; then
    echo "release-promote tests: FAILED" >&2
    exit 1
fi

echo "release-promote tests: OK"
