#!/bin/bash
#
# Decides promoted vs staged for a tagged release, from the GitHub release's
# isPrerelease flag. Emits make_latest / prerelease / docker_tags / promoted
# via GITHUB_OUTPUT so release.yml's build/docker/helm jobs never publish
# Docker `:latest`, a "latest" GitHub release, or the Helm chart for an
# unpromoted (staged) release.
#
# Fails CLOSED: any `gh` error other than "release not found" (the shape
# release-agent.sh's DEFAULT path produces — it pushes the tag before `gh
# release create` ever runs) stops the workflow before anything publishes.
#
# Env:
#   TAG              e.g. v1.4.88 (required)
#   REPO             owner/name, e.g. defensia/agent (required)
#   GITHUB_OUTPUT    path to the step output file (required)
#   GH_TOKEN         used implicitly by `gh`
#   RELEASE_MODE_SLEEP  seconds between retries (default 5; tests override to 0)
#
set -euo pipefail

TAG="${TAG:-}"
REPO="${REPO:-}"
SLEEP_SECS="${RELEASE_MODE_SLEEP:-5}"

if ! [[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "::error::invalid TAG '${TAG}' (expected vX.Y.Z)" >&2
    exit 1
fi
if [ -z "$REPO" ]; then
    echo "::error::REPO not set" >&2
    exit 1
fi
if [ -z "${GITHUB_OUTPUT:-}" ]; then
    echo "::error::GITHUB_OUTPUT not set" >&2
    exit 1
fi

V="${TAG#v}"

PROMOTED=""
ATTEMPT=1
MAX_ATTEMPTS=3
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do
    if OUT="$(gh release view "$TAG" --repo "$REPO" --json isPrerelease -q .isPrerelease 2>"$ERR_FILE")"; then
        case "$OUT" in
            true) PROMOTED=0 ;;
            false) PROMOTED=1 ;;
            *)
                echo "::error::unexpected isPrerelease value for ${TAG}: '${OUT}'" >&2
                exit 1
                ;;
        esac
        break
    fi
    ERR="$(cat "$ERR_FILE" 2>/dev/null || true)"
    if echo "$ERR" | grep -qi 'release not found'; then
        # release-agent.sh's default (promoting) path pushes the tag BEFORE
        # `gh release create` ever runs, so release.yml's own tag-triggered
        # run can legitimately start before the release object exists yet.
        # Treat "not found" as promoted (today's — pre-Phase-15 — behavior).
        PROMOTED=1
        break
    fi
    if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
        echo "::error::cannot determine release mode for ${TAG} after ${MAX_ATTEMPTS} attempts: ${ERR}" >&2
        exit 1
    fi
    ATTEMPT=$((ATTEMPT + 1))
    sleep "$SLEEP_SECS"
done

if [ "$PROMOTED" = "1" ]; then
    {
        echo "promoted=true"
        echo "make_latest=true"
        echo "prerelease=false"
        echo "docker_tags<<EOF"
        echo "ghcr.io/defensia/agent:latest"
        echo "ghcr.io/defensia/agent:${V}"
        echo "defensiacloud/agent:latest"
        echo "defensiacloud/agent:${V}"
        echo "EOF"
    } >> "$GITHUB_OUTPUT"
    echo "release mode: promoted"
else
    {
        echo "promoted=false"
        echo "make_latest=false"
        echo "prerelease=true"
        echo "docker_tags<<EOF"
        echo "ghcr.io/defensia/agent:${V}"
        echo "defensiacloud/agent:${V}"
        echo "EOF"
    } >> "$GITHUB_OUTPUT"
    echo "release mode: staged"
fi
