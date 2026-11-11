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
#   BUILD_DISPATCH   "true" when called from release.yml's `-f build=true`
#                    workflow_dispatch path (Phase 15 COL-04, plan 15-13):
#                    builds/signs/publishes version-only artifacts for an
#                    EXISTING staged (prerelease) tag whose tag event did
#                    not trigger this workflow. Fails closed before any
#                    output is written if the release does not exist, is
#                    not a prerelease, or was already built (checksums.txt
#                    already present) — never a path to Docker :latest.
#
set -euo pipefail

TAG="${TAG:-}"
REPO="${REPO:-}"
SLEEP_SECS="${RELEASE_MODE_SLEEP:-5}"
BUILD_DISPATCH="${BUILD_DISPATCH:-}"

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

MAX_ATTEMPTS=3
ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

if [ "$BUILD_DISPATCH" = "true" ]; then
    ATTEMPT=1
    RELEASE_JSON=""
    while :; do
        if RELEASE_JSON="$(gh release view "$TAG" --repo "$REPO" --json isPrerelease,assets 2>"$ERR_FILE")"; then
            break
        fi
        ERR="$(cat "$ERR_FILE" 2>/dev/null || true)"
        if [ "$ATTEMPT" -ge "$MAX_ATTEMPTS" ]; then
            if echo "$ERR" | grep -qi 'release not found'; then
                echo "::error::build dispatch: release ${TAG} does not exist (create it with scripts/release-agent.sh --no-promote first)" >&2
            else
                echo "::error::cannot read release ${TAG} for build dispatch after ${MAX_ATTEMPTS} attempts: ${ERR}" >&2
            fi
            exit 1
        fi
        ATTEMPT=$((ATTEMPT + 1))
        sleep "$SLEEP_SECS"
    done

    IS_PRERELEASE="$(echo "$RELEASE_JSON" | jq -r '.isPrerelease')"
    if [ "$IS_PRERELEASE" != "true" ]; then
        echo "::error::build dispatch is only for staged (prerelease) releases" >&2
        exit 1
    fi

    if echo "$RELEASE_JSON" | jq -r '.assets[].name' | grep -qxF 'checksums.txt'; then
        echo "::error::${TAG} already built (checksums.txt present): nothing to do" >&2
        exit 1
    fi

    {
        echo "promoted=false"
        echo "make_latest=false"
        echo "prerelease=true"
        echo "docker_tags<<EOF"
        echo "ghcr.io/defensia/agent:${V}"
        echo "defensiacloud/agent:${V}"
        echo "EOF"
    } >> "$GITHUB_OUTPUT"
    echo "release mode: staged (build dispatch)"
    exit 0
fi

PROMOTED=""
ATTEMPT=1

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
