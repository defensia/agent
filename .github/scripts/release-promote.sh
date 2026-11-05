#!/bin/bash
#
# Preflight + promotion of a staged (prerelease) release: un-prerelease,
# mark latest, retag Docker :latest (ghcr.io + Docker Hub) to the
# already-published, already-signed version image, then release.yml's
# helm job (gated separately) publishes the chart. Phase 15 COL-04.
#
# Retagging :latest re-points it at the EXISTING manifest (same digest) —
# no rebuild, so the version image's cosign signature and build-provenance
# attestation stay valid for the image that :latest now also points at.
#
# Fails CLOSED before any change: bad tag, release missing, release
# missing one of the 4 release-agent.sh assets, either version image
# missing from a registry, or TAG would move :latest backwards.
#
# Idempotent: every mutating step (the retag, the release edit) is
# itself idempotent, so a run that failed partway through can simply be
# re-run.
#
# Env:
#   TAG            e.g. v1.4.95 (required)
#   REPO           owner/name, e.g. defensia/agent (required)
#   PROMOTE        "true" to promote; anything else = read-only preflight
#   GH_TOKEN       used implicitly by `gh`
#   GITHUB_OUTPUT  path to the step output file (required)
#
set -euo pipefail

TAG="${TAG:-}"
REPO="${REPO:-}"
PROMOTE="${PROMOTE:-false}"

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
GHCR_IMAGE="ghcr.io/defensia/agent"
HUB_IMAGE="defensiacloud/agent"
REQUIRED_ASSETS=(defensia-agent defensia-agent-linux-arm64 defensia-agent-linux-amd64.sha256 defensia-agent-linux-arm64.sha256)

ERR_FILE="$(mktemp)"
trap 'rm -f "$ERR_FILE"' EXIT

# --- Preflight: release exists and carries all 4 release-agent.sh assets ---
if ! RELEASE_JSON="$(gh release view "$TAG" --repo "$REPO" --json isPrerelease,assets 2>"$ERR_FILE")"; then
    echo "::error::release ${TAG} not found or inaccessible: $(cat "$ERR_FILE")" >&2
    exit 1
fi

ASSET_NAMES="$(echo "$RELEASE_JSON" | jq -r '.assets[].name')"
for a in "${REQUIRED_ASSETS[@]}"; do
    if ! echo "$ASSET_NAMES" | grep -qxF "$a"; then
        echo "::error::release ${TAG} is missing asset ${a} (not built yet?)" >&2
        exit 1
    fi
done

# --- Preflight: never move :latest backwards --------------------------------
LATEST_TAG=""
if OUT="$(gh api "repos/${REPO}/releases/latest" -q .tag_name 2>"$ERR_FILE")"; then
    LATEST_TAG="$OUT"
else
    ERR="$(cat "$ERR_FILE" 2>/dev/null || true)"
    if ! echo "$ERR" | grep -qi '404\|not found'; then
        echo "::error::cannot determine current latest release: ${ERR}" >&2
        exit 1
    fi
    # No release marked "latest" yet (fresh repo) — nothing to protect.
fi
if [ -n "$LATEST_TAG" ] && [ "$LATEST_TAG" != "$TAG" ]; then
    HIGHEST="$(printf '%s\n%s\n' "$LATEST_TAG" "$TAG" | sort -V | tail -1)"
    if [ "$HIGHEST" = "$LATEST_TAG" ]; then
        echo "::error::refusing to move latest backwards (${LATEST_TAG} > ${TAG})" >&2
        exit 1
    fi
fi

# --- Preflight: both version images already exist (signed by the build job) -
docker buildx imagetools inspect "${GHCR_IMAGE}:${V}" >/dev/null
docker buildx imagetools inspect "${HUB_IMAGE}:${V}" >/dev/null

if [ "$PROMOTE" != "true" ]; then
    echo "would retag ${GHCR_IMAGE}:latest -> ${GHCR_IMAGE}:${V}"
    echo "would retag ${HUB_IMAGE}:latest -> ${HUB_IMAGE}:${V}"
    echo "would mark ${TAG} not-prerelease + latest"
    echo "preflight OK (promote=false): nothing changed"
    {
        echo "promoted=false"
        echo "version=${V}"
    } >> "$GITHUB_OUTPUT"
    exit 0
fi

# --- Promote: retag :latest first (Docker becomes consistent), then flip
# GitHub's prerelease/latest flags last, so GitHub only shows this release as
# "latest" once pulling :latest already serves the matching image.
docker buildx imagetools create -t "${GHCR_IMAGE}:latest" "${GHCR_IMAGE}:${V}"
docker buildx imagetools create -t "${HUB_IMAGE}:latest" "${HUB_IMAGE}:${V}"
gh release edit "$TAG" --repo "$REPO" --prerelease=false --latest

{
    echo "promoted=true"
    echo "version=${V}"
} >> "$GITHUB_OUTPUT"
echo "release promoted: ${TAG}"
