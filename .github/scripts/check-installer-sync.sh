#!/usr/bin/env bash
#
# Fails when the installer served at defensia.cloud/install.sh has drifted from
# the copy versioned here.
#
# agent/install.sh in the panel repository is the single source of truth; this
# file is a byte-identical copy. Keeping it versioned is what lets an auditor
# read the installer with its history and know it is the one that actually runs
# — a public repo whose installer is not the installed one gives a false
# guarantee, which is worse than publishing nothing.
#
# The served copy is not byte-identical by construction: the panel injects the
# server URL and swaps the download order on the way out. Those lines are
# normalised on both sides before comparing, and normalisation REFUSES TO RUN if
# a line it expects is missing — a normaliser that silently stops matching would
# make this check pass while comparing the wrong thing, which is the direction
# that costs you.
#
#   ./check-installer-sync.sh [path-to-versioned-install.sh]
set -euo pipefail

SERVED_URL="${SERVED_URL:-https://defensia.cloud/install.sh}"
VERSIONED="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/install.sh}"

die() { echo "FAIL: $*" >&2; exit 1; }

[[ -f "$VERSIONED" ]] || die "versioned installer not found at $VERSIONED"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Fetching $SERVED_URL"
curl -fsSL --retry 3 --retry-delay 2 --max-time 60 -o "$work/served.sh" "$SERVED_URL" \
    || die "could not fetch $SERVED_URL"

[[ -s "$work/served.sh" ]] || die "served installer is empty"
head -1 "$work/served.sh" | grep -q '^#!' || die "served installer does not start with a shebang"

# Each entry is a line the panel rewrites: an anchor that must be present on
# both sides, and the sed program that collapses it to a canonical form.
# Keep in step with InstallScriptController::injections().
NORMALISE=(
    'local server_url="${DEFENSIA_SERVER_URL:|s#^\( *local server_url="${DEFENSIA_SERVER_URL:-\).*\(}"\)$#\1\2#'
    'RELEASE_BASE="${RELEASE_BASE:|s#^RELEASE_BASE=.*$#RELEASE_BASE=<normalised>#'
    'RELEASE_FALLBACK="${RELEASE_FALLBACK:|s#^RELEASE_FALLBACK=.*$#RELEASE_FALLBACK=<normalised>#'
)

normalise() {
    local src="$1" dst="$2" label="$3" entry anchor program
    cp "$src" "$dst"

    for entry in "${NORMALISE[@]}"; do
        anchor="${entry%%|*}"
        program="${entry#*|}"

        grep -qF -- "$anchor" "$dst" \
            || die "normalisation anchor missing from the $label installer: $anchor
       Either that line changed shape, or an injection was added without
       teaching this check about it. Refusing to compare a file this script
       cannot normalise — see InstallScriptController::injections()."

        sed -i.bak "$program" "$dst" && rm -f "${dst}.bak"
    done
}

normalise "$work/served.sh" "$work/a" served
normalise "$VERSIONED" "$work/b" versioned

if diff -u "$work/b" "$work/a" > "$work/diff"; then
    echo "OK: the served installer matches the versioned one."
    exit 0
fi

echo "FAIL: the served installer has drifted from this repository." >&2
echo >&2
echo "  versioned: $VERSIONED" >&2
echo "  served:    $SERVED_URL" >&2
echo >&2
echo "agent/install.sh in the panel repository is the source of truth. Copy it" >&2
echo "here and commit, or if the difference belongs only to the hosted copy," >&2
echo "move it into InstallScriptController::injections() and add its line to" >&2
echo "NORMALISE above." >&2
echo >&2
sed 's/^/  /' "$work/diff" >&2
exit 1
