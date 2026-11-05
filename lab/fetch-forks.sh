#!/usr/bin/env bash
# lab/fetch-forks.sh [id...] — download and integrity-check pinned CSF fork
# sources from lab/forks.lock into lab/cache/. Default: all ids in the lock
# file. Exits non-zero on any checksum/commit mismatch. NEVER fetches from
# configserver.com (hard guard below, independent of forks.lock content).
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lab/lib.sh
source "$LAB_DIR/lib.sh"

mkdir -p "$CACHE_DIR" "$CACHE_DIR/src"

ids="$*"
if [ -z "$ids" ]; then
  ids="$(awk -F'|' '!/^#/ && NF==5 {print $1}' "$LAB_DIR/forks.lock")"
fi

for id in $ids; do
  kind="$(forks_field "$id" 2)"
  url="$(forks_field "$id" 3)"
  sha="$(forks_field "$id" 4)"
  pin="$(forks_field "$id" 5)"

  [ -n "$kind" ] || die "unknown fork id in forks.lock: $id"

  case "$url" in
    *configserver.com*) die "refusing to fetch $id from configserver.com: $url" ;;
  esac

  target="$CACHE_DIR/$id.tgz"

  case "$kind" in
    tgz)
      if [ -f "$target" ] && [ "$(sha256_of "$target")" = "$sha" ]; then
        log "cached $id -> $target"
        continue
      fi
      tmp="$target.tmp"
      rm -f "$tmp"
      curl -fsSL --retry 3 -o "$tmp" "$url"
      got="$(sha256_of "$tmp")"
      if [ "$got" != "$sha" ]; then
        rm -f "$tmp"
        die "sha256 mismatch for $id: got $got expected $sha"
      fi
      mv "$tmp" "$target"
      echo "OK $id $target"
      ;;
    git)
      srcdir="$CACHE_DIR/src/$id"
      if [ -d "$srcdir" ] && [ -f "$target" ] && [ "$(git -C "$srcdir" rev-parse HEAD 2>/dev/null || true)" = "$pin" ]; then
        log "cached $id -> $target"
        continue
      fi
      if [ ! -d "$srcdir" ]; then
        git clone --quiet "$url" "$srcdir"
      fi
      git -C "$srcdir" fetch --quiet origin "$pin" || true
      git -C "$srcdir" checkout --quiet "$pin"
      head="$(git -C "$srcdir" rev-parse HEAD)"
      if [ "$head" != "$pin" ]; then
        die "git checkout mismatch for $id: got $head expected $pin"
      fi
      git -C "$srcdir" archive --format=tar.gz --prefix=csf/ "$pin" -o "$target"
      echo "OK $id $target"
      ;;
    *)
      die "unknown kind '$kind' for fork id $id"
      ;;
  esac
done
