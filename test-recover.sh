#!/usr/bin/env bash
# Functional harness for the generated defensia-agent-recover.sh.
# Substitutes the real paths so nothing outside the sandbox is touched.
# Extracts the recovery script that install.sh embeds and exercises it against
# fake binaries. The embedded script runs as systemd ExecStartPre on customer
# machines, and `bash -n install.sh` does not look inside the heredoc, so without
# this nothing checks it at all.
#
#   bash agent/test-recover.sh
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_SH="${HERE}/install.sh"
ROOT="$(mktemp -d)"
SRC="${ROOT}/recover-src.sh"

trap 'rm -rf "$ROOT"' EXIT

sed -n "/<<'RECOVEREOF'/,/^RECOVEREOF\$/p" "$INSTALL_SH" | sed '1d;$d' > "$SRC"

if [[ ! -s "$SRC" ]]; then
    echo "FAIL: could not extract the recovery script from ${INSTALL_SH}" >&2
    exit 1
fi

bash -n "$SRC" || { echo "FAIL: the embedded recovery script is not valid bash" >&2; exit 1; }
pass=0; fail=0

check() {
    local name="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        echo "  ok    $name"
        pass=$((pass + 1))
    else
        echo "  FAIL  $name: expected '$expected', got '$actual'"
        fail=$((fail + 1))
    fi
}

# Build a runnable copy pointed at the sandbox.
build() {
    rm -rf "$ROOT/bin" "$ROOT/var"; mkdir -p "$ROOT/bin" "$ROOT/var"
    sed -e "s#^BINARY=.*#BINARY=\"$ROOT/bin/defensia-agent\"#" \
        -e "s#^BACKUP=.*#BACKUP=\"$ROOT/bin/defensia-agent.bak\"#" \
        -e "s#^MARKER=.*#MARKER=\"$ROOT/var/marker\"#" \
        -e "s#^DOWNLOAD_STAMP=.*#DOWNLOAD_STAMP=\"$ROOT/var/stamp\"#" \
        -e "s#^RELEASE_URL=.*#RELEASE_URL=\"file://$ROOT/rel\"#" \
        "$SRC" > "$ROOT/recover.sh"
    chmod +x "$ROOT/recover.sh"
}

good_binary() { printf '#!/bin/sh\n[ "$1" = check ] && exit 0\nexit 1\n' > "$1"; chmod 755 "$1"; }
bad_binary()  { printf '#!/bin/sh\nexit 3\n' > "$1"; chmod 755 "$1"; }

echo "A) healthy binary: exits 0 and touches nothing"
build; good_binary "$ROOT/bin/defensia-agent"
"$ROOT/recover.sh" >/dev/null 2>&1; check "exit code" 0 "$?"
check "no download attempted" "absent" "$([[ -f $ROOT/var/stamp ]] && echo present || echo absent)"
check "no marker written" "absent" "$([[ -f $ROOT/var/marker ]] && echo present || echo absent)"

echo "B) corrupt binary with a healthy backup: restores from backup"
build; bad_binary "$ROOT/bin/defensia-agent"; good_binary "$ROOT/bin/defensia-agent.bak"
"$ROOT/recover.sh" >/dev/null 2>&1; check "exit code" 0 "$?"
check "marker says backup" "backup" "$(cat "$ROOT/var/marker" 2>/dev/null)"
check "binary now verifies" "0" "$("$ROOT/bin/defensia-agent" check >/dev/null 2>&1; echo $?)"
check "no download attempted" "absent" "$([[ -f $ROOT/var/stamp ]] && echo present || echo absent)"

echo "C) corrupt binary, no backup, download unreachable: still exits 0"
build; bad_binary "$ROOT/bin/defensia-agent"
"$ROOT/recover.sh" >/dev/null 2>&1
check "exit code (must be 0 or systemd refuses to start)" 0 "$?"
check "download was attempted" "present" "$([[ -f $ROOT/var/stamp ]] && echo present || echo absent)"

echo "D) rate limit: a second run inside the window does not retry the download"
out="$("$ROOT/recover.sh" 2>&1)"
check "exit code" 0 "$?"
check "says it is not retrying" "yes" "$(grep -q 'not retrying' <<<"$out" && echo yes || echo no)"

echo "E) stamp older than the window: retries"
echo 1 > "$ROOT/var/stamp"; touch -d '2020-01-01' "$ROOT/var/stamp" 2>/dev/null || touch -t 202001010000 "$ROOT/var/stamp"
out="$("$ROOT/recover.sh" 2>&1)"
check "does not say not retrying" "no" "$(grep -q 'not retrying' <<<"$out" && echo yes || echo no)"

echo "F) coreutils timeout absent: a healthy binary still verifies"
build; good_binary "$ROOT/bin/defensia-agent"
mkdir -p "$ROOT/nopath"
for c in bash env sh cat grep awk sed chmod cp mv rm mktemp date stat dirname mkdir printf curl; do
    p="$(command -v "$c" 2>/dev/null)" && ln -sf "$p" "$ROOT/nopath/$c"
done
out="$(PATH="$ROOT/nopath" "$ROOT/recover.sh" 2>&1)"; rc=$?
check "exit code" 0 "$rc"
check "no recovery triggered" "absent" "$([[ -f $ROOT/var/stamp ]] && echo present || echo absent)"
check "timeout really was unavailable" "no" "$(PATH="$ROOT/nopath" command -v timeout >/dev/null 2>&1 && echo yes || echo no)"
check "script produced no failure log" "no" "$(grep -q 'verification failed' <<<"$out" && echo yes || echo no)"

echo "G) stat without GNU -c (BSD-style): rate limit must still hold"
build; bad_binary "$ROOT/bin/defensia-agent"
mkdir -p "$ROOT/fakebin"
# A stat that rejects -c and only understands -f, like BSD/macOS.
cat > "$ROOT/fakebin/stat" <<'FAKE'
#!/bin/sh
[ "$1" = "-c" ] && { echo "stat: illegal option -- c" >&2; exit 1; }
[ "$1" = "-f" ] && { shift; shift; date +%s; exit 0; }   # pretend the stamp is fresh
exit 1
FAKE
chmod +x "$ROOT/fakebin/stat"
"$ROOT/recover.sh" >/dev/null 2>&1          # first run lays the stamp
out="$(PATH="$ROOT/fakebin:$PATH" "$ROOT/recover.sh" 2>&1)"
check "exit code" 0 "$?"
check "rate limit held via -f" "yes" "$(grep -q 'not retrying' <<<"$out" && echo yes || echo no)"

echo "H) no usable stat at all: must fail CLOSED and not download"
build; bad_binary "$ROOT/bin/defensia-agent"
cat > "$ROOT/fakebin/stat" <<'FAKE'
#!/bin/sh
exit 1
FAKE
chmod +x "$ROOT/fakebin/stat"
"$ROOT/recover.sh" >/dev/null 2>&1
out="$(PATH="$ROOT/fakebin:$PATH" "$ROOT/recover.sh" 2>&1)"
check "exit code" 0 "$?"
check "refuses to retry rather than hammering the mirror" "yes" \
    "$(grep -q 'cannot read stamp mtime' <<<"$out" && echo yes || echo no)"

echo
echo "pass=$pass fail=$fail"
[[ $fail -eq 0 ]]
