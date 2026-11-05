#!/bin/bash
#
# Stubbed tests for the BUILD_DISPATCH mode of .github/scripts/release-mode.sh
# (used by release.yml's `-f build=true` workflow_dispatch path), plus static
# (YAML-parsed, not grep) checks of the build dispatch wiring in
# .github/workflows/release.yml. No network, no real GitHub token.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RELEASE_MODE="$SCRIPT_DIR/release-mode.sh"
RELEASE_MODE_TEST="$SCRIPT_DIR/test-release-mode.sh"
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

# run_build_mode <tag> -> sets $RC, writes $T/out (GITHUB_OUTPUT content),
# $T/stdout, $T/stderr. BUILD_DISPATCH=true always.
run_build_mode() {
    local tag="$1" repo="${2:-defensia/agent}"
    : > "$T/out"
    TAG="$tag" REPO="$repo" GITHUB_OUTPUT="$T/out" RELEASE_MODE_SLEEP=0 BUILD_DISPATCH=true PATH="$T/bin:$PATH" \
        bash "$RELEASE_MODE" > "$T/stdout" 2> "$T/stderr" && RC=0 || RC=$?
}

count_lines() { grep -c "$1" "$2" 2>/dev/null || true; }

# ---------------------------------------------------------------------------
test_staged_build_ok() {
    write_gh_stub 'echo "{\"isPrerelease\":true,\"assets\":[{\"name\":\"defensia-agent\"},{\"name\":\"defensia-agent-linux-arm64\"},{\"name\":\"defensia-agent-linux-amd64.sha256\"},{\"name\":\"defensia-agent-linux-arm64.sha256\"}]}"; exit 0'
    run_build_mode v9.9.9

    [ "$RC" = "0" ] || { fail "staged_build_ok: exit=$RC want 0"; cat "$T/stderr" >&2; return; }
    grep -q '^promoted=false$' "$T/out" || { fail "staged_build_ok: promoted != false"; cat "$T/out" >&2; return; }
    grep -q '^make_latest=false$' "$T/out" || { fail "staged_build_ok: make_latest != false"; return; }
    grep -q '^prerelease=true$' "$T/out" || { fail "staged_build_ok: prerelease != true"; return; }

    local tags n_tags n_latest
    tags="$(awk '/^docker_tags<<EOF$/{f=1;next} /^EOF$/{f=0} f' "$T/out")"
    n_tags="$(echo "$tags" | grep -c . || true)"
    n_latest="$(echo "$tags" | grep -c ':latest$' || true)"
    [ "$n_tags" = "2" ] || { fail "staged_build_ok: docker_tags has $n_tags lines, want 2"; cat "$T/out" >&2; return; }
    [ "$n_latest" = "0" ] || { fail "staged_build_ok: docker_tags has a :latest line"; return; }
    echo "$tags" | grep -qxF 'ghcr.io/defensia/agent:9.9.9' || { fail "staged_build_ok: missing ghcr tag"; return; }
    echo "$tags" | grep -qxF 'defensiacloud/agent:9.9.9' || { fail "staged_build_ok: missing hub tag"; return; }

    grep -q 'release mode: staged (build dispatch)' "$T/stdout" || { fail "staged_build_ok: missing stdout message"; cat "$T/stdout" >&2; return; }

    echo "  ok: staged_build_ok"
}

# ---------------------------------------------------------------------------
test_not_prerelease() {
    write_gh_stub 'echo "{\"isPrerelease\":false,\"assets\":[{\"name\":\"defensia-agent\"},{\"name\":\"defensia-agent-linux-arm64\"},{\"name\":\"defensia-agent-linux-amd64.sha256\"},{\"name\":\"defensia-agent-linux-arm64.sha256\"}]}"; exit 0'
    run_build_mode v9.9.9

    [ "$RC" != "0" ] || { fail "not_prerelease: expected non-zero exit"; return; }
    grep -qi 'only for staged (prerelease) releases' "$T/stderr" || { fail "not_prerelease: missing message"; cat "$T/stderr" >&2; return; }
    [ "$(count_lines '^promoted=' "$T/out")" = "0" ] || { fail "not_prerelease: promoted= line written"; return; }

    echo "  ok: not_prerelease"
}

# ---------------------------------------------------------------------------
test_not_found() {
    write_gh_stub 'echo "release not found" >&2; exit 1'
    run_build_mode v9.9.9

    [ "$RC" != "0" ] || { fail "not_found: expected non-zero exit"; return; }
    [ "$(count_lines '^promoted=' "$T/out")" = "0" ] || { fail "not_found: promoted= line written"; return; }

    echo "  ok: not_found"
}

# ---------------------------------------------------------------------------
test_already_built() {
    write_gh_stub 'echo "{\"isPrerelease\":true,\"assets\":[{\"name\":\"defensia-agent\"},{\"name\":\"defensia-agent-linux-arm64\"},{\"name\":\"defensia-agent-linux-amd64.sha256\"},{\"name\":\"defensia-agent-linux-arm64.sha256\"},{\"name\":\"checksums.txt\"}]}"; exit 0'
    run_build_mode v9.9.9

    [ "$RC" != "0" ] || { fail "already_built: expected non-zero exit"; return; }
    grep -qi 'already built' "$T/stderr" || { fail "already_built: missing message"; cat "$T/stderr" >&2; return; }
    [ "$(count_lines '^promoted=' "$T/out")" = "0" ] || { fail "already_built: promoted= line written"; return; }

    echo "  ok: already_built"
}

# ---------------------------------------------------------------------------
test_push_path_unchanged() {
    if bash "$RELEASE_MODE_TEST" > "$T/push-path-out" 2>&1; then
        grep -q 'release-mode tests: OK' "$T/push-path-out" || { fail "push_path_unchanged: missing OK line"; cat "$T/push-path-out" >&2; return; }
        echo "  ok: push_path_unchanged"
    else
        fail "push_path_unchanged: test-release-mode.sh failed"
        cat "$T/push-path-out" >&2
    fi
}

# ---------------------------------------------------------------------------
# Extracts the `run:` body of the build job's "Dispatch guard" step from
# release.yml and executes it standalone with bash, to prove its fail-closed
# behaviour without ever dispatching the real workflow.
test_guard_simulation() {
    local guard_script="$T/guard.sh"
    if ! python3 - "$RELEASE_YML" "$guard_script" <<'PYEOF'
import sys, yaml
path, out = sys.argv[1], sys.argv[2]
w = yaml.safe_load(open(path))
jobs = w.get('jobs') or {}
build = jobs.get('build') or {}
steps = build.get('steps') or []
guard = next((s for s in steps if s.get('name') == 'Dispatch guard'), None)
if guard is None:
    sys.exit('no Dispatch guard step found')
run = guard.get('run')
if not run:
    sys.exit('Dispatch guard step has no run body')
open(out, 'w').write(run)
PYEOF
    then
        fail "guard_simulation: could not extract Dispatch guard step"
        return
    fi

    local rc

    TAG=v9.9.9 BUILD=true PROMOTE=true bash "$guard_script" >/dev/null 2>"$T/g1" && rc=0 || rc=$?
    [ "$rc" != "0" ] || { fail "guard_simulation: build+promote both true should fail"; return; }
    grep -qi 'mutually exclusive' "$T/g1" || { fail "guard_simulation: missing mutually-exclusive message"; cat "$T/g1" >&2; return; }

    TAG=v1.4 BUILD=true PROMOTE=false bash "$guard_script" >/dev/null 2>"$T/g2" && rc=0 || rc=$?
    [ "$rc" != "0" ] || { fail "guard_simulation: bad tag v1.4 should fail"; return; }

    TAG='v1.4.5;id' BUILD=true PROMOTE=false bash "$guard_script" >/dev/null 2>"$T/g3" && rc=0 || rc=$?
    [ "$rc" != "0" ] || { fail "guard_simulation: bad tag with shell metacharacters should fail"; return; }

    TAG=v9.9.9 BUILD=true PROMOTE=false bash "$guard_script" >/dev/null 2>"$T/g4" && rc=0 || rc=$?
    [ "$rc" = "0" ] || { fail "guard_simulation: valid tag, build=true, promote=false should succeed"; cat "$T/g4" >&2; return; }

    echo "  ok: guard_simulation"
}

# ---------------------------------------------------------------------------
test_static_build_dispatch_wiring() {
    [ -f "$RELEASE_YML" ] || { fail "static: $RELEASE_YML missing"; return; }

    if ! python3 - "$RELEASE_YML" <<'PYEOF'
import sys, yaml
path = sys.argv[1]
text = open(path).read()
w = yaml.safe_load(text)
errors = []

on = w.get(True, w.get('on')) or {}
wd = on.get('workflow_dispatch') or {}
inputs = wd.get('inputs') or {}
build_in = inputs.get('build') or {}
if build_in.get('type') != 'boolean' or build_in.get('default') is not False:
    errors.append(f'build input wrong: {build_in!r}')

jobs = w.get('jobs') or {}

for name in ('build', 'docker'):
    cond = str((jobs.get(name) or {}).get('if', ''))
    if "github.event_name == 'push'" not in cond or 'inputs.build' not in cond:
        errors.append(f'{name} job if wrong: {cond!r}')

promote_cond = str((jobs.get('promote') or {}).get('if', ''))
if '!inputs.build' not in promote_cond:
    errors.append(f'promote job if missing !inputs.build: {promote_cond!r}')

build_job = jobs.get('build') or {}
build_steps = build_job.get('steps') or []
if not build_steps or build_steps[0].get('name') != 'Dispatch guard':
    errors.append(f'build job step 0 is not Dispatch guard: {build_steps[0].get("name") if build_steps else None!r}')
else:
    guard = build_steps[0]
    gcond = str(guard.get('if', ''))
    if 'workflow_dispatch' not in gcond:
        errors.append(f'Dispatch guard if wrong: {gcond!r}')
    genv = guard.get('env') or {}
    for key in ('TAG', 'BUILD', 'PROMOTE'):
        if key not in genv or 'inputs.' not in str(genv[key]):
            errors.append(f'Dispatch guard env {key} wrong: {genv.get(key)!r}')

for name in ('build', 'docker'):
    steps = (jobs.get(name) or {}).get('steps') or []
    checkout = next((s for s in steps if 'checkout' in str(s.get('uses', ''))), None)
    if not checkout:
        errors.append(f'{name} job has no checkout step')
    else:
        ref = str((checkout.get('with') or {}).get('ref', ''))
        if "format('refs/tags/{0}', inputs.tag)" not in ref:
            errors.append(f'{name} checkout ref missing refs/tags/ format: {ref!r}')

mode_step = next((s for s in build_steps if s.get('id') == 'mode'), None)
if not mode_step:
    errors.append('build job has no step id=mode')
else:
    menv = mode_step.get('env') or {}
    if 'BUILD_DISPATCH' not in menv:
        errors.append('mode step env missing BUILD_DISPATCH')
    if 'inputs.tag' not in str(menv.get('TAG', '')):
        errors.append(f'mode step env TAG missing inputs.tag: {menv.get("TAG")!r}')

for name in ('build', 'docker', 'helm'):
    steps = (jobs.get(name) or {}).get('steps') or []
    vstep = next((s for s in steps if s.get('name') == 'Extract version from tag'), None)
    if not vstep:
        errors.append(f'{name} job has no "Extract version from tag" step')
        continue
    venv = vstep.get('env') or {}
    if 'TAG' not in venv:
        errors.append(f'{name} Extract version step does not take TAG from env')

# Only the uppercase shell env var is forbidden (it resolves to the dispatch
# ref, "main", not the tag). The lowercase `github.ref_name` expression
# context is the legitimate push-event fallback inside env:/if: mappings.
if 'GITHUB_REF_NAME' in text:
    errors.append('GITHUB_REF_NAME shell env var still referenced')

softprops = next(
    (s for s in build_steps if 'softprops' in str(s.get('uses', ''))), None
)
if not softprops or (softprops.get('with') or {}).get('tag_name') != '${{ steps.version.outputs.TAG }}':
    errors.append(f'softprops tag_name wrong: {(softprops.get("with") or {}).get("tag_name") if softprops else None!r}')

bconcurrency = build_job.get('concurrency') or {}
if 'inputs.tag' not in str(bconcurrency.get('group', '')) or bconcurrency.get('cancel-in-progress') is not False:
    errors.append(f'build job concurrency wrong: {bconcurrency!r}')

run_name = str(w.get('run-name', ''))
for needle in ('inputs.tag', 'inputs.build', 'inputs.promote'):
    if needle not in run_name:
        errors.append(f'run-name missing {needle!r}: {run_name!r}')

helm_cond_task2 = str((jobs.get('helm') or {}).get('if') or '')
if "needs.build.outputs.promoted == 'true'" not in helm_cond_task2:
    errors.append('helm if regressed from Task 2 (promoted condition missing)')

forbidden = ['${{ inputs.', '${{ github.event.inputs.', 'steps.version.outputs']
for jname, j in jobs.items():
    for s in (j.get('steps') or []):
        run = s.get('run')
        if run is None:
            continue
        for pat in forbidden:
            if pat in str(run):
                errors.append(f'run body in job={jname} step={s.get("name")!r} contains {pat!r}')

if 'agent:latest' in text:
    errors.append('agent:latest literal present')

if errors:
    for e in errors:
        print('WIRING FAIL:', e, file=sys.stderr)
    sys.exit(1)
print('build dispatch wiring OK')
PYEOF
    then
        fail "static_build_dispatch_wiring: see stderr above"
        return
    fi

    echo "  ok: static_build_dispatch_wiring"
}

echo "== release-build tests =="
test_staged_build_ok
test_not_prerelease
test_not_found
test_already_built
test_push_path_unchanged
test_guard_simulation
test_static_build_dispatch_wiring

if [ "$FAILED" != "0" ]; then
    echo "release-build tests: FAILED" >&2
    exit 1
fi

echo "release-build tests: OK"
