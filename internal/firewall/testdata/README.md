# internal/firewall/testdata — real per-fork CSF fixtures

Phase 14, plan 07 (requirement LAB-04). These are **real files captured from
the running CSF test lab** (Phase 14's OrbStack VM matrix), not hand-written
approximations — they ground `internal/firewall`'s fixture-driven tests
(`csf_fixtures_test.go`) in what each CSF fork actually prints/writes, so
Phase 15's fork-detection logic is built against real quirks instead of
assumptions.

## Regenerating

```
lab/capture-fixtures.sh [--no-reset] [vm...]
```

Run from the agent repo root (or via a VM list; default is all 5 CSF-variant
VMs below). By default it resets each target VM from its golden clone first
(`lab/reset.sh`) so the capture always starts from the same known-clean state
`lab/verify.sh` checks; pass `--no-reset` to capture from the VMs' current
state as-is (faster when the matrix is already known-healthy, e.g.
immediately after `make lab-verify` passed).

The script captures the 9 raw files below per fixture directory. It does
**not** write `expected.json` — that file encodes fixed per-fork facts
(already known from `lab/matrix.sh` and the phase research, not derived from
a single capture run) and is hand-maintained. If a capture disagrees with an
existing `expected.json`, re-check the VM before trusting the capture over the
existing value — matrix drift (if any) must be investigated, not silently
absorbed into a new expectation.

## Sanitisation

Each VM's own private IPv4 (OrbStack DHCP-assigned from the lab's private
/24, changes across VM resets) is replaced with `192.0.2.10` (TEST-NET-1,
RFC 5737 — reserved for documentation, never routable) in every captured
file.
This is the **only** redaction applied. Nothing else was stripped:

- `csf.conf`'s GPL header, `MM_LICENSE_KEY = ""`, `RECAPTCHA_SITEKEY = ""`,
  `RECAPTCHA_SECRET = ""`, `CLUSTER_KEY = ""` and `UI_PASS = "password"` are
  ConfigServer's own unconfigured stock defaults on a fresh install — not
  real secrets, license keys, or customer data.
- `csf.allow` only ever contains the lab's own panel-allow entry
  (`0.250.250.254 # lab-panel - ...`), added by `lab/provision/csf-*.sh`
  during VM provisioning. No real customer IP ever touches this lab.
- No agent tokens appear in any captured file — the capture only reads
  `/etc/csf/*`, never `/etc/defensia/config.json`.

## Fixture directories

| dir | source VM | distro | fork pin (`lab/forks.lock`) | `csf -v` reports | variant |
|---|---|---|---|---|---|
| `original-15.00` | `alma9-csf-orig` | AlmaLinux 9 | `2923c43f...` (original-15.00) | `csf: v15.00 (generic)` | generic |
| `aetherinox-15.10` | `alma9-csf-aetherinox` | AlmaLinux 9 | `4260bc81...` (aetherinox-15.10) | multi-line banner, `v15.10 (generic)` on line 2 | generic |
| `sentinel-15.13` | `debian12-csf-sentinel` | Debian 12 (bookworm) | `8278b57b...` (sentinel-15.13) | `csf: v15.11 (generic)` | generic |
| `directadmin-15.12` | `alma9-csf-da` | AlmaLinux 9 | `444d6dac...` (directadmin-15.12) | `csf: v15.12 (DirectAdmin)` | DirectAdmin |
| `cwp-orphan-15.00` | `alma8-csf-cwp-orphan` | AlmaLinux 8 | `2923c43f...` (original-15.00 release, but configured as an abandoned CWP install) | `csf: v15.00 (generic)` + `*WARNING* TESTING mode is enabled` | generic |

Each directory contains:

| file | source | notes |
|---|---|---|
| `csf-v.txt` | `csf -v 2>&1` | raw combined stdout+stderr, byte-for-byte except IP sanitisation |
| `version.txt` | `/etc/csf/version.txt` | the release's own version stamp (not always equal to what `csf -v` prints — see quirks below) |
| `downloadservers` | `/etc/csf/downloadservers` | update-check source(s); comments preserved |
| `csf.conf` | `/etc/csf/csf.conf` | full stock config as provisioned for this VM |
| `csf.allow` | `/etc/csf/csf.allow` | contains only the lab's own panel-allow entry |
| `csf.deny` | `/etc/csf/csf.deny` | captured immediately after `csf -d 203.0.113.9 lab-fixture`, then the entry is removed again (`csf -dr`) so the live VM is unaffected |
| `lfd-ps.txt` | `ps -eo user,args \| grep '[l]fd'` | empty only for `cwp-orphan-15.00` (lfd is not running there — see quirks) |
| `lfd-active.txt` | `systemctl is-active lfd` | `active` or `inactive` |
| `captured.txt` | script-generated | `vm=... distro=... fork=... date=<UTC ISO> forks.lock-pin=...` — provenance, not parsed by any test |
| `expected.json` | hand-maintained | the ground truth the fixture-driven tests assert against (see schema below) |

### `expected.json` schema

```json
{
  "csf_version": "15.00",
  "variant": "generic",
  "testing": "0",
  "lfd_active": true,
  "configserver_com_source": false,
  "deny_contains": "203.0.113.9",
  "allow_comment_contains": "lab-panel"
}
```

## Known per-fork quirks (why these fixtures exist)

- **Aetherinox (`aetherinox-15.10`): multi-line `csf -v`.** Unlike every
  other fork, its `csf -v` output is a 4-line banner (`ConfigServer Security
  & Firewall` / `v15.10 (generic)` / `License: None` / `Channel: Stable
  Channel`) — the version is on the **second** line. A naive `head -1`
  parse would miss it entirely; `parseCSFVersion` (the Phase 14 plan 01
  seam) scans every line for this reason. Its `downloadservers` active
  (non-comment) line is `download.configserver.dev` — a different domain
  from the dead `configserver.com`, not a `.com` match.
- **Sentinel (`sentinel-15.13`): release 15.13 reports 15.11.** The
  installed package is the 15.13 release (pinned by commit in
  `lab/forks.lock`), but its own `csf -v` prints `csf: v15.11 (generic)` —
  the fork's internal version string lags its release tag. Fixture tests
  must assert the **reported** `15.11`, never the release number, and this
  mismatch is deliberately pinned by `TestFixtureSentinelVersionQuirk` so a
  future parser "fix" that starts returning `15.13` is caught as a
  behaviour change, not silently accepted.
- **DirectAdmin (`directadmin-15.12`): variant string.** `csf -v` prints
  `csf: v15.12 (DirectAdmin)` instead of `(generic)` — the only fork in this
  set whose parenthesised variant differs. `csf.conf`'s format is otherwise
  identical to the generic forks (same `TCP_IN`/`TCP_OUT` key style).
- **CWP orphan (`cwp-orphan-15.00`): simulates an abandoned CentOS Web Panel
  install.** Same underlying CSF release as `original-15.00` (15.00,
  `(generic)`), but: `TESTING = "1"` in `csf.conf` (lfd never daemonises —
  `lfd-active.txt` is `inactive` and `lfd-ps.txt` is **empty**, the one
  fixture directory where that file is legitimately 0 bytes, not a capture
  bug); `downloadservers` still points at the now-dead
  `download.configserver.com`/`download2.configserver.com` (uncommented,
  unlike `original-15.00` where the same two lines are commented out); and
  `csf -v` prints an extra `*WARNING* TESTING mode is enabled` line after the
  version line. This models exactly what Phase 15's fork detection will see
  on a real customer box nobody has touched since ConfigServer stopped
  distributing CSF (2025-08-31).
- **`original-15.00`:** the one fixture with no quirks — `downloadservers`'
  two `download.configserver.com`/`download2.configserver.com` lines are
  commented out (`#download.configserver.com`), i.e. update-checking is
  disabled by default, which is why `configserver_com_source` is `false`
  here but `true` for the orphan (same lines, minus the `#`).

## Out of scope

Licensed cPanel and DirectAdmin installations (the real commercial panels,
as opposed to the `poralix/da-csf` DirectAdmin-compatible fork captured
here) are **not** represented in this fixture set — they require a paid
license and are validated later, on licensed pilot servers (Phase 21), not
in this local lab.

## Known parser gaps for Phase 15

None found while writing `csf_fixtures_test.go` — `parseCSFVersion`,
`csfInfoFrom`, `csfConfigValue` and `csfListEntries` (the Phase 14 plan 01
seam) all produce the values `expected.json` asserts for every fixture,
including the Aetherinox multi-line banner and the Sentinel 15.11-vs-15.13
mismatch. This section exists for Phase 15 to append to if that plan's
production work discovers a gap between what this seam currently returns and
what fork detection actually needs (e.g. distinguishing the `variant` string
programmatically — today's `csfInfoFrom` does not expose it at all, only the
numeric `Version`).
