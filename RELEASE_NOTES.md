# Release notes — OpenLine Living Projects 0.1.0

Tag: `v0.1.0`
Repository: https://github.com/terryncew/openline-living-projects
License: Apache-2.0 (see `LICENSE`)
Status: Public developer preview. Not production authorization
infrastructure. Not a payment system. Not a hosted service.

This release supersedes `v0.1.0-rc3-corrected` as the version to
point people toward. That frozen tag and commit
(`136203d0f557213065ade7a638f1169940063e36`) are NOT overwritten
or changed by this release. This release is a new commit on top of
it, under a new tag.

## Baseline

The parent of this release is the frozen `v0.1.0-rc3-corrected`
commit, which was itself the internal RC3 candidate
(`a9ef5d120ef53daf4db19fbb2204022ae0410c64`) plus the manager
combined correction patch (`RC3_MANAGER_R1_R2_FIX.patch`, SHA-256
`e691486f41c079d0738d30a6b43e0b34511a754b41203735c45cde108ba61564`:
SQLite connection context manager, MCP strict validation for
progress fields and `receiver_verified`, QUICKSTART RC3 labels,
executable `openline` script).

## What changed in 0.1.0

### Security corrections, in order, inspected before applying

1. Argon outsider patch `OPENLINE_IMPROVEMENTS.patch`, Drive file
   `1DFnzgdKXoWaUKQyWmEfOyW88sIL9VN4E`, SHA-256
   `90f77fefe0a7c0dd2b5c9d0e2fd4e0c126631c9e891ca08b684efd17b6c3ba23`.
   It applies cleanly to the frozen public package. Fixes:
   - F-01 (HIGH): `ReceiverGuard` and `LocalEffectStore` reject
     boolean, NaN, infinite, non-positive, and missing amounts
     when a signed grant or delegation sets a maximum.
   - F-02 (HIGH): `ProjectLedger.propose_memory` refuses settled
     memory overwrites, cross-worker candidate overwrites, and
     assignment-scope mismatches.
   - F-03 (MEDIUM): `record_graph_claim` refuses unsigned or
     other-signer overwrites of a `CRYPTOGRAPHICALLY_BOUND` claim.
   - F-04 (LOW): MCP `threshold` is strict-typed (no `int()`
     coercion) in watchdog status and record tools.
   - F-05 (LOW): `mcp_test.py` closes subprocess stdout/stderr
     pipes, removing the harness ResourceWarning.
   - F-06 (MEDIUM): `OPENLINE-PROTECT-005/REPLAY.sh` uses
     `python3`, not `python`.
   - F-07 (MEDIUM): `OPENLINE-RELEASE-001/REPLAY.sh` falls back
     to `/tmp` (or honors `OPENLINE_REPLAY_RUNS_DIR`) when the
     checkout mount does not support SQLite locking.
   - New regression suite
     `tests/test_argon_outsider_improvements.py` (4 tests).

2. GPT-6 follow-on security patch
   `GPT6_ARGON_FOLLOWON_SECURITY.patch`, Drive file
   `1Z9p9jHAyFbRJ4-AZN2tv53MjIP5Y9m8n`, SHA-256
   `8f2dbefb9070f4bbb5b32858e695ccbade937ba4b49212be703f63f957681208`.
   It applies cleanly on top of the Argon-patched tree (it is
   relative to that candidate, not to pristine RC3). Fixes:
   - F-01 follow-on (HIGH): the signed cap itself is validated
     in `ReceiverGuard` and `LocalEffectStore`. A signed NaN,
     infinite, boolean, string, zero, or negative cap is refused
     with `invalid_authorized_cap` / `invalid_delegation_cap`,
     with no ledger effect, even though the grant signature is
     valid. Previously a NaN cap let amount 99999 commit.
   - F-02 follow-on (HIGH): `propose_memory` refuses an
     assignment that does not exist (`memory_assignment_missing`),
     so a worker cannot preplant memory on a future assignment.
     When a legitimate repair is accepted, old candidates whose
     worker, deliverable, or basis do not match the active
     assignment are quarantined, and only matching candidates
     are inherited.
   - New regression suites
     `tests/test_gpt6_malformed_grant_cap.py` (2 tests) and
     `tests/test_gpt6_memory_preplant.py` (2 tests).

3. Final-release fixes by the independent verifier (this release):
   - F-08: `OPENLINE-PROTECT-001/protect.py` closes its three
     SQLite connections with `closing()` instead of relying on
     garbage collection. Previously `with sqlite3.connect(...)`
     left connections unclosed at interpreter finalization,
     which is the source of the ResourceWarnings GPT-6 reported
     on Python 3.13. After this fix, the Release-001 and RC3
     suites run on Python 3.12.3 with `-W error::ResourceWarning`
     and zero ResourceWarnings in their logs. Python 3.13 is
     still NOT TESTED in this environment (no 3.13 interpreter),
     so 3.13 cleanliness is not claimed.
   - F-09: `living_projects_watchdog_e2e.py` creates its
     evidence directory before writing. On a fresh public clone
     the script previously failed at the final write with
     `FileNotFoundError`, after the scenario itself had run.
     This was pre-existing on the frozen baseline, not a
     regression from the Argon or GPT-6 patches.
   - MCP server version string updated from `0.3.0-rc3` to
     `0.1.0`, to match this release. `mcp_test.py` still passes.

No other product logic was changed. No rewrite, no second
platform, no new authority engine.

### First-experience fixes (no product logic change)

- Top-level README own-project example fixed: it assigned
  `repair-1` and then prepared/intercepted `rep-1`, which
  failed with `repair_assignment_missing`. It now uses `rep-1`
  throughout, with the exact price edit (`qty * 11` for basis
  `invoice_v2`) and the expected ACCEPTED / SEALED / HEALTHY
  result. Verified verbatim from a fresh project directory.
- New `GETTING_STARTED.md`: an AI-readable guide that maps a
  person's interest to a deliverable, basis, assignment, and
  worker in plain language, with exact install, demo, and
  first-project commands, and an honest limitations section.
- New `install.sh` and `requirements.txt`: `install.sh` checks
  Python 3.11+ and git, creates `.venv`, installs only
  `cryptography`, and verifies `PUBLIC-SHA256SUMS.txt`, failing
  closed on any mismatch.
- README MCP section now includes a copy-paste host config with
  absolute paths, and a stdio test (tools/list + status) to run
  before relying on it. Verified with a real stdio MCP client:
  initialize, tools/list (11 tools), status, and string/boolean
  threshold refusals (isError), server survives.

## Verified results (final gate, Python 3.12.3, Linux)

- Bundled suites: 206 ran, 203 pass, 3 clean skips, 0 fail.
  The 3 skips are the `openline_lite`-dependent MCP-entry tests,
  skipped offline, not passes. The increase from 198 (frozen
  release) is exactly the 8 new Argon + GPT-6 tests.
  Note: the MCP-entry suite must be run from its own directory;
  run from the repository root its probe subprocess cannot find
  its server module and fails with `mcp_probe_server_failed`.
  That is a harness/cwd artifact, not a product failure, and it
  reproduces on the frozen baseline.
- New tests: Argon 4/4, GPT-6 4/4.
- Independent adversarial script (beyond the new suites):
  27/27 passed on the patched tree, covering guard and effect
  bad caps (NaN, infinite, boolean, string, zero, negative),
  bad amounts (boolean, NaN, infinite, negative, zero, string,
  missing), a valid commit path, no-effect-on-refusal row
  counts, future-assignment preplant refusal, and cross-worker
  propose refusal. The same script on the frozen baseline fails
  and then crashes on a string cap in the effect store, proving
  it is not vacuous. Bound-claim downgrade is covered by the
  Argon suite (unsigned refusal, other-signer refusal, original
  signer legitimate update).
- Demo: `run_demo.py` ALL STEPS PASS. `openline replay` exit 0.
- Replays: `OPENLINE-RELEASE-001/REPLAY.sh` exit 0
  ("RELEASE REPLAY COMPLETE"), `OPENLINE-PROTECT-005/REPLAY.sh`
  exit 0 ("PRIVATE GATES COMPLETE").
- E2E: `living_projects_e2e.py` exit 0 (PASS),
  `living_projects_watchdog_e2e.py` exit 0 after the F-09 fix
  (carol intercept ACCEPTED, final deliverables CURRENT).
- README own-project verbatim: ACCEPTED / SEALED / HEALTHY.
- QUICKSTART section 3 verbatim: intercept ACCEPTED, memory
  INHERITED, guard SEALED, doctor HEALTHY.
- MCP: `mcp_test.py` ALL STEPS PASS; host-config stdio test
  passed (see above); MCP strict validation from the earlier
  post-audit gate (8 malformed inputs refused) still holds via
  the Argon/GPT-6 suites.
- Two-disruption recovery: covered by the demo, the 12-step E2E,
  and RC3 suite test_02 (two disruptions, revocation, replacement,
  unrelated work preserved). Protect-005 replay also reports
  "TWO_SCRIPTED_DISRUPTIONS_LOCAL_GIT_PASS" with unrelated
  accepted work preserved.
- Conventional comparison: PARITY on refusal/acceptance/retry/
  revocation outcomes (replay baseline line, RC3 suite
  test_06/07, Protect-005 conventional comparison). The narrow
  OpenLine delta is signed receipts including refusals,
  effect-state binding, and persistent cross-agent stagnation
  tracking with signed reconciliation. No superiority claim.
- Argon's working application CivicLedger Shield (NOT part of
  this public package, NOT published here): 10/10 tests pass
  when run from its own directory against this candidate.
  It is evidence that a stranger's AI could build with the
  primitives, not a claim of adoption or revenue.
- Resource warnings: 0 ResourceWarnings in any bundled suite log
  on Python 3.12.3 with `-W error::ResourceWarning`, after the
  F-08 fix.

## What remains NOT TESTED or NOT CLAIMED

- Python 3.13 and Python 3.11: NOT TESTED in this environment
  (only 3.12.3 available). GPT-6's Python 3.13 resource-warning
  finding is addressed by the F-08 fix in code, but 3.13
  cleanliness is not verified here.
- Live coding-agent host: NOT TESTED. Codex binary is detected
  by `doctor` but is not logged in; no paid API was used.
  MCP is proven at raw stdio protocol level only.
- External receiver acceptance, outsider adoption, revenue:
  NOT TESTED and NOT CLAIMED. Argon's experiment separates
  "AI suggested something" and "AI built something" (achieved)
  from "a human found it useful" and "someone adopted or paid"
  (not occurred).
- macOS/Windows: NOT TESTED. Linux only.
- Production isolation beyond a container, multi-agent or
  held-out tasks, cost/latency superiority: NOT CLAIMED.
- In-flight revocation is bounded, not instant. Same-UID
  deployment condition stands: the gate holds only under
  separate OS identities. Watchdog is advisory, authorization
  NONE. A signed receipt proves what the receiver recorded and
  signed, not a downstream effect, and cannot cover actions
  that never crossed the recording boundary.

## What is NOT in this release

Same exclusions as the frozen release (see `PROVENANCE.md`):
internal roadmap, handoff/verdict/gate/closeout documents, the
TOE-graph experiment, the private watchdog zip, neutral
evaluation materials, internal evidence logs, and stale internal
manifests. Argon's CivicLedger Shield application is also NOT
included; it is Argon's work, held in Drive, not part of this
package. No private research, credentials, or founder TOE
documents are published.
