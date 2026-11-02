# Release notes — OpenLine Living Projects, public corrected RC3

Tag: `v0.1.0-rc3-corrected`
Repository: https://github.com/terryncew/openline-living-projects
License: Apache-2.0 (see `LICENSE`)
Status: Public developer preview. Not production authorization
infrastructure. Not a payment system. Not a hosted service.

## What changed from the internal RC3 candidate

Original internal candidate: RC3 HEAD
`a9ef5d120ef53daf4db19fbb2204022ae0410c64`, branch
`engineering/argon-living-projects-rc3-20261101`.

This public release applies exactly one combined correction patch,
once, to that pristine candidate:

- Manager patch `RC3_MANAGER_R1_R2_FIX.patch`, Drive file
  `11YowGTOsN1PmmBlMg4Ruc-5R5GXdyvnz`, SHA-256
  `e691486f41c079d0738d30a6b43e0b34511a754b41203735c45cde108ba61564`.
- The patch includes the earlier SQLite connection fix, so the
  SQLite patch was NOT stacked on top of it. Re-applying the SQLite
  patch to the corrected tree fails, as expected, because its change
  is already present.
- Patch effect, exactly 4 files:
  1. `experiments/OPENLINE-GRAPH-WATCHDOG-001/openline_graph_watchdog/durable_watchdog.py`
     — `_db()` becomes a context manager that closes the SQLite
     connection on all paths. Corrected file SHA-256
     `a7b81fe1f17639956e63955246fcd8073c61a4818fd2abeef2ec1ed49c1487ba`,
     identical to the earlier SQLite-corrected candidate.
  2. `experiments/OPENLINE-RELEASE-001/mcp_server.py`
     — strict type validation for `openline_watchdog_record`: integer
     fields must be integers (booleans rejected) and
     `receiver_verified` must be a boolean. No more `int()` / `bool()`
     coercion of those fields. Corrected file SHA-256
     `c8beb19b25157e827e216737f58bb1de0e2951fe2e9bcc8db0684563981a4b7c`.
     Residual note: `threshold` is still passed through `int()`. It is
     a configuration parameter, not trusted progress evidence, and it
     was out of scope for this fix.
  3. `QUICKSTART.md` — RC3 labels, corrected-candidate notice, and
     limitations. In this public package the quickstart is further
     adapted for a git clone (see `PROVENANCE.md` packaging edits).
  4. `experiments/OPENLINE-RELEASE-001/openline` — mode change to
     executable (100755). Content hash unchanged:
     `0161383e66e3987606269638fd755632f07dda9524242792821a378a7df79f66`.

No other code changes were made. ProjectLedger, Protect,
SafePromotion, LocalEffectStore, supervisors, and watchdog semantics
are unchanged from the internal RC3 candidate, except for the three
deliberate fail-closed RC3 deltas already in RC3 (conflicting duplicate
attempts raise, progress reset requires after > before and > peak,
durable migration retroactively halts scopes already at/over threshold).

## Verified results (post-audit, Python 3.12.3, Linux container)

Full internal gate (for reference): bundled suites 199 ran, 196 pass,
3 clean skips, 0 fail; adversarial suite 29/29; replay exit 0;
both E2E scripts exit 0.

This public package (TOE experiment excluded; see `PROVENANCE.md`):
bundled suites 198 ran, 195 pass, 3 clean skips, 0 fail. The 3 skips
are the `openline_lite`-dependent MCP-entry tests, skipped offline,
not passes.

Post-audit re-verification on the corrected candidate:
- MCP strict validation: 8 malformed inputs refused with `isError`
  (string "false", string "true", int 1 for `receiver_verified`;
  string, boolean, float, and null for progress fields), no watchdog
  scope created, server survives, valid records still work.
- Adversarial suite, with the one MCP expectation updated from the
  old coercion behavior to the new refusal behavior: 29/29.
- Release replay (`REPLAY.sh`): exit 0, about 20 seconds, in two
  separate runs, including a run with `PYTHONWARNINGS=error::ResourceWarning`.
- 12-step E2E: exit 0. Watchdog E2E: exit 0.
- QUICKSTART core flow via direct `./openline`: intercept ACCEPTED,
  guard SEALED, doctor HEALTHY.
- Watchdog suite with `-W error::ResourceWarning`: 21/21, no
  ResourceWarning escapes.

## Manager-environment discrepancies, reconciled, not waived

1. Replay timeout in the manager's environment, twice.
   In the verifier's environment the same replay exits 0 in about
   20 seconds, twice, on both the internal corrected tree and the
   public package. No hang was reproduced. The manager's timeout is
   recorded as environmental to the manager's runtime, not as a
   product hang in the verifier's environment. It is not converted
   into a PASS for the manager's environment.

2. SQLite resource warnings on Python 3.13 in the manager's environment.
   Python 3.13 is not available in the verifier's environment, so
   3.13-specific warnings could not be reproduced here. In the
   verifier's Python 3.12.3 environment, no SQLite ResourceWarning
   was found in the watchdog suite (run with warnings as errors),
   in the replay (run with warnings as errors), or in a grep of the
   replay log. The only ResourceWarnings surfaced in the replay log
   are unclosed file pipes in the `mcp_test.py` test harness
   (stdout/stderr of the MCP subprocess are not closed after
   `stdin.close()` + `wait()`), not SQLite connections and not
   product code. That harness warning does not fail the replay and
   is not a release blocker, but it is recorded here so a future
   3.13 run can distinguish it from a SQLite leak.
   Release claim: tested on Python 3.12.3 only. Python 3.13 is
   NOT TESTED in this verification.

## What is NOT in this release, and why

See `PROVENANCE.md` for the full excluded-files list. In short:
the internal private/draft roadmap document, all internal handoff /
verdict / breakthrough / gate / closeout documents, the TOE-graph
experiment (including coherence-dynamics files), the private
watchdog zip bundle, the neutral-evaluation materials, and internal
evidence logs are excluded. The public package contains product code,
its tests, and public documentation only. The excluded TOE experiment
accounts for the one-test difference between the internal gate count
(199) and the public package count (198).

## What is NOT claimed

No live coding-agent autonomy, no external receiver acceptance, no
outsider adoption, no production isolation, no macOS/Windows support,
no multi-agent or held-out task results, no cost or latency
superiority, no instant revocation. Conventional comparison is
PARITY on refusal/acceptance/retry/revocation outcomes. A signed
receipt proves what the receiver recorded and signed, not that a
downstream effect happened, and it cannot cover actions that never
crossed the recording boundary.
