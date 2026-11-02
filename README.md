# OpenLine Living Projects

**Receiver-owned authority for AI agents, local-first. Developer preview.**

A local operator controls which agent work is allowed, saves exactly the
work it admits, and signs decisions that another machine can verify
offline. No cloud service, no account, no payment, no external side
effects in this preview.

This is not production authorization infrastructure, not a payment
system, and not a hosted service. Effects are SQLite-local. See
`SECURITY.md` and `PROVENANCE.md` before using it for anything real.

## What it does, in one paragraph

You run a project as the receiver. You create members and scoped
assignments. A worker prepares a candidate change in a separate
workspace. The receiver's Protect gate independently checks that
candidate against the assignment, the accepted Git head, and the
project ledger, then either ACCEPTS it (with a signed, offline-verifiable
receipt) or STOPs / refuses it, preserving unrelated accepted work.
If a worker stalls, a cross-agent watchdog (advisory only) tracks
stagnation by deliverable and basis across workers and restarts, and
requires an owner-signed reconciliation to clear a hold. The same
machinery can continue a project after a worker is revoked and
replaced, from the last accepted checkpoint.

## Install

Prerequisites: Python 3.11+, `git`, Linux. macOS and Windows are
untested in this release.

```bash
git clone https://github.com/terryncew/openline-living-projects.git
cd openline-living-projects
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
```

No other package is required. The MCP server uses only the Python
standard library. Do not install anything else to run the demo.

Verify the package you cloned:

```bash
sha256sum -c PUBLIC-SHA256SUMS.txt
```

## First proof

```bash
python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo
bash experiments/OPENLINE-RELEASE-001/REPLAY.sh
```

The demo runs the full mission in seconds: a forbidden change is
STOPPED, an authorized repair is ACCEPTED with a verified receipt, a
falsifier report is UNKNOWN with the candidate preserved, a second
disruption with revocation and replacement is ACCEPTED, the boundary
gate and effect binding are checked, real CLI recover/verify runs,
an isolation probe runs, and the same-UID deployment condition is
shown. Exit 0 only if every step passes.

`REPLAY.sh` runs the demo, the MCP protocol test, the conventional
baseline, and the 24 adversarial regression tests.

For the full quickstart, including your own project, see
`QUICKSTART.md`.

## Your own project

```bash
OPENLINE=./experiments/OPENLINE-RELEASE-001/openline
$OPENLINE init --dir ~/ol-proj --project-id demo-1 --workers alice,bob,carol
$OPENLINE assign --dir ~/ol-proj --assignment repair-1 --deliverable invoice-feature --worker bob --basis invoice_v2 --allowed-paths app/price.py
$OPENLINE prepare --dir ~/ol-proj --assignment rep-1
# edit the printed workspace's app/price.py, then:
$OPENLINE intercept --dir ~/ol-proj --assignment rep-1
$OPENLINE status --dir ~/ol-proj
$OPENLINE guard --dir ~/ol-proj
$OPENLINE doctor --dir ~/ol-proj
```

`init` creates the project, members, and keys. `assign` creates an
assignment. `prepare` makes a candidate workspace. `intercept` admits
or refuses that candidate. `status` shows the current head and
deliverables. `guard` seals and verifies the receiver state.
`doctor` checks continuity and the receiver boundary.

Every command prints one JSON object to stdout. `intercept` exits 0
for ACCEPTED, 3 for STOPPED, 4 for UNKNOWN, and 2 for usage or engine
errors.

`verify` checks a receipt offline, with a pinned receiver key:

```bash
./experiments/OPENLINE-RELEASE-001/openline verify --receipt <receipt.json> --pinned-key <hex>
```

A signed receipt proves what the receiver recorded and signed. It
does not prove a downstream effect happened, and it cannot cover
actions that never crossed the recording boundary.

## MCP

```bash
./experiments/OPENLINE-RELEASE-001/openline mcp --dir ~/ol-proj
```

This is a stdio JSON-RPC 2.0 server. Tools: `openline_status`,
`openline_prepare`, `openline_intercept`, `openline_verify_receipt`,
`openline_recover`, `openline_watchdog_status`,
`openline_watchdog_record`, `openline_doctor`, and others listed by
`tools/list`. Assignment creation and dependency changes are
deliberately NOT MCP tools: they require contributor/owner signatures,
and those keys must not live in a receiver-side server.

## Layout

- `experiments/OPENLINE-RELEASE-001/` — the main CLI (`openline`),
  MCP server, demo, baseline comparison, and replay scripts.
- `experiments/OPENLINE-PROTECT-001/` — the Protect gate.
- `experiments/OPENLINE-PROTECT-002/` — continuity audit.
- `experiments/OPENLINE-PROTECT-003/` — repeating-loop repair.
- `experiments/OPENLINE-PROTECT-005/` — conventional comparison.
- `experiments/OPENLINE-GRAPH-WATCHDOG-001/` — cross-agent
  stagnation watchdog (advisory) and its durable SQLite store.
- `experiments/OPENLINE-AGENT-WATCHDOG-001/` — agent watchdog and
  execution supervisor.
- `experiments/LIVING-PROJECTS-001/`, `SELF-HEALING-ENGINE-001/`,
  `SELF-HEALING-PROJECTS-001/`, `OPENLINE-COACH-001/`,
  `OPENLINE-MCP-ENTRY-001/`, `OPENLINE-ONE-001/`,
  `CODEX-B-ISOLATED-REPAIR-001/` — the engines and entry points
  the release CLI loads by path.

## What is NOT claimed

No genuine live coding-agent run, no external receiver, no production
isolation, no multi-agent runs, no held-out tasks, no cost superiority,
no independent adoption. The conventional comparison is PARITY on
refusal/acceptance/retry/revocation outcomes; the OpenLine delta is
narrow: signed receipts (including refusals), effect-state binding,
and persistent cross-agent stagnation tracking with signed
reconciliation. Any superiority claim requires measured evidence that
does not exist yet.

See `SECURITY.md` for the full limitation list, and `PROVENANCE.md`
for exactly what was verified, what was excluded, and what remains
untested.
