# OpenLine Release 001 — local-first receiver-owned authority for agents

The simplest free, local-first, self-hostable OpenLine an unfamiliar
coding agent can install and use. No cloud service, no account, no
new authorization engine: a thin CLI + MCP server over the existing
receiver-owned engines (Protect, ProjectLedger, SafePromotion,
LocalEffectStore, continuity audit).

## Install + first proof (measured, under 10 minutes)

Prerequisites: `python3`, `git`. Then:

```
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
```

Measured here: venv 4s, pip install 3s (cryptography 50.0.2).
With cryptography already installed, skip the venv entirely.

From a checkout (or the exact-source archive, which preserves the
`experiments/` layout):

```
python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo
```

That runs the full mission in seconds: forbidden change STOPPED,
authorized repair ACCEPTED with a verified receipt, falsifier report
UNKNOWN with the candidate preserved, second disruption with
revocation + replacement ACCEPTED and unrelated work CURRENT,
boundary gate, effect binding, real-CLI recover/verify, isolation
probe, and the same-UID deployment condition. Exit 0 only if every
step passes.

Then your own project:

```
python3 experiments/OPENLINE-RELEASE-001/openline init --dir ~/ol-proj
python3 experiments/OPENLINE-RELEASE-001/openline assign --dir ~/ol-proj \
  --assignment repair-1 --worker bob --basis invoice_v2
python3 experiments/OPENLINE-RELEASE-001/openline prepare --dir ~/ol-proj \
  --assignment repair-1
# edit the printed workspace's app/price.py, then:
python3 experiments/OPENLINE-RELEASE-001/openline intercept --dir ~/ol-proj \
  --assignment repair-1
python3 experiments/OPENLINE-RELEASE-001/openline status --dir ~/ol-proj
```

MCP (stdio, standard library only, no SDK to install):

```
python3 experiments/OPENLINE-RELEASE-001/openline mcp --dir ~/ol-proj
```

Tools: `openline_status`, `openline_prepare`, `openline_intercept`,
`openline_verify_receipt`, `openline_recover`. Assignment creation
and dependency changes are deliberately NOT MCP tools: they require
contributor/owner signatures, and those keys must not live in a
receiver-side server. They are CLI steps, or out-of-band
`--signature` flows. See `mcp_test.py` for a raw-protocol test
(no host needed).

## Commands

`init`, `assign`, `prepare`, `intercept`, `verify`, `status`,
`recover`, `change`, `revoke`, `effect-demo`, `mcp`. Every command
prints one JSON object to stdout. `intercept` exits 0 ACCEPTED,
3 STOPPED, 4 UNKNOWN, 2 on usage/engine error.

## What the gate guarantees, and what it does not

- The receiver (this CLI/server, running as the operator) owns the
  keys, policy, Git accepted ref, ledgers, and receipts. A worker
  that only holds an assignment cannot admit its own work.
- A signed receipt proves what the receiver recorded and signed. It
  does not prove a downstream effect happened, and it cannot cover
  actions that never crossed the recording boundary.
- Effect entries can be BOUND to the observed accepted head +
  contract + assignment state (`effect-demo`). Binding records what
  was observed at apply time; Git/project/effect stores remain
  NONATOMIC. Disagreement after the fact is RECONCILIATION_REQUIRED,
  not silent consistency.
- The gate holds only under SEPARATE OS identities. A same-UID
  process can write receiver paths directly (proved, restored, in
  the demo). That is a deployment requirement, not a gate defect,
  and it applies symmetrically to the conventional baseline.
- On filesystems where the receiver tree inherits a group shared
  with the worker (setgid parent), git creates group-writable repo
  dirs. The boundary check refuses such a tree; `init` hardens it
  to owner-only modes and records before/after.
- Membership in `init` is local bootstrap (the operator creates
  members). A real World admission would replace the verifier; the
  demo does not claim one.

## Keys

`init` writes per-member keyfiles (0600) under `<dir>/keys/` plus a
receiver keyfile. Those are local demo credentials. NEVER ship a
project directory (it contains keys); ship only code and evidence.
Production members hold their own keys and sign out-of-band
(`--signature` on assign/change/revoke; claim formats are the
engine's documented claim dicts).

## License / provenance (public release version)

This public release is licensed under Apache-2.0; see the top-level
`LICENSE`, `PROVENANCE.md`, and `RELEASE_NOTES.md`. That public license
supersedes the private-evaluation notice that was in the original
internal candidate. Engine files are used unmodified from the frozen
closeout (#157), except for the two documented corrections in
`PROVENANCE.md` (SQLite connection close; strict MCP type validation);
the release package imports them by path (see `engine_loader.py`) and
never vendors a drifted copy. The separate public OpenLine Connect
project (Apache-2.0) is a different codebase and is not part of this
candidate.

## Evaluation (public package)

- Genuine-host gate: NOT RUN in this public package. A live coding-agent
  host was not available (Codex not logged in; no paid API substituted).
  MCP is proven at the raw protocol level only.
- Replay: `REPLAY.sh` (python3 only).
- Full verification, counts, limitations, and excluded files: see the
  top-level `PROVENANCE.md` and `RELEASE_NOTES.md`.

## What is NOT claimed

No genuine host run, no external receiver, no production isolation,
no multi-agent runs, no held-out tasks, no cost superiority, no
independent adoption. The conventional comparison is PARITY on
refusal/acceptance/retry/revocation outcomes; the OpenLine delta is
narrow (signed receipts + effect binding). Any superiority claim
requires measured evidence Argon does not yet have.
