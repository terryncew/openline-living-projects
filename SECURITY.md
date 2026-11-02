# Security and limitations

This is a developer preview, not production authorization infrastructure.
Read this file before using it for anything real.

## What the gate guarantees, and what it does not

- The receiver (this CLI/server, running as the operator) owns the
  keys, policy, Git accepted ref, ledgers, and receipts. A worker
  that only holds an assignment cannot admit its own work.
- A signed receipt proves what the receiver recorded and signed. It
  does not prove a downstream effect happened, and it cannot cover
  actions that never crossed the recording boundary.
- Effect entries can be bound to the observed accepted head, contract,
  and assignment state. Binding records what was observed at apply
  time. Git, project, and effect stores remain non-atomic.
  Disagreement after the fact is reconciliation, not silent consistency.
- The watchdog is advisory. Its decisions carry receiver authorization
  NONE. It grants no authority, and it must not be used as an allow/deny
  gate for a real receiver.
- Post-halt watchdog attempts are not recorded by design. The worker
  set freezes at halt time.
- The clear-hold path is trusted to a single caller: the integrated
  supervisor's owner-reconcile step, after owner-signature verification.
  A deployment that adds another caller to that path changes the trust
  boundary and is not covered by this release's verification.

## Deployment conditions

- The gate holds only under separate OS identities. A same-UID
  process can write receiver paths directly. That was demonstrated
  and restored in the demo. It is a deployment requirement, not a
  gate defect, and it applies symmetrically to the conventional
  baseline.
- On filesystems where the receiver tree inherits a group shared with
  the worker (setgid parent), git creates group-writable repo dirs.
  The boundary check refuses such a tree; `init` hardens it to
  owner-only modes and records before/after.
- Membership in `init` is local bootstrap (the operator creates
  members). A real admission system would replace the verifier; the
  demo does not claim one.
- `init` writes per-member keyfiles (0600) under `<dir>/keys/` plus a
  receiver keyfile. Those are local demo credentials. NEVER ship a
  project directory (it contains keys); ship only code and evidence.
  Production members hold their own keys and sign out-of-band.

## Known limits in this release

- No live coding-agent host was tested. Codex was not logged in and
  no paid API was substituted. MCP is proven at the raw protocol
  level only, not through an official host.
- No outsider adoption, no external receiver, no production isolation
  beyond the verifier's container, no macOS/Windows testing.
- No multi-agent or held-out task testing. No cost or latency
  superiority claim.
- The three `openline_lite`-dependent MCP-entry tests are skipped
  offline. They are not passes.
- Python 3.13 was not tested in the verifier's environment. The
  release was verified on Python 3.12.3. See `RELEASE_NOTES.md` for
  the warning reconciliation.
- In-flight revocation is bounded, not instant. This release does not
  claim instant revocation.

## Reporting

This is a public preview by an individual author, not a maintained
security product with a response SLA. Do not use it to protect real
money, real infrastructure, or real personal data until you have
independently reviewed the code and the deployment conditions above.
