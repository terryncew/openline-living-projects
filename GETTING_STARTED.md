# Getting started with OpenLine Living Projects

Read this first if you are a coding AI given only the repository URL,
or a person who has never seen OpenLine before. No internal
architecture is assumed.

## What OpenLine is, in plain language

OpenLine is a local tool that lets a person (the owner) stay in
control while AI workers do coding work.

- **Owner / receiver.** You. You hold the keys, you create the
  project, and only your signed decisions admit work. Nothing is
  admitted because an agent said it was done.
- **Worker.** A named member, for example `alice` or `bob`. A
  worker proposes a change. A proposal is not an acceptance.
- **Deliverable.** The thing being built, for example
  `invoice-feature`, a small price calculator.
- **Basis / contract.** The rule the deliverable must satisfy right
  now. In the built-in example, `invoice_v1` means `total(2) == 20`,
  `invoice_v2` means `total(2) == 22`, `invoice_v2b` means
  `total(2) == 24`, and `invoice_v3` means `total(2) == 26`.
  Changing the basis reopens only the deliverables that depend on
  it. Unrelated work stays accepted.
- **Assignment.** One scoped job: one worker, one deliverable, one
  basis, and a short list of files that worker may change, for
  example `app/price.py`. The assignment ID, for example `rep-1`,
  must be identical in every step. Changing it partway through is
  the most common first-run mistake, and the gate will refuse the
  work with `repair_assignment_missing`.
- **Candidate.** A separate workspace where the worker edits files.
  Editing the accepted tree directly is not how work is admitted.
- **Protect gate.** The receiver-side check. It either ACCEPTS a
  candidate, with a signed receipt you can verify offline on
  another machine, or STOPs / refuses it, leaving accepted work
  untouched.
- **Watchdog.** Advisory only. It tracks whether different workers
  keep failing on the same deliverable and basis, and it can hold
  a project until the owner signs a reconciliation. It grants no
  authority by itself.

## From a person's interest to a project

Start from what the person actually wants, not from OpenLine terms.

1. Ask what they want to build, in one sentence. Example: "a small
   tool that totals an invoice."
2. Turn that into one deliverable with one file and one rule.
   Example: deliverable `invoice-feature`, file `app/price.py`,
   rule "total(2) must equal 22" (basis `invoice_v2`).
3. If their idea is bigger, split it. One deliverable, one rule,
   one assignment first. Do not invent a whole system, a payment
   flow, or a deployment in the first project.
4. If OpenLine cannot express their rule as a local file change
   with a checkable result, say so. Do not pretend a receipt proves
   an external effect, a payment, or a real-world outcome.

## Install (Linux, Python 3.11+, git required)

```bash
git clone https://github.com/terryncew/openline-living-projects.git
cd openline-living-projects
bash install.sh
```

`install.sh` creates `.venv`, installs only `cryptography`, and
checks the package manifest. If the manifest check fails, stop.
Do not trust that checkout. Re-clone, and do not edit files to
make the check pass.

macOS and Windows are untested in this release. Do not claim they
work until you have tested them yourself.

## Run the demo first (about 30 seconds)

```bash
python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo
bash experiments/OPENLINE-RELEASE-001/REPLAY.sh
```

The demo must end with ALL STEPS PASS, and replay must exit 0.
It shows, in order: a forbidden change STOPPED, an authorized
repair ACCEPTED with a verified receipt, a falsifier report
UNKNOWN with the candidate preserved, a second disruption with
revocation and replacement ACCEPTED, and the same-UID deployment
condition. If any step fails, read the step output. Do not skip
to your own project until the demo passes.

## Your first own project (exact commands)

```bash
OPENLINE=./experiments/OPENLINE-RELEASE-001/openline
$OPENLINE init --dir ~/ol-proj --project-id demo-1 --workers alice,bob,carol
$OPENLINE assign --dir ~/ol-proj --assignment rep-1 --deliverable invoice-feature --worker bob --basis invoice_v2 --allowed-paths app/price.py
$OPENLINE prepare --dir ~/ol-proj --assignment rep-1
printf "def total(qty):\n    return qty * 11\n" > ~/ol-proj/promotion/task-rep-1/candidate/app/price.py
$OPENLINE intercept --dir ~/ol-proj --assignment rep-1
$OPENLINE status --dir ~/ol-proj
$OPENLINE guard --dir ~/ol-proj
$OPENLINE doctor --dir ~/ol-proj
```

Expected: `intercept` ACCEPTED, `guard` SEALED, `doctor` HEALTHY.
Every command prints one JSON object. `intercept` exits 0 for
ACCEPTED, 3 for STOPPED, 4 for UNKNOWN, and 2 for usage or engine
errors.

If `intercept` is STOPPED, read the receipt and the reason. The
usual causes are: the assignment ID changed, the edited file is
outside the allowed paths, the price rule does not match the
basis (invoice_v2 needs `qty * 11`, not `qty * 10`), or the worker
is not the assigned worker. Fix the candidate and try again.
Do not edit the accepted tree, and do not delete the project
database to force an acceptance.

For the longer workflow, including graph claims, basis changes,
and memory, see `QUICKSTART.md` section 3. It uses `rep-1` and
basis `invoice_v2b` (`qty * 12`) consistently.

## Using OpenLine from an MCP host

The MCP server is stdio only. It does not listen on a network
port. Create a project with `init` first, then configure your
host with absolute paths:

```json
{
  "mcpServers": {
    "openline": {
      "command": "/absolute/path/to/openline-living-projects/experiments/OPENLINE-RELEASE-001/openline",
      "args": ["mcp", "--dir", "/absolute/path/to/ol-proj"]
    }
  }
}
```

Assignment creation and dependency changes are deliberately NOT
MCP tools. They require owner signatures, and those keys must not
live in a receiver-side server. Do those steps on the command
line, as the owner.

## What this does NOT prove

A signed receipt proves what the receiver recorded and signed.
It does not prove a downstream effect happened, a payment
cleared, or an external system changed. It cannot cover actions
that never crossed the recording boundary.

This release does not prove live coding-agent autonomy, external
receiver acceptance, production isolation, cross-platform
support, or real-world adoption. Local tests, even passing ones,
are not adoption. A conventional Git + SQLite + Ed25519 setup
reaches the same refusal/acceptance outcomes for simple cases;
OpenLine's narrow difference is signed receipts including
refusals, effect-state binding, and persistent cross-agent
stagnation tracking with signed reconciliation.

Same-UID warning: if the worker runs as the same operating-system
user as the receiver, the worker can write receiver files
directly on disk. OpenLine detects and refuses same-UID admission
when the worker UID is accurately passed, but real isolation
needs a separate user, a container, or another machine.

See `SECURITY.md` for the full limitation list, `RELEASE_NOTES.md`
for what changed in this release, and `PROVENANCE.md` for what
was verified and what was excluded.
