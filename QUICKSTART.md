# OpenLine Living Projects — Developer Quickstart (0.1.0)

**Repository:** https://github.com/terryncew/openline-living-projects  
**Classification:** Public developer preview — Local-First, Self-Hostable, Zero Paid APIs

**Candidate identity:** frozen `v0.1.0-rc3-corrected` (`136203d0f557213065ade7a638f1169940063e36`) plus the Argon outsider patch, the GPT-6 follow-on security patch, and the final-release fixes listed in `RELEASE_NOTES.md` (F-01 through F-09), plus the first-experience fixes (`GETTING_STARTED.md`, `install.sh`, fixed README example, MCP host config). See `PROVENANCE.md` for exact patch hashes and `RELEASE_NOTES.md` for verified test counts.

**Verification (final gate, Python 3.12.3, Linux):** bundled suites 206 ran, 203 pass, 3 clean offline skips, 0 fail. Demo ALL STEPS PASS, both replays exit 0, both E2E scripts exit 0, README and QUICKSTART section 3 verbatim ACCEPTED / SEALED / HEALTHY.

The watchdog is advisory; it grants no receiver authority. Same-UID workers can write receiver paths unless isolated. Effect receipts bind database state, not downstream real-world effects. No live coding-agent autonomy, outsider adoption, macOS/Windows, or production isolation has been demonstrated. Conventional refusal/acceptance outcomes showed parity. Python 3.13 and 3.11 were not tested in the verifier's environment; see `RELEASE_NOTES.md`.

## 1. Prerequisites
- Python 3.11+ (`cryptography` package installed)
- Git 2.30+

## 2. Cold-Start Installation & Full Replay
```bash
git clone https://github.com/terryncew/openline-living-projects.git
cd openline-living-projects
bash install.sh
# install.sh creates .venv, installs only cryptography, and checks the manifest.
# The manual equivalent is: python3 -m venv .venv; .venv/bin/python -m pip install -r requirements.txt; sha256sum -c PUBLIC-SHA256SUMS.txt

# Run the Mandatory 12-Step Living Projects End-to-End Test & Conventional Comparison:
./experiments/OPENLINE-RELEASE-001/openline replay

# Run the Release 001 + Protect 005 regression & security suites:
bash experiments/OPENLINE-RELEASE-001/REPLAY.sh
bash experiments/OPENLINE-PROTECT-005/REPLAY.sh
```

## 3. Core CLI Workflow (`openline`)
```bash
OPENLINE=./experiments/OPENLINE-RELEASE-001/openline

# 1. Initialize a Living Project with 3 participants (alice, bob, carol)
$OPENLINE init --dir /tmp/my-project --project-id demo-1 --workers alice,bob,carol

# 2. Inspect project status, dependency graph, and Claim Graph
$OPENLINE status --dir /tmp/my-project
$OPENLINE graph --dir /tmp/my-project --changed format_v1

# 3. Record a cryptographically bound graph claim vs. an untrusted advisory claim
$OPENLINE graph --dir /tmp/my-project --add-claim c1 --subject invoice-feature --predicate verified_by --object alice --signer alice --sign-local
$OPENLINE graph --dir /tmp/my-project --add-claim c2 --subject invoice-feature --predicate note --object external_hint

# 4. Change multiple dependencies without deadlock
$OPENLINE change --dir /tmp/my-project --change invoice_v2=invoice_v2b --change format_v1=format_v2

# 5. Assign a scoped repair, prepare a worktree with a CANDIDATE memory hypothesis, and gate via Protect
$OPENLINE assign --dir /tmp/my-project --assignment rep-1 --deliverable invoice-feature --worker bob --basis invoice_v2b --allowed-paths app/price.py
$OPENLINE prepare --dir /tmp/my-project --assignment rep-1 --propose-memory mem-1 --diagnosis "invoice_v2b expects 24" --lesson "Set unit price to 12 in app/price.py"
printf "def total(qty):\n    return qty * 12\n" > /tmp/my-project/promotion/task-rep-1/candidate/app/price.py
$OPENLINE intercept --dir /tmp/my-project --assignment rep-1

# 6. Inspect inherited verified experience, chronological history, cryptographic seal, and diagnostics
$OPENLINE memory --dir /tmp/my-project --deliverable invoice-feature
$OPENLINE history --dir /tmp/my-project
$OPENLINE guard --dir /tmp/my-project
$OPENLINE doctor --dir /tmp/my-project

# 7. Start the stdio JSON-RPC 2.0 MCP server
$OPENLINE mcp --dir /tmp/my-project
```
