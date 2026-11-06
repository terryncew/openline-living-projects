# Start Here: OpenLine Ecosystem (8 Public Repositories)

Need the fastest path into OpenLine without reading eight repositories first? Start here.

## 1. Fastest No-Clone Entry Point (Live Public Web App)

- **OpenLine Idea Layer (Live Browser App)**: [https://terryncew.github.io/openline-idea-layer/](https://terryncew.github.io/openline-idea-layer/)
- **OpenLine Idea Layer Repository**: [https://github.com/terryncew/openline-idea-layer](https://github.com/terryncew/openline-idea-layer)

You can browse 12 curated local-first small-business starting problems (432 deterministic combinations), inspect explicit safety boundaries and cheapest real-world demand tests, export a build-ready agent assignment brief (`node export_brief.mjs --list`), or run the 20-test verification suite locally with zero external dependencies (`node --test tests/*.test.mjs trials/compare_briefs_vs_manual_template.test.mjs trials/trial_*/test.mjs`).

## 2. Which OpenLine Repo Do You Need?

| Goal | Repository | Quick Verification Command |
| :--- | :--- | :--- |
| Pick a concrete business hypothesis, export a deterministic agent build brief (`export_brief.mjs`), and run 6 sector prototype acceptance suites (`IL-3-0`, `IL-8-0`, `IL-11-0`, `IL-1-0`, `IL-4-0`, `IL-6-0`) | [openline-idea-layer](https://github.com/terryncew/openline-idea-layer) | `node --test tests/*.test.mjs trials/compare_briefs_vs_manual_template.test.mjs trials/trial_*/test.mjs` (`20/20 PASS`) |
| Keep multi-agent coding projects coherent across handoffs, crashes, and replacement agents with receiver-owned Kill Switch and Agent Hunt (`AGENT-HUNT-001`) | [openline-living-projects](https://github.com/terryncew/openline-living-projects) | `python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo && bash experiments/OPENLINE-RELEASE-001/REPLAY.sh` (`EXIT 0`) |
| Preserve public-record source bytes (U.S. House Clerk Roll Call 283 XML), check completeness, and reopen dependent reviews when evidence changes | [mandate-ledger](https://github.com/terryncew/mandate-ledger) | `./REPLAY_EXPERIMENTAL.sh` (`42/42 PASS`) |
| Gate AI agent actions through default-deny SQLite execution controls and receiver-signed Ed25519 receipts (`cryptography >= 38`) | [openline-connect](https://github.com/terryncew/openline-connect) | `python3 scripts/run_tests.py && PYTHONPATH="$PWD/src" python3 -m openline_connect.cli demo` (`15/15 PASS`) |
| Explore California SB 868 plug-in solar scenarios locally with AB 205 fixed charges, daytime load caps, and adversarial safety tests in Node.js | [openline-energy](https://github.com/terryncew/openline-energy) | `node tests/test_engine_and_attacks.js && node tests/test_gpt_release_regressions.js` (`26/26 PASS`) |
| Run Python residential EV charging schedule optimization, tariff window planning, and hash-chained receipt verification in simulation | [openline-energy-autopilot](https://github.com/terryncew/openline-energy-autopilot) | `python3 demo.py && PYTHONPATH=src python3 -m unittest discover -s tests -v` (`62/62 PASS`) |
| Gate proposed energy controller source repairs through an isolated Linux user/mount/PID/net namespace sandbox and receiver attestor | [openline-living-energy](https://github.com/terryncew/openline-living-energy) | `./run_demo.sh && ./REPLAY_EXPERIMENTAL.sh` (`64/64` energy + `67/67` living-energy PASS) |
| Diagnose, rank, and repair corrupted neural network weights (`.safetensors` / NumPy CPU or PyTorch) with falsifier-gated rollbacks | [openline-weight-space-repair](https://github.com/terryncew/openline-weight-space-repair) | `bash REPLAY.sh` (`14/14` unit + `4/4` live CPU scripts PASS, no PyTorch required) |

## 3. Copy-Paste Agent Prompt (Works in Any Coding Agent)

Paste this prompt into Claude Code, Cursor, Codex, Gemini, or any local agent:

```text
Clone https://github.com/terryncew/openline-idea-layer and https://github.com/terryncew/openline-living-projects.
1. In openline-idea-layer, run `node export_brief.mjs --list`, export the brief for sector 7 (`node export_brief.mjs --sector 7 --audience "small businesses" --format toolkit --budget 0`), and run `node --test trials/trial_2_food_allergen/test.mjs`.
2. In openline-living-projects, run `python3 experiments/OPENLINE-RELEASE-001/run_demo.py --dir /tmp/ol-demo` and `python3 -m unittest discover -s experiments/AGENT-HUNT-001/tests -v`.
3. Show me how Idea Layer's exported brief (`IL-8-0`) connects to Living Projects' receiver-owned authorization, Agent Hunt (`AGENT-HUNT-001`), crash recovery, and replacement-agent succession.
```

## 4. End-to-End Cross-Product Verification (`integration/`)

In the integrated workspace, run the full cross-product workflow (`Idea Layer -> Prototype -> Agent Hunt -> Receiver Kill Switch -> Signed Acceptance -> Crash Recovery -> Replacement-Agent Succession` + `Energy / Mandate Ledger / Weight-Space Repair` Living Network loop):

```bash
python3 -m unittest discover -s integration/tests -p "test_*.py" -v
```

## 5. Honest Scope & Claim Guardrails

- **Proven in software & Linux user/mount/PID/net namespaces**: All 8 public repositories and the cross-product integration suite execute deterministically on CPU with standard open-source tooling.
- **Equal-information audit parity (`PARITY`)**: In `openline-living-projects`, `AGENT-HUNT-001` catches `4/4` constructed authority/replay/revocation/provenance attacks, and a competent conventional SQLite audit over the same normalized records also catches `4/4` (`PARITY`).
- **Held claims (`NOT TESTED` in container sandboxes)**: Do not claim hardware KVM guest-root containment without running `isolation/astra_vm/deploy/disposable_vm_package/run_disposable_vm_qualification.sh` on a bare-metal Linux host with `/dev/kvm`, and do not claim live physical EV charger actuation without physical hardware-in-the-loop qualification.
