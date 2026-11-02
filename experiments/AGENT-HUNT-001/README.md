# Agent Hunt — an OpenLine research MVP

**Try the existing incident-investigation lab.** Free, offline, Python 3.11+, no accounts or paid APIs. This is a **fictional retrospective simulation**, not live rogue-agent protection or an integrated authorization service.

## Try it in 60 seconds

1. Download [the prebuilt incident console](index.html) and open the file in your browser. It needs no server or internet connection. Explore the scope alerts and what affected work should be reopened or retained.
2. To check and change the investigation, from this directory run:

```sh
python3 hunt.py
python3 -m unittest discover -s tests -v
```

Open the generated `hunt-report.html`. The source events are in `events.jsonl`; the illustrative authorization policy, revocation time, dependency evidence, and recorded work are in `policy.json`. Change those inputs and rerun. A machine-readable report is written to `hunt-report.json`; the initial sample is also saved as [sample-report.json](sample-report.json).

**What the sample contains:** eight fictional tool-event log entries; five scope-alert events involving one agent; a repeated nonce; an out-of-scope file change and network-send request; stale evidence; a post-revocation request. Declared downstream dependencies mark one accepted deliverable `REOPEN`, one `RETAIN`, and one `UNDETERMINED`.

The independent test invocation above was rerun before publication: **7 tests passed, 0 failed**. No security certification or operational deployment is claimed.

## Hand this to your AI

> Inspect `experiments/AGENT-HUNT-001` in this repository. Read the README, Python source, sample events, policy, and tests. Run the tests and the offline scenario. Explain exactly what the incident console proves, what it cannot observe or prove, and how you'd extend it into a *receiver-owned*, permission-scoped agent investigation workflow. Do not claim that fictional logs prove real execution or that uninstrumented actions were stopped. Tell me what useful application you could build on top.

## Boundaries before claims

- Input events are **unsigned and fictional**. A flagged mismatch is **not proof of malicious intent, action execution, or complete detection**. Event `effect_claim` is unverified even if it says “applied”.
- This lab neither intercepts tools nor controls a live agent. Its scope check is retrospective **analysis, not enforcement**. Unobserved actions are invisible. Policy and dependency data are assumed to be accurate for the demo; they are not authenticated.
- `REOPEN` / `RETAIN` / `UNDETERMINED` are based on a *declared* fictional dependency graph, not verified live project standing. The honest choice for incomplete dependencies is `UNDETERMINED`.
- Actual control belongs at a trusted receiving system. Reuse the separately published [OpenLine Living Projects](https://github.com/terryncew/openline-living-projects) recovery/Protect implementation and [OpenLine Receipt Gate](https://github.com/terryncew/openline-receipt-gate) as research sources; do not treat this lab as a competing authority engine.
- A real-agent version still needs independently verified identities, receiver-signed decisions, trustworthy effect observation, worker isolation, and fair comparisons with a competent baseline.

## Files

`index.html`: openable static snapshot of the fictional investigation. `hunt.py`: stdlib-only local generator and retrospective scope analysis. `events.jsonl`: fictional calls. `policy.json`: illustrative scope, revocation, and dependencies. `tests/test_hunt.py`: regression tests. `sample-report.json`: generator output.

This experiment is published as a separate subtree of OpenLine Living Projects. It does **not** change or expand the guarantees of the existing `v0.1.1` release tag. Source originally recovered from the founder's `openline_agent_hunt_lab.zip`, with the core Python, inputs, and tests unchanged. Repository license: Apache-2.0, except where otherwise identified.
