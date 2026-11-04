# OpenLine — START HERE

**OpenLine — Projects That Remember What They've Earned.**
Experimental open-source software. Local-first, no accounts, no paid APIs,
no production service. Start here, then follow each project's own README.

## The seven projects

| Project | What it is, in one line | Try it |
|---|---|---|
| [OpenLine Energy](https://github.com/terryncew/openline-energy) | California plug-in solar explorer you open in a browser. A planning tool, not a savings quote. | Open `index.html`, enter one monthly usage number. |
| [Energy Autopilot](https://github.com/terryncew/openline-energy-autopilot) | Simulated EV charger that picks cheaper charging windows and holds on stale prices. No charger connected. | Run the Python demo (see its README). |
| [Living Energy](https://github.com/terryncew/openline-living-energy) | Simulated charging mission that stops on bad evidence, tests a proposed repair, survives a restart, and resumes. | Run `run_demo.sh`, then the test suite (see below). |
| [Mandate Ledger](https://github.com/terryncew/mandate-ledger) | Keeps the original file behind a U.S. House vote so a reader can check what was recorded and what changed. No politician scores, no motive judgments. | Run the CLI roll-call replay and member lookup. |
| [Weight-Space Repair](https://github.com/terryncew/openline-weight-space-repair) | Local workbench that actually changes small neural-model weights, repairs deliberately damaged digit recognition, and checks against ordinary fixes (which tie). | Run `bash REPLAY.sh`. |
| [OpenLine Connect](https://github.com/terryncew/openline-connect) | Local receiver gate: a business controls which agent requests are allowed and signs decisions another machine can audit. Fictional SQLite effects only. | Run `openline-connect demo`, then the tests. |
| [OpenLine Living Projects](https://github.com/terryncew/openline-living-projects) (this repo) | Local developer preview: a receiver accepts or refuses a worker's change, signs the decision, and continues from the last accepted checkpoint after a worker is replaced. | `bash install.sh`, then `./experiments/OPENLINE-RELEASE-001/openline replay`. |

## Verified versions (November 4, 2026)

- openline-energy: main `a548539b`, MIT, v0.2.1.
- openline-energy-autopilot: main `91014170`, MIT.
- openline-living-energy: tag v0.4.3 (code commit `347c4a7b`; main HEAD may carry later docs-only amendments — the tag is the release).
- mandate-ledger: tag v0.3.3, main `2984b7a`, MIT.
- openline-weight-space-repair: tag v0.2.0, main `d4805bc`, Apache-2.0.
- openline-connect: tag v0.1.0rc2, main `507b5348`, Apache-2.0.
- openline-living-projects: tag v0.1.1 (commit `730bf184`); this file lives on main after that tag.

If a HEAD above has moved, the tag is the release to check out. A HEAD drift
without a new tag is not a new release.

## How to verify (public material only)

```bash
git clone https://github.com/terryncew/openline-living-energy.git
cd openline-living-energy
sha256sum -c SHA256SUMS.txt
bash run_demo.sh
```

Each repo documents its own install and test commands in its README. General
needs: Linux, Python 3.11+, git, Node 18+ (Energy only). Python packages are
installed per repo from that repo's own requirements (Living Projects needs
`cryptography`; Weight-Space Repair needs CPU torch for its full suite;
Connect needs its `src/` on `PYTHONPATH` for subprocess tests — use an
absolute path, not a relative one).

**Living Energy interpreter note:** its namespace sandbox masks `/home`,
`/root`, `/mnt`, and `/working_dir`. Run its suite from an interpreter
outside those paths (for example the system `python3`), or the sandbox
tests fail by design. The CI host disallows user namespaces, so sandbox
tests are NOT TESTED in CI; the full 67-test suite was verified locally
with a system interpreter. The sandbox no longer needs `iproute2`.

## What is NOT here (do not mistake these for shipped features)

- No Mandate Ledger dashboard site. The repo contains a fictional browser
  example file; there is no deployed dashboard URL, and the newer dashboard
  candidate is unpublished.
- No integrated Living Network module, no Weight-Space emergence v0.3.0,
  no Connect expansion. Those are separate, unpublished proposals.
- No physical charger control, no measured household savings (the $2.67
  autopilot figure is modeled on synthetic tariffs), no live government
  ingestion, no live frontier-model repair, no production authorization,
  no adoption claim. Conventional alternatives tie or beat OpenLine on the
  constructed comparisons, and that negative result is part of the record.
- Test counts are not adoption, and a signed receipt proves what the
  receiver recorded and signed, not what happened afterward.

## Dedication

The founder dedicated the three newest projects (Living Energy, Mandate
Ledger, Weight-Space Repair) to Nolan Wells, Ms. Rachel, and Stacey Abrams.
Their names are in those projects' `DEDICATION.md` files. No involvement,
sponsorship, or endorsement by them is implied.
