#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
for suite in SELF-HEALING-PROJECTS-001 OPENLINE-PROTECT-001 OPENLINE-PROTECT-002 OPENLINE-PROTECT-003 OPENLINE-PROTECT-005; do
  (cd "experiments/$suite" && python3 -Werror -m unittest discover -s tests -v)
  (cd "experiments/$suite" && python3 -O -Werror -m unittest discover -s tests -v)
done
python3 experiments/OPENLINE-PROTECT-005/compare_concurrent.py
python3 experiments/OPENLINE-PROTECT-003/repair_loop.py
printf '\nPRIVATE GATES COMPLETE: no live model, no official host, no release.\n'
