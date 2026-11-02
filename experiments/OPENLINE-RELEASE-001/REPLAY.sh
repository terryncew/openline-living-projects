#!/usr/bin/env bash
# OpenLine Release 001 replay -- python3 only.
# Runs the demo, the MCP protocol test, the conventional baseline,
# and the upstream Argon blocker regression suite. Exit 0 only if
# every step passes. Run directories land under runs/ (untracked,
# never committed: they contain per-run keyfiles).
set -euo pipefail
cd "$(dirname "$0")/../.."
PKG="experiments/OPENLINE-RELEASE-001"
DEFAULT_RUNS="$PKG/runs/replay-$(date +%s)"
if [ -n "${OPENLINE_REPLAY_RUNS_DIR:-}" ]; then
  RUNS="$OPENLINE_REPLAY_RUNS_DIR"
elif ! python3 -c "import sqlite3, tempfile; p='$PKG/runs/.lock_probe.db'; import os; os.makedirs('$PKG/runs', exist_ok=True); c=sqlite3.connect(p); c.execute('CREATE TABLE IF NOT EXISTS t(x INT)'); c.close(); os.remove(p)" 2>/dev/null; then
  RUNS="/tmp/openline-replay-$(date +%s)"
else
  RUNS="$DEFAULT_RUNS"
fi
mkdir -p "$RUNS"
python3 "$PKG/run_demo.py" --dir "$RUNS/demo"
python3 "$PKG/mcp_test.py" --dir "$RUNS/mcp"
python3 "$PKG/baseline.py" --dir "$RUNS/baseline"
(cd experiments/OPENLINE-PROTECT-001 && python3 -m unittest tests.test_argon_blockers)
echo "RELEASE REPLAY COMPLETE."
