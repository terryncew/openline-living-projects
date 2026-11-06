#!/usr/bin/env bash
# OpenLine Release 001 replay -- python3 only.
# Runs the demo, the MCP protocol test, the conventional baseline,
# the Kill Switch conformance + audit proof, the upstream Argon
# blocker regression suite, the 5 hardening suites, the 3 GPT-6
# regression suites, and the Astra adversarial challenge suite.
# Exit 0 only if every step passes.
set -euo pipefail
cd "$(dirname "$0")/../.."
PKG="experiments/OPENLINE-RELEASE-001"
DEFAULT_RUNS="$PKG/runs/replay-$(date +%s)"
FS_TYPE="$(df -T . 2>/dev/null | awk 'NR==2 {print $2}' || true)"
if [ -n "${OPENLINE_REPLAY_RUNS_DIR:-}" ]; then
  RUNS="$OPENLINE_REPLAY_RUNS_DIR"
elif [ "$FS_TYPE" = "9p" ] || ! python3 -c "import sqlite3, tempfile; p='$PKG/runs/.lock_probe.db'; import os; os.makedirs('$PKG/runs', exist_ok=True); c=sqlite3.connect(p); c.execute('CREATE TABLE IF NOT EXISTS t(x INT)'); c.close(); os.remove(p)" 2>/dev/null; then
  RUNS="/tmp/openline-replay-$(date +%s)"
else
  RUNS="$DEFAULT_RUNS"
fi
mkdir -p "$RUNS"
python3 "$PKG/run_demo.py" --dir "$RUNS/demo"
python3 "$PKG/mcp_test.py" --dir "$RUNS/mcp"
python3 "$PKG/baseline.py" --dir "$RUNS/baseline"
python3 "$PKG/openline_cli.py" kill-switch --action conformance --output-dir "$RUNS/kill_switch"
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_owner_intent_hardening.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_validator_fixture_hardening.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_crash_consistency_hardening.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_argon_outsider_improvements.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_gpt6_malformed_grant_cap.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_gpt6_memory_preplant.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_post_release_002.py")
(cd "$PKG" && python3 -m unittest discover -s tests -p "test_astra_adversarial_challenge.py")
(cd experiments/OPENLINE-PROTECT-001 && python3 -m unittest tests.test_argon_blockers)
(cd experiments/OPENLINE-RECEIVER-ISOLATION-001 && python3 -m unittest discover -s tests -p "test_*.py")
python3 experiments/OPENLINE-RECEIVER-ISOLATION-001/deploy/backup_restore_rehearsal.py
echo "RELEASE REPLAY COMPLETE."
# NOTE (merge): run directories land under runs/ (untracked, never committed:
# they contain per-run keyfiles). Carried over from the public release.
