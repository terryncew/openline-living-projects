from pathlib import Path
import sys

EXPERIMENTS = Path(__file__).resolve().parent.parent


def load_engines() -> Path:
    for rel in (
        "SELF-HEALING-ENGINE-001",
        "SELF-HEALING-PROJECTS-001",
        "OPENLINE-PROTECT-001",
        "OPENLINE-PROTECT-002",
        "OPENLINE-PROTECT-003",
        "OPENLINE-PROTECT-005",
        "LIVING-PROJECTS-001",
        "OPENLINE-COACH-001",
        "OPENLINE-ONE-001",
        "CODEX-B-ISOLATED-REPAIR-001",
        "OPENLINE-AGENT-WATCHDOG-001",
        "OPENLINE-GRAPH-WATCHDOG-001/openline_graph_watchdog",
        "OPENLINE-TOE-GRAPH-EXPLORATION-001",
    ):
        target = str(EXPERIMENTS / rel)
        if target not in sys.path:
            sys.path.insert(0, target)
    return EXPERIMENTS
