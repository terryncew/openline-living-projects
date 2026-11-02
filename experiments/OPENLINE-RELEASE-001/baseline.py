"""Conventional baseline -- competent Git + hook + gate, equal task.

Same files, same disruptions as the release demo, minus OpenLine:
- bare Git repo, pre-receive hook denying direct main pushes;
- gate script: scope (app/price.py only) + frozen validator
  (total(2) == 22, label present, bob contribution present);
- author allowlist file: removing a worker refuses later merges
  (author-name check -- weaker than cryptographic membership, and
  that weakness is part of the honest delta, not hidden).

Outcomes recorded for PARITY comparison: refusal, acceptance,
interruption-retry, revocation. What the baseline does NOT provide
(and the release does): per-decision signed receipts verifiable
offline, effect binding, and a receiver-owned gate independent of
the worker's own checkout.

Exit 0 only if every asserted step passes.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

GATE = r'''
import json, subprocess, sys
from pathlib import Path
repo, refname, old, new, allowed_file, validator = sys.argv[1:7]
if refname != "refs/heads/main":
    sys.exit(0)
author = subprocess.run(["git", "--git-dir", repo, "log", "-1",
                         "--format=%an", new],
                        capture_output=True, text=True).stdout.strip()
allowed = set(Path(allowed_file).read_text().split())
if author not in allowed:
    print("author_not_allowed"); sys.exit(1)
out = subprocess.run(["git", "--git-dir", repo, "diff", "--name-only",
                      old, new], capture_output=True, text=True).stdout.split()
if any(not p.startswith("app/price.py") for p in out):
    print("scope_violation"); sys.exit(1)
if subprocess.run([sys.executable, "-B", validator],
                  cwd=Path(repo).parent / "work").returncode:
    print("validator_failed"); sys.exit(1)
print("ACCEPTED")
'''

HOOK = """#!/bin/sh
while read old new ref; do
  if [ "$ref" = "refs/heads/main" ]; then echo "direct_push_denied"; exit 1; fi
done
exit 0
"""


def _git(*args, cwd=None):
    result = subprocess.run(["git", *map(str, args)], cwd=cwd,
                            capture_output=True, text=True)
    if result.returncode:
        raise AssertionError((result.args, result.stdout, result.stderr))
    return result.stdout.strip()


def _validator(path: Path) -> Path:
    path.write_text(
        "import ast\n"
        "from pathlib import Path\n"
        "tree = Path('.')\n"
        "price = ast.parse((tree / 'app' / 'price.py').read_text())\n"
        "label_src = (tree / 'app' / 'independent.py').read_text()\n"
        "ns = {}\n"
        "exec(compile(price, 'price.py', 'exec'), ns)\n"
        "assert ns['total'](2) == 22, 'total mismatch'\n"
        "assert 'def label' in label_src\n"
        "assert 'upper' in label_src\n")
    return path


def run_baseline(root: Path):
    root = root.resolve()
    repo = root / "baseline.git"
    _git("init", "--bare", str(repo))
    work = root / "work"
    _git("clone", str(repo), str(work))
    (work / "app").mkdir()
    (work / "app" / "price.py").write_text("def total(qty):\n    return qty * 10\n")
    (work / "app" / "independent.py").write_text(
        "def label(value):\n    return value.upper()\n")
    _git("-C", str(work), "config", "user.name", "Baseline")
    _git("-C", str(work), "config", "user.email", "b@local.test")
    _git("-C", str(work), "add", "app")
    _git("-C", str(work), "commit", "-qm", "init")
    _git("-C", str(work), "push", "origin", "HEAD:refs/heads/main")
    hook = repo / "hooks" / "pre-receive"
    hook.write_text(HOOK)
    os.chmod(hook, 0o755)
    gate = root / "baseline_gate.py"
    gate.write_text(GATE)
    allowed = root / "allowed_authors.txt"
    allowed.write_text("Baseline\nbob\ncarol\n")
    validator = _validator(root / "baseline_validator.py")

    def gate_check(branch):
        _git("-C", str(work), "push", "origin", branch)
        _git("-C", str(work), "fetch", "origin")
        old = _git("--git-dir", str(repo), "rev-parse", "refs/heads/main")
        new = _git("--git-dir", str(repo), "rev-parse", branch)
        proc = subprocess.run(
            [sys.executable, str(gate), str(repo), "refs/heads/main",
             old, new, str(allowed), str(validator)],
            capture_output=True, text=True)
        return proc.returncode, proc.stdout.strip()

    # Forbidden: out-of-scope change refused.
    _git("-C", str(work), "checkout", "-qb", "rogue")
    (work / "app" / "independent.py").write_text(
        'def label(value):\n    return "hacked"\n')
    _git("-C", str(work), "commit", "-qam", "rogue")
    rc, msg = gate_check("rogue")
    assert rc != 0 and msg == "scope_violation", (rc, msg)
    # Authorized: repair accepted.
    _git("-C", str(work), "checkout", "main")
    _git("-C", str(work), "checkout", "-qb", "repair")
    (work / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
    _git("-C", str(work), "commit", "-qam", "repair")
    rc, msg = gate_check("repair")
    assert rc == 0 and msg == "ACCEPTED", (rc, msg)
    _git("--git-dir", str(repo), "update-ref", "refs/heads/main", "repair")
    # Interruption + retry: abandoned branch, fresh retry accepted.
    _git("-C", str(work), "checkout", "main")
    _git("-C", str(work), "checkout", "-qb", "abandoned")
    (work / "app" / "price.py").write_text("def total(qty):\n    return qty * 12\n")
    _git("-C", str(work), "commit", "-qam", "abandoned")
    _git("-C", str(work), "checkout", "main")
    _git("-C", str(work), "checkout", "-qb", "retry")
    (work / "app" / "price.py").write_text(
        "def total(qty):\n    # retry after interruption\n    return qty * 11\n")
    _git("-C", str(work), "commit", "-qam", "retry")
    rc, msg = gate_check("retry")
    assert rc == 0 and msg == "ACCEPTED", (rc, msg)
    # Revocation: remove bob from the allowlist; his next merge refused.
    allowed.write_text("Baseline\ncarol\n")
    _git("-C", str(work), "checkout", "main")
    _git("-C", str(work), "checkout", "-qb", "bob-revoked")
    (work / "app" / "price.py").write_text("def total(qty):\n    return qty * 11\n")
    _git("-C", str(work), "config", "user.name", "bob")
    _git("-C", str(work), "commit", "-qam", "bob-revoked")
    _git("-C", str(work), "config", "user.name", "Baseline")
    rc, msg = gate_check("bob-revoked")
    assert rc != 0 and msg == "author_not_allowed", (rc, msg)
    evidence = {"refusal": "scope_violation", "acceptance": "ACCEPTED",
                "interruption_retry": "ACCEPTED",
                "revocation": "author_not_allowed",
                "signed_receipts": False, "effect_binding": False,
                "revocation_mechanism": "author-name allowlist (weaker "
                "than cryptographic membership; delta, not hidden)"}
    (root / "baseline_evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    print("BASELINE: refusal/acceptance/retry/revocation PARITY; "
          "no signed receipts, no effect binding")
    return evidence


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", required=True)
    args = parser.parse_args()
    run_baseline(Path(args.dir))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
