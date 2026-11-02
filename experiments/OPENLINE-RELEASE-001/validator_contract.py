"""Demo acceptance validator for the release package (pinned, trusted).

Reads active contracts from the project ledger (operator-owned, outside any
worktree) and enforces the matching expectations for both deliverables:
  invoice-feature (app/price.py):
    invoice_v1  -> total(2) == 20  (qty * 10)
    invoice_v2  -> total(2) == 22  (qty * 11)
    invoice_v2b -> total(2) == 24  (qty * 12)
    invoice_v3  -> total(2) == 26  (qty * 13)
  independent-formatter (app/independent.py):
    format_v1   -> label("ok") == "OK"
    format_v2   -> label("ok") == "[OK]"
"""
import ast
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path

EXPECTED_INVOICE = {
    "invoice_v1": 20,
    "invoice_v2": 22,
    "invoice_v2b": 24,
    "invoice_v3": 26,
}

EXPECTED_FORMAT = {
    "format_v1": "OK",
    "format_v2": "[OK]",
}


def main() -> int:
    db_path = sys.argv[1]
    tree = Path(".")
    price = ast.parse((tree / "app" / "price.py").read_text())
    label_src = (tree / "app" / "independent.py").read_text()
    label_ast = ast.parse(label_src)
    ns_price = {}
    ns_label = {}
    exec(compile(price, "price.py", "exec"), ns_price)
    exec(compile(label_ast, "independent.py", "exec"), ns_label)
    assert "def label" in label_src and "upper" in label_src, "bob contribution missing"

    with closing(sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)) as db:
        global_contract = db.execute("SELECT contract FROM projects").fetchone()[0]
        deps = dict(db.execute("SELECT deliverable_id, depends_on FROM dependencies").fetchall())
        standings = dict(db.execute("SELECT id, standing FROM deliverables").fetchall())
        events = [json.loads(r[0]) for r in db.execute(
            "SELECT payload FROM events WHERE kind='CONTRACT_CHANGED' ORDER BY seq DESC")]

    inv_contract = global_contract if global_contract in EXPECTED_INVOICE else None
    if inv_contract is None:
        for ev in events:
            if ev.get("contract") in EXPECTED_INVOICE and "invoice-feature" in ev.get("affected", []):
                inv_contract = ev["contract"]
                break
    if inv_contract is None:
        inv_contract = deps.get("invoice-feature", "invoice_v2")
    expected_inv = EXPECTED_INVOICE.get(inv_contract, 22)
    settled_inv = EXPECTED_INVOICE.get(deps.get("invoice-feature", "invoice_v1"), 20)
    actual_total = ns_price["total"](2)

    fmt_contract = global_contract if global_contract in EXPECTED_FORMAT else None
    if fmt_contract is None:
        for ev in events:
            if ev.get("contract") in EXPECTED_FORMAT and "independent-formatter" in ev.get("affected", []):
                fmt_contract = ev["contract"]
                break
    if fmt_contract is None:
        fmt_contract = deps.get("independent-formatter", "format_v1")
    expected_fmt = EXPECTED_FORMAT.get(fmt_contract, "OK")
    settled_fmt = EXPECTED_FORMAT.get(deps.get("independent-formatter", "format_v1"), "OK")
    actual_fmt = ns_label["label"]("ok")

    # If both deliverables are REOPEN (multi-deliverable change), the candidate being promoted
    # must satisfy its own new contract while the other deliverable is at either its settled or new contract.
    if standings.get("invoice-feature") == "REOPEN" and standings.get("independent-formatter") == "REOPEN":
        assert (actual_total == expected_inv and actual_fmt in (settled_fmt, expected_fmt)) or (
            actual_fmt == expected_fmt and actual_total in (settled_inv, expected_inv)
        ), f"multi-deliverable mismatch: total={actual_total} (exp {expected_inv}), fmt={actual_fmt} (exp {expected_fmt})"
    else:
        if standings.get("invoice-feature") == "REOPEN":
            assert actual_total == expected_inv, f"total mismatch: {actual_total} != {expected_inv}"
        else:
            assert actual_total == settled_inv, f"settled total mismatch: {actual_total} != {settled_inv}"
        if standings.get("independent-formatter") == "REOPEN":
            assert actual_fmt == expected_fmt, f"format mismatch: {actual_fmt} != {expected_fmt}"
        else:
            assert actual_fmt == settled_fmt, f"settled format mismatch: {actual_fmt} != {settled_fmt}"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
