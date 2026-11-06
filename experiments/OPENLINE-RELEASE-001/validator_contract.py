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



def _fixture_function(src: str, name: str):
    """Read an intentionally tiny fixture language; NEVER execute candidate Python.

    The release example accepts exactly one unannotated, undecorated, one-argument
    function with a single return. This is a fixture-specific contract checker,
    not a Python sandbox or a general-purpose safe evaluator.
    """
    if not (len(src) <= 16384):
        raise AssertionError("fixture too large")
    module = ast.parse(src)
    if not (len(module.body) == 1):
        raise AssertionError("fixture must contain one function only")
    fn = module.body[0]
    if not (isinstance(fn, ast.FunctionDef) and fn.name == name):
        raise AssertionError("unexpected function")
    if not (not fn.decorator_list and fn.returns is None):
        raise AssertionError("decorators/annotations refused")
    args = fn.args
    if not (not (args.posonlyargs or args.kwonlyargs or args.defaults or
                args.kw_defaults or args.vararg or args.kwarg)):
        raise AssertionError("invalid fixture arguments")
    if not (len(args.args) == 1 and args.args[0].annotation is None):
        raise AssertionError("one plain argument required")
    if not (len(fn.body) == 1 and isinstance(fn.body[0], ast.Return)):
        raise AssertionError("single return required")
    return args.args[0].arg, fn.body[0].value


def _literal_total(src: str) -> int:
    param, value = _fixture_function(src, 'total')
    if not (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult)
            and isinstance(value.left, ast.Name) and value.left.id == param
            and isinstance(value.right, ast.Constant)
            and type(value.right.value) is int):
        raise AssertionError("total must be qty * literal integer")
    coeff = value.right.value
    if not (coeff in {10, 11, 12, 13}):
        raise AssertionError("unsupported demo contract multiplier")
    return 2 * coeff


def _is_upper(expr, param: str) -> bool:
    return (isinstance(expr, ast.Call) and not expr.args and not expr.keywords
            and isinstance(expr.func, ast.Attribute) and expr.func.attr == 'upper'
            and isinstance(expr.func.value, ast.Name) and expr.func.value.id == param)


def _literal_format(src: str) -> str:
    param, value = _fixture_function(src, 'label')
    if _is_upper(value, param):
        return 'OK'
    if (isinstance(value, ast.JoinedStr) and len(value.values) == 3
            and isinstance(value.values[0], ast.Constant) and value.values[0].value == '['
            and isinstance(value.values[1], ast.FormattedValue)
            and value.values[1].conversion == -1 and value.values[1].format_spec is None
            and _is_upper(value.values[1].value, param)
            and isinstance(value.values[2], ast.Constant) and value.values[2].value == ']'):
        return '[OK]'
    raise AssertionError('unsupported demo formatter expression')


def _read_fixture(tree: Path, file: str) -> str:
    """Read only a small regular file under the candidate tree (no symlinks)."""
    base = tree / 'app'
    path = base / file
    if not (not base.is_symlink() and not path.is_symlink()):
        raise AssertionError('fixture symlink refused')
    if not (path.is_file()):
        raise AssertionError('fixture missing')
    if not (path.stat().st_size <= 16384):
        raise AssertionError('fixture too large')
    return path.read_text(encoding='utf-8')


def main() -> int:
    db_path = sys.argv[1]
    tree = Path('.')
    actual_total = _literal_total(_read_fixture(tree, 'price.py'))
    actual_fmt = _literal_format(_read_fixture(tree, 'independent.py'))

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

    # If both deliverables are REOPEN (multi-deliverable change), the candidate being promoted
    # must satisfy its own new contract while the other deliverable is at either its settled or new contract.
    if standings.get("invoice-feature") == "REOPEN" and standings.get("independent-formatter") == "REOPEN":
        if not ((actual_total == expected_inv and actual_fmt in (settled_fmt, expected_fmt)) or (
            actual_fmt == expected_fmt and actual_total in (settled_inv, expected_inv)
        )):
            raise AssertionError(f"multi-deliverable mismatch: total={actual_total} (exp {expected_inv}), fmt={actual_fmt} (exp {expected_fmt})")
    else:
        if standings.get("invoice-feature") == "REOPEN":
            if not (actual_total == expected_inv):
                raise AssertionError(f"total mismatch: {actual_total} != {expected_inv}")
        else:
            if not (actual_total == settled_inv):
                raise AssertionError(f"settled total mismatch: {actual_total} != {settled_inv}")
        if standings.get("independent-formatter") == "REOPEN":
            if not (actual_fmt == expected_fmt):
                raise AssertionError(f"format mismatch: {actual_fmt} != {expected_fmt}")
        else:
            if not (actual_fmt == settled_fmt):
                raise AssertionError(f"settled format mismatch: {actual_fmt} != {settled_fmt}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
