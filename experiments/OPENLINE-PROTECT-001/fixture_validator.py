"""Fixture-only static AST validator. Never imports or executes candidate code.

Not a general software correctness oracle. Production must use a separately
sandboxed trusted acceptance runner with owner-specified tests.
"""
import ast
import argparse
from pathlib import Path


def only_function(file: str, name: str, parameter: str):
    source = Path('app') / file
    doc = ast.parse(source.read_text(encoding='utf8'))
    if len(doc.body) != 1 or not isinstance(doc.body[0], ast.FunctionDef):
        raise ValueError('unexpected_source_top_level')
    fun = doc.body[0]
    if fun.name != name or fun.decorator_list or fun.returns is not None or getattr(fun, 'type_params', []):
        raise ValueError('unexpected_function_signature')
    if len(fun.args.args) != 1 or fun.args.args[0].arg != parameter or fun.args.defaults or fun.args.kwonlyargs:
        raise ValueError('unexpected_arguments')
    if len(fun.body) != 1 or not isinstance(fun.body[0], ast.Return):
        raise ValueError('unexpected_function_body')
    return fun.body[0].value


def run(expected: int, needs_bob: bool):
    value = only_function('price.py', 'total', 'qty')
    if not (isinstance(value, ast.BinOp) and isinstance(value.op, ast.Mult) and
            isinstance(value.left, ast.Name) and value.left.id == 'qty' and
            isinstance(value.right, ast.Constant) and type(value.right.value) is int and
            value.right.value * 2 == expected):
        raise ValueError('price_does_not_match_frozen_fixture')
    if needs_bob:
        label = only_function('independent.py', 'label', 'value')
        if not (isinstance(label, ast.Call) and not label.args and not label.keywords and
                isinstance(label.func, ast.Attribute) and label.func.attr == 'upper' and
                isinstance(label.func.value, ast.Name) and label.func.value.id == 'value'):
            raise ValueError('independent_contribution_not_preserved')
    print('TRUSTED_STATIC_FIXTURE_PASS')


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--expected', required=True, type=int)
    p.add_argument('--needs-bob', action='store_true')
    opt = p.parse_args()
    run(opt.expected, opt.needs_bob)
