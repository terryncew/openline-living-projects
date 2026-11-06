"""Independent adversarial checks for the *demo-only* AST fixture evaluator.

Not evidence that arbitrary Python jobs are sandboxed; only demonstrates that
this one validator does not execute source code from the candidate worktree.
"""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

VALIDATOR = Path(__file__).resolve().parents[1] / 'validator_contract.py'
spec = importlib.util.spec_from_file_location('openline_validator_contract_under_test', VALIDATOR)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


class FixtureValidationTests(unittest.TestCase):
    def test_legitimate_multistep_contracts(self):
        for coeff in (10, 11, 12, 13):
            self.assertEqual(validator._literal_total(f'def total(qty):\n    return qty * {coeff}\n'), 2 * coeff)
        self.assertEqual(validator._literal_format('def label(value):\n    return value.upper()\n'), 'OK')
        self.assertEqual(validator._literal_format('def label(value):\n    return f"[{value.upper()}]"\n'), '[OK]')

    def test_untrusted_side_effect_cannot_execute(self):
        with tempfile.TemporaryDirectory(prefix='openline-validator-negative-') as d:
            target = Path(d) / 'malicious_side_effect'
            malicious = ('from pathlib import Path\n'
                         f'Path({str(target)!r}).write_text("ATTACK")\n'
                         'def total(qty):\n    return qty * 11\n')
            with self.assertRaises(AssertionError):
                validator._literal_total(malicious)
            self.assertFalse(target.exists(), 'untrusted source executed!')

    def test_dynamic_eval_and_decorators_refused(self):
        malicious = ('def total(qty):\n    return __import__("os").system("echo owned") or qty * 11\n')
        with self.assertRaises(AssertionError):
            validator._literal_total(malicious)
        with self.assertRaises(AssertionError):
            validator._literal_format('def label(value):\n    return eval(value)\n')
        with self.assertRaises(AssertionError):
            validator._literal_total('@exfiltrate\ndef total(qty):\n    return qty * 11\n')
        with self.assertRaises(AssertionError):
            validator._literal_total('def total(qty):\n    return qty * 11\n\ntotal(2)\n')

    def test_symlink_and_oversized_fixture_refused(self):
        with tempfile.TemporaryDirectory(prefix='openline-validator-path-') as d:
            root = Path(d)
            app = root / 'app'
            app.mkdir()
            victim = root / 'private-source.py'
            victim.write_text('def total(qty):\n    return qty * 11\n')
            (app / 'price.py').symlink_to(victim)
            with self.assertRaises(AssertionError):
                validator._read_fixture(root, 'price.py')
            (app / 'price.py').unlink()
            (app / 'price.py').write_text('X' * 16385)
            with self.assertRaises(AssertionError):
                validator._read_fixture(root, 'price.py')


if __name__ == '__main__':
    unittest.main()
