"""Private local operator CLI; no services, API keys or network requirements."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from protect import Protect, ProtectError, verify_receipt


def _add_verify_args(parser):
    parser.add_argument('--receipt', type=Path, required=True)
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument('--pinned-receiver-public-key', dest='pinned_key',
                           help='Hex Ed25519 public key from trusted receiver channel')
    key_group.add_argument('--receiver-public-hex', dest='pinned_key',
                           help='Alias for --pinned-receiver-public-key')
    parser.add_argument('--accepted-git', type=Path, default=None,
                        help='Optional bare Git repo to cross-check refs/heads/accepted')
    parser.add_argument('--project-db', type=Path, default=None,
                        help='Optional ProjectLedger SQLite DB to cross-check dependency continuity')


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog='openline-protect', description='Local OpenLine Protect gate demo, reconciliation, and offline evidence verifier (experimental)')
    sub = p.add_subparsers(dest='cmd', required=True)
    run = sub.add_parser('demo', help='Run real local Git STOP/ACCEPT demonstration (scripted attempts)')
    run.add_argument('--output-dir', type=Path, help='Preserve private project and receipt evidence')

    check = sub.add_parser('verify', help='Verify a receiver-signed incident against an independently pinned key')
    _add_verify_args(check)

    check_alias = sub.add_parser('verify-receipt', help='Verify a receiver-signed incident against an independently pinned key')
    _add_verify_args(check_alias)

    rec = sub.add_parser('reconcile', help='Idempotently reconcile an interrupted post-CAS promotion from SafePromotion journal')
    rec.add_argument('--project-dir', type=Path, required=True,
                     help='Directory containing project.sqlite, accepted.git, effects.sqlite, promotion/, and incidents/')
    rec.add_argument('--assignment', required=True, help='Assignment ID to reconcile')
    rec.add_argument('--receiver-key-file', type=Path, required=True,
                     help='0600 receiver signing seed file; never pass private seeds in argv')
    rec.add_argument('--pinned-receiver-public-key', required=True,
                     help='Trusted Ed25519 public key hex; refuse signing if key mismatches')
    rec.add_argument('--worker-uid', type=int, default=None,
                     help='Worker OS UID for the receiver-boundary check; when given, reconcile refuses admission if OS separation is absent')

    args = p.parse_args(argv)
    try:
        if args.cmd == 'demo':
            from demo import execute
            import tempfile
            if args.output_dir:
                if args.output_dir.exists() and any(args.output_dir.iterdir()):
                    raise ProtectError('output_directory_not_empty')
                result = execute(args.output_dir)
            else:
                with tempfile.TemporaryDirectory(prefix='openline-protect-') as folder:
                    result = execute(Path(folder))
        elif args.cmd in ('verify', 'verify-receipt'):
            if args.receipt.is_symlink() or not args.receipt.is_file() or args.receipt.stat().st_size > 128000:
                raise ProtectError('receipt_file_invalid')
            result = verify_receipt(
                json.loads(args.receipt.read_text(encoding='utf8')),
                args.pinned_key,
                accepted_git=args.accepted_git,
                project_db=args.project_db,
            )
        else:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            here = Path(__file__).resolve().parent
            experiments = here.parent
            for extra in (experiments / 'SELF-HEALING-ENGINE-001', experiments / 'SELF-HEALING-PROJECTS-001'):
                if str(extra) not in sys.path:
                    sys.path.insert(0, str(extra))
            if not (experiments / 'SELF-HEALING-PROJECTS-001').is_dir() \
                    and (here / 'promotion.py').is_file() \
                    and (here / 'project.py').is_file():
                # Flat release layout: promotion.py/project.py sit next
                # to cli.py. Map foundation.promotion onto the flat
                # module so the same import line keeps working.
                if str(here) not in sys.path:
                    sys.path.insert(0, str(here))
                import types
                import promotion as _flat_promotion
                if 'foundation' not in sys.modules:
                    pkg = types.ModuleType('foundation')
                    pkg.__path__ = []
                    sys.modules['foundation'] = pkg
                sys.modules['foundation.promotion'] = _flat_promotion
            from foundation.promotion import SafePromotion
            from project import ProjectLedger
            root = args.project_dir
            promo = SafePromotion(root / 'accepted.git', root / 'effects.sqlite', root / 'promotion', require_final_gate=True)
            project = ProjectLedger(root / 'project.sqlite', promotion=promo)
            import os
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            key_path = args.receiver_key_file
            if key_path.is_symlink() or not key_path.is_file() or key_path.stat().st_mode & 0o077:
                raise ProtectError('receiver_key_file_not_private')
            seed = bytes.fromhex(key_path.read_text(encoding='ascii').strip())
            if len(seed) != 32:
                raise ProtectError('receiver_key_invalid_length')
            signer = Ed25519PrivateKey.from_private_bytes(seed)
            pub = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
            if pub != args.pinned_receiver_public_key:
                raise ProtectError('receiver_key_not_pinned')
            gate = Protect(project, signer, root / 'incidents', acceptance_cmd=(sys.executable, '-B'),
                           worker_uid=args.worker_uid)
            out = gate.reconcile(args.assignment)
            result = {
                'verdict': out['verdict'],
                'receipt_path': out['path'],
                'incident_id': out['receipt']['payload']['incident_id'],
                'receiver_pub_ed25519_hex': gate.receiver_public_hex,
                'accepted_ref_after': out['receipt']['payload']['accepted_ref_after'],
            }
    except (ProtectError, OSError, ValueError, json.JSONDecodeError) as e:
        print(json.dumps({'status': 'REFUSED', 'reason': str(e)}), file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
