"""Load a separately prepared, pinned RC5 integration tree; never import candidate code."""
from pathlib import Path
import sys


def load(root):
    root = Path(root).resolve(strict=True)
    for rel in ('SELF-HEALING-ENGINE-001', 'SELF-HEALING-PROJECTS-001',
                'OPENLINE-PROTECT-001', 'OPENLINE-PROTECT-002', 'LIVING-PROJECTS-001',
                'OPENLINE-RELEASE-001', 'OPENLINE-RECEIVER-ISOLATION-001',
                'OPENLINE-RECEIVER-ISOLATION-001/deploy'):
        p = root / 'experiments' / rel
        if not p.is_dir():
            raise RuntimeError('missing installed RC5 module: ' + rel)
        sys.path.insert(0, str(p))
    return root
