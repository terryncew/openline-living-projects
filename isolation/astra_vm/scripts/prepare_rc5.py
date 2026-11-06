#!/usr/bin/env python3
"""Extract pinned RC5 into a NEW target and apply the narrow integration patch."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import zipfile

EXPECTED = 'b47a80169b745b1fe3af3647f79ce181ba75903866f8ab7baf4a0b0c15cd0980'
p = argparse.ArgumentParser()
p.add_argument('--archive', required=True)
p.add_argument('--destination', required=True)
a = p.parse_args()
archive = Path(a.archive)
if hashlib.sha256(archive.read_bytes()).hexdigest() != EXPECTED:
    raise SystemExit('RC5 archive pin mismatch')
dst = Path(a.destination)
if dst.exists():
    raise SystemExit('destination must not exist; baseline is never overwritten')
with zipfile.ZipFile(archive) as z:
    for item in z.infolist():
        n = Path(item.filename)
        if n.is_absolute() or '..' in n.parts or ((item.external_attr >> 16) & 0o170000) == 0o120000:
            raise SystemExit('unsafe archive member')
    z.extractall(dst)
root = dst / 'openline-living-projects-security-rc'
subprocess.run(['patch', '-p1', '--batch', '--forward', '-i', str(Path(__file__).resolve().parents[1]/'deploy/rc5-vm-adapter.patch')], cwd=root, check=True)
print(root.resolve())
