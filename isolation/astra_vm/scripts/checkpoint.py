#!/usr/bin/env python3
"""Preservation packaging only. Upload and independently read back before experiments."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import zipfile
p=argparse.ArgumentParser();p.add_argument('milestone');p.add_argument('--note',required=True)
a=p.parse_args();root=Path(__file__).resolve().parents[1]
out=root.parent/'checkpoints'/a.milestone;out.mkdir(parents=True,exist_ok=False)
handoff=root/'ASTRA_VM_CONTAINMENT_HANDOFF.md'
handoff.write_text('# ASTRA VM containment — '+a.milestone+'\n\n'+a.note+'\n\nOriginal RC4 and RC5 archives remain unchanged. See evidence/preservation_log.json for completed readbacks. This checkpoint must be uploaded/read back before security experiments. No VM has been run in this environment. Actual VM containment: NOT TESTED.\n')
shutil.copyfile(handoff,out/handoff.name)
source=out/('ASTRA_VM_CONTAINMENT_'+a.milestone+'_SOURCE.zip')
with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED) as z:
    for f in sorted(root.rglob('*')):
        if f.is_file():z.write(f,Path('astra_vm')/f.relative_to(root))
manifest=out/'ASTRA_VM_CONTAINMENT_SHA256.txt'
manifest.write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in sorted(out.iterdir()) if f.is_file()))
print(json.dumps([{'name':f.name,'path':str(f),'size':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()} for f in sorted(out.iterdir())],indent=2))
