"""Create real multi-module invoice repo + private acceptance oracle; no repair code.

The oracle is intentionally outside the editable worktree. Cases are author-constructed
and are NOT independent held-out coding-agent evaluations until assigned externally.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import sqlite3
import sys
from foundation.promotion import SafePromotion,cmd
from foundation.controller import RepairController

CASES={
 'invoice-tax-change': {'version':2,'tax_basis_points':775,'service_cents':0},
 'invoice-service-fee': {'version':3,'tax_basis_points':0,'service_cents':275},
 'invoice-both-change':{'version':4,'tax_basis_points':925,'service_cents':125},
}

def create(root,case):
    root=Path(root).resolve()
    if root.exists():raise ValueError('fresh destination required')
    root.mkdir(parents=True)
    bare=root/'repo.git'; seed=root/'seed';cmd('git','init','--bare',str(bare));cmd('git','clone',str(bare),str(seed))
    (seed/'app').mkdir();(seed/'spec').mkdir()
    (seed/'app'/'__init__.py').write_text('')
    (seed/'app'/'invoice.py').write_text('''"""Invoice contract calculation. Check spec/contract.json for current requirements."""\ndef total_cents(subtotal_cents: int, tax_basis_points: int, service_cents: int) -> int:\n    return subtotal_cents  # v1 behavior; v2 contract needs implementation\n''')
    (seed/'app'/'store.py').write_text('''import sqlite3\ndef current_rows(path):\n    with sqlite3.connect(path) as db:\n        return db.execute("SELECT id, cents FROM invoices ORDER BY id").fetchall()\n''')
    (seed/'app'/'api.py').write_text('''from .invoice import total_cents\ndef handle(request):\n    return {"total_cents":total_cents(request["subtotal_cents"],request["tax_basis_points"],request["service_cents"])}\n''')
    (seed/'app'/'notes.txt').write_text('Accepted prior business notes.\n')
    (seed/'spec'/'contract.json').write_text(json.dumps({**CASES[case],
        'contract':'Invoice totals are integer cents; exact math: subtotal + (subtotal * tax_basis_points // 10000) + service_cents.',
        'requested_api':'app.invoice.total_cents(subtotal_cents, tax_basis_points, service_cents)',
        'constraint':'Preserve previously accepted invoice rows and concurrent edits.'},indent=2))
    cmd('git','-C',str(seed),'add','.');cmd('git','-C',str(seed),'-c','user.name=Fixture','-c','user.email=fixture@localhost','commit','-m','accepted v1 source')
    cmd('git','-C',str(seed),'push','origin','HEAD:refs/heads/accepted')
    db=root/'live.sqlite'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE invoices (id TEXT PRIMARY KEY,cents INTEGER NOT NULL)')
        conn.executemany('INSERT INTO invoices VALUES (?,?)',[('accepted-A',1000),('accepted-B',2500)])
    oracle=root/'private_oracle.py'
    oracle.write_text('''import json,os,sqlite3\nfrom app.api import handle\nfrom app.store import current_rows\nfrom pathlib import Path\nspec=json.loads(Path("spec/contract.json").read_text())\nfor cents in (101,1000,10001):\n    payload={"subtotal_cents":cents,"tax_basis_points":spec["tax_basis_points"],"service_cents":spec["service_cents"]}\n    assert handle(payload)["total_cents"]==cents+(cents*payload["tax_basis_points"]//10000)+payload["service_cents"]\nassert current_rows(os.environ["OPENLINE_TEST_DB"])==[("accepted-A",1000),("accepted-B",2500)]\nprint("ACCEPTED_APPLICATION_STATE_VERIFIED")\n''')
    return {'root':str(root),'case':case,'repo':str(bare),'db':str(db),'state_dir':str(root/'journal'),
        'oracle':str(oracle)}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True);parser.add_argument('--case',choices=CASES,required=True)
    parser.add_argument('--agent',nargs=argparse.REMAINDER,help='actual installed coding-agent argv; no default/fake agent')
    args=parser.parse_args();meta=create(args.root,args.case)
    controller=RepairController(SafePromotion(meta['repo'],meta['db'],meta['state_dir']),trusted_validator=Path(meta['oracle']))
    out=controller.run('repair-'+args.case,args.agent or None)
    print(json.dumps({'task':meta,'result':out},indent=2,sort_keys=True))

if __name__=='__main__':main()
