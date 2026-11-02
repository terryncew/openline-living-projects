"""Private OpenLine continuity falsifier — READ ONLY, never grants authority.

Compares stored dependency keys with owner-change events after repairs.
It deliberately does not claim cryptographic validation of the event log:
the SQLite writer and Git history are trusted *inputs* to be challenged.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import json
import sqlite3
from urllib.parse import quote

class ContinuityRefused(RuntimeError):
    pass


def audit(project_db: Path) -> dict:
    project_db = Path(project_db)
    if not project_db.is_file() or project_db.is_symlink():
        raise ContinuityRefused('project_db_missing_or_unsafe')
    uri='file:'+quote(str(project_db.resolve()),safe='/')+'?mode=ro'
    try:
        with closing(sqlite3.connect(uri,uri=True,timeout=5)) as db:
            db.execute('PRAGMA query_only=ON')
            db.execute('BEGIN')
            project=db.execute('SELECT id,contract,last_accepted,status FROM projects').fetchall()
            if len(project)!=1:
                raise ContinuityRefused('one_project_required')
            project_id,basis,accepted_head,project_status=project[0]
            deliveries=db.execute('SELECT id,standing,accepted_head FROM deliverables ORDER BY id').fetchall()
            refs=db.execute('SELECT deliverable_id,depends_on FROM dependencies ORDER BY deliverable_id,depends_on').fetchall()
            assign_rows=db.execute('SELECT id,deliverable_id FROM assignments').fetchall()
            events=db.execute('SELECT seq,kind,payload FROM events ORDER BY seq').fetchall()
            db.commit()
    except sqlite3.Error as exc:
        raise ContinuityRefused('project_db_unreadable') from exc
    deps={name:[] for name,_,_ in deliveries}
    for name,dep in refs:
        if name not in deps:
            raise ContinuityRefused('orphan_dependency')
        deps[name].append(dep)
    assign_to_deliv=dict(assign_rows)
    settled_seq={name:0 for name,_,_ in deliveries}
    last_rebind_target={}
    changes=[]
    try:
        for seq,kind,blob in events:
            if kind=='DELIVERABLE_ACCEPTED':
                ev=json.loads(blob)
                if isinstance(ev,dict) and ev.get('deliverable_id') in settled_seq:
                    settled_seq[ev['deliverable_id']]=seq
                continue
            if kind=='REPAIR_VERIFIED':
                ev=json.loads(blob)
                if isinstance(ev,dict):
                    deliv=assign_to_deliv.get(ev.get('assignment'))
                    rebind=ev.get('dependency_rebind')
                    if (deliv in settled_seq and isinstance(rebind,list) and len(rebind)==2
                        and all(isinstance(x,str) and x for x in rebind)):
                        settled_seq[deliv]=seq
                        last_rebind_target[deliv]=(seq,rebind[0],rebind[1])
                continue
            if kind!='CONTRACT_CHANGED':
                continue
            event=json.loads(blob)
            if not isinstance(event,dict) or set(('dependency','contract','affected','project_id'))-set(event):
                raise ContinuityRefused('invalid_change_event')
            if event['project_id'] != project_id or not isinstance(event['affected'],list) or any(not isinstance(x,str) for x in event['affected']):
                raise ContinuityRefused('invalid_change_event')
            changes.append((seq,event))
    except (ValueError,TypeError) as exc:
        raise ContinuityRefused('invalid_change_event') from exc
    rows=[]
    for name,standing,head in deliveries:
        since=settled_seq.get(name,0)
        unresolved=[{'change_seq':seq,'obsolete_dependency':e['dependency'],
                     'replacement_contract':e['contract']}
                    for seq,e in changes if seq>since and name in e['affected'] and e['dependency'] in deps[name]]
        if not unresolved and name in last_rebind_target:
            r_seq,old_dep,new_dep=last_rebind_target[name]
            if new_dep not in deps[name]:
                unresolved.append({'change_seq':r_seq,'obsolete_dependency':old_dep,
                                   'replacement_contract':new_dep})
        if standing=='CURRENT' and unresolved:
            assessment='CURRENT_LABEL_UNSUPPORTED_DEPENDENCY_REBIND_REQUIRED'
        elif standing=='CURRENT':
            assessment='CURRENT_NOT_FALSIFIED_BY_RECORDED_CHANGES'
        else:
            assessment='NOT_CURRENT'
        rows.append({'deliverable':name,'ledger_standing':standing,'dependency_keys':deps[name],
                     'accepted_head':head,'unresolved_changes':unresolved,'assessment':assessment})
    defects=[r for r in rows if r['assessment']=='CURRENT_LABEL_UNSUPPORTED_DEPENDENCY_REBIND_REQUIRED']
    return {'schema':'openline.continuity.audit.v0.1','project':project_id,'current_contract':basis,
            'ledger_project_status':project_status,'ledger_accepted_head':accepted_head,
            'assessment':'CONTINUITY_UNPROVEN' if defects else 'NO_RECORDED_STALE_DEPENDENCY_FOUND',
            'flagged_current_deliverables':len(defects), 'deliverables':rows,
            'source':'LOCAL_SQLITE_UNAUTHENTICATED_OBSERVATION',
            'signed_change_proof':'NOT_REVERIFIED','accepted_git_ref':'NOT_REOBSERVED',
            'mutation_authority':'NONE','external_effect_truth':'UNKNOWN',
            'pass_claim':'NOT_PERMITTED'}
