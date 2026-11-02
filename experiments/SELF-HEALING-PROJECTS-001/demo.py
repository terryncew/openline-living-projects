"""Run a real World-custody + Git/SQLite deterministic two-participant demonstration.

Requires pinned public OpenLine World checkout via WORLD_REPO, and source from
private Self-Healing Engine 001 in the sibling experiments folder. All effects
are local fictional SQLite rows. Workers are scripted, NOT coding LLM agents.
"""
from __future__ import annotations
from contextlib import closing
from pathlib import Path
import json, os, sqlite3, subprocess, sys, tempfile, time, urllib.parse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PrivateFormat,NoEncryption,PublicFormat

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/'SELF-HEALING-ENGINE-001'))
from foundation.promotion import SafePromotion, cmd, PromotionRefused
from foundation.effects import Principal, LocalEffectStore, EffectDenied
from project import ProjectLedger, ProjectRefused, canonical, digest

WORLD_SHA='5dd095b4d7a046569abd4518b1c9a60ae6007015'

def pub(k):return k.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
def sig(k,obj):return k.sign(canonical(obj)).hex()
def seed(k):return k.private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
def ensure(test,message):
    if not test:raise AssertionError(message)

def git(*args,cwd=None):
    return cmd('git',*args,cwd=cwd).stdout.strip()

def world_setup(world_path,work):
    """Run actual World backend and real wallet-bound participant clients on loopback.
    The test coordinator owns both separate key dirs; no OS isolation is claimed.
    """
    sys.path.insert(0,str(world_path/'clients'))
    sys.path.insert(0,str(world_path/'backend'/'vendor'))
    from participant import ParticipantClient
    port=18571
    env={**os.environ,'WORKSHOP_PORT':str(port),'WORLD_DATA_DIR':str(work/'world_data')}
    out=open(work/'world-server.log','w')
    proc=subprocess.Popen([sys.executable,str(world_path/'backend'/'server.py')],cwd=world_path,
                          env=env,stdout=out,stderr=subprocess.STDOUT)
    try:
        import urllib.request
        deadline=time.monotonic()+18
        while time.monotonic()<deadline:
            if proc.poll() is not None: raise RuntimeError('World server exited')
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/api/health',timeout=1) as response:
                    if response.status==200:break
            except Exception:time.sleep(.15)
        else:raise RuntimeError('World backend not healthy')
        clients={}
        for who in ('alice','bob'):
            c=ParticipantClient(work/'keys'/who,f'http://127.0.0.1:{port}')
            c.ceremony(f'participant-{who}',who,f'agent-{who}',f'Agent {who}', ['draft.write','notes.write'])
            c.join()
            clients[who]=c
        pinned_gate=None
        receipts={}
        for who,c in clients.items():
            allowed=c.propose('draft.write',c.authorize('draft.write'))
            ensure(allowed.get('decision')=='ALLOWED','World gate refused member '+who)
            params=urllib.parse.urlencode({'participant_id':c.participant_id,'token':c._token})
            entries=c._get('/api/world/receipts?'+params).get('receipts',[])
            matching=[x for x in entries if x.get('action')=='draft.write' and
                      x.get('signature',{}).get('value','')[:16]==allowed.get('receipt_id')]
            ensure(len(matching)==1,'World signed receipt missing')
            raw=matching[0]
            gate=raw.get('gate_public_key')
            if pinned_gate is None:pinned_gate=gate
            ensure(gate==pinned_gate,'World gate key changed')
            # World receipts_for projects a reduced view lacking payload_hash.
            # Ask the World receiver to verify its FULL stored signed record.
            # This proves receiver-side validity, NOT independent offline verification.
            shared=c._post('/api/world/receipts/share',
                           {'participant_id':c.participant_id,'token':c._token,
                            'receipt_id':allowed['receipt_id']})
            ensure(isinstance(shared,dict),'World internal signature check unavailable')
            ensure(raw.get('subject_id')==c.agent_id and raw.get('decision')=='ALLOWED',
                   'World receipt identity/decision wrong')
            receipts[who]={'member':who,'receipt':raw}
        def world_verify(data,inv):
            try:
                raw=data['receipt']; member=data['member']; c=clients[member]
                return (member==inv['member_id'] and raw.get('gate_public_key')==pinned_gate and
                        raw['subject_id']==c.agent_id and raw['action']=='draft.write' and
                        raw['decision']=='ALLOWED' and inv['worker_pub']==c.worker_public_key)
            except (KeyError,TypeError):return False
        return proc,out,clients,receipts,world_verify
    except BaseException:
        proc.terminate();proc.wait(timeout=6);out.close();raise

def setup_git(work):
    repo=work/'accepted.git'
    git('init','--bare',str(repo))
    bootstrap=work/'bootstrap'
    git('clone',str(repo),str(bootstrap))
    git('-C',str(bootstrap),'config','user.name','Trusted Project Bootstrap')
    git('-C',str(bootstrap),'config','user.email','boot@localhost')
    (bootstrap/'app').mkdir()
    (bootstrap/'app'/'price.py').write_text('def total(qty):\n    return 0\n')
    (bootstrap/'app'/'independent.py').write_text('def label(value):\n    return value\n')
    git('-C',str(bootstrap),'add','app')
    git('-C',str(bootstrap),'commit','-m','bounded project baseline')
    git('-C',str(bootstrap),'push','origin','HEAD:refs/heads/accepted')
    effects_db=work/'effects.sqlite'
    with closing(sqlite3.connect(effects_db)) as db:
        db.execute('CREATE TABLE application_effects (id TEXT PRIMARY KEY, value INTEGER NOT NULL)')
        db.commit()
    return SafePromotion(repo,effects_db,work/'promotion')

def validator(path,price,require_b):
    path.write_text('from app.price import total\nfrom app.independent import label\n'
                    f'assert total(2)=={price}, "wrong observed invoice amount"\n'+
                    ("assert label('ok')=='OK', 'independent contributor lost'\n" if require_b else '')+
                    "print('TRUSTED_APPLICATION_PASS')\n")

def proposal(promotion,task,changes,validator_path,*,allowed=('app/',)):
    prepared=promotion.prepare(task)
    for relative,source in changes.items():
        path=Path(prepared['workspace'])/relative
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_text(source)
    return promotion.promote(task,acceptance_cmd=[sys.executable,str(validator_path)],allow_prefixes=allowed)

def observed_acceptance(promotion,work,validator_path):
    inspect=work/'observe'
    git('--git-dir',str(promotion.repo),'worktree','add','--detach',str(inspect),promotion.accepted())
    try:
        p=subprocess.run([sys.executable,str(validator_path)],cwd=inspect,
                         env={**os.environ,'PYTHONPATH':str(inspect)},capture_output=True,text=True)
        return {'exit':p.returncode,'stdout':p.stdout.strip(),'stderr':p.stderr.strip()}
    finally:
        git('--git-dir',str(promotion.repo),'worktree','remove','--force',str(inspect))

def execute(work,world_repo):
    work.mkdir(parents=True,exist_ok=True)
    proc=out=None
    try:
        proc,out,clients,receipts,world_verify=world_setup(world_repo,work)
        promotion=setup_git(work)
        founder=Ed25519PrivateKey.generate()
        project=ProjectLedger(work/'project.sqlite','invoice-project-001','Maintain correct invoice calculation',
                              pub(founder),promotion=promotion,world_verifier=world_verify)
        for who,c in clients.items():
            inv={'project_id':project.id,'member_id':who,'owner_pub':pub(c._root_key),
                 'worker_pub':c.worker_public_key,'scope':'contribute',
                 'world_digest':digest(receipts[who])}
            ensure(project.join(inv,sig(founder,inv),sig(c._root_key,inv),world_receipt=receipts[who])=='JOINED',
                   'project member admission failed')
        v1=work/'trusted_v1.py';v1b=work/'trusted_v1b.py';v2=work/'trusted_v2.py'
        validator(v1,20,False);validator(v1b,20,True);validator(v2,22,True)
        a=proposal(promotion,'feature-a',{'app/price.py':'def total(qty):\n    return qty * 10\n'},v1)
        ensure(a['status']=='PROMOTED','Agent A script contribution refused '+str(a))
        def accepted(d,who,deps):
            claim={'project_id':project.id,'deliverable_id':d,'member_id':who,
                   'accepted_head':promotion.accepted(),'dependencies':sorted(deps)}
            project.accept(d,who,promotion.accepted(),deps,sig(clients[who]._root_key,claim))
        accepted('invoice-feature','alice',['invoice_v1'])
        stale=promotion.prepare('stale-candidate')
        (Path(stale['workspace'])/'app'/'independent.py').write_text('def label(value):\n    return value.lower()\n')
        b=proposal(promotion,'feature-b',{'app/independent.py':'def label(value):\n    return value.upper()\n'},v1b)
        ensure(b['status']=='PROMOTED','Agent B script contribution refused '+str(b))
        accepted('independent-formatter','bob',['format_v1'])
        before=observed_acceptance(promotion,work,v1b)
        ensure(before['exit']==0,'pre-change application invalid')
        change={'project_id':project.id,'dependency':'invoice_v1','contract':'invoice_v2',
                'action':'change_dependency'}
        affected=project.change_dependency('invoice_v1','invoice_v2',sig(founder,change))
        ensure(affected==['invoice-feature'],'dependency impact was not selective')
        broken=observed_acceptance(promotion,work,v2)
        ensure(broken['exit']!=0,'contract change failed to expose defect')
        assignment={'project_id':project.id,'assignment_id':'repair-v2','deliverable_id':'invoice-feature',
                    'worker_member':'bob','basis':'invoice_v2',
                    'allowed_paths':['app/price.py'],'action':'repair_assignment'}
        project.assign_repair('repair-v2','invoice-feature','bob','invoice_v2',
                              sig(clients['alice']._root_key,assignment),allowed_paths=['app/price.py'])
        invalid=proposal(promotion,'invalid-repair',{'app/price.py':'def total(qty):\n    return 999\n'},v2,allowed=('app/price.py',))
        ensure(invalid['status']=='REFUSED' and invalid['reason']=='independent_acceptance_failed',
               'invalid repair was not rejected')
        stale_refused=promotion.promote('stale-candidate',acceptance_cmd=[sys.executable,str(v2)],
                                        allow_prefixes=('app/price.py',))
        ensure(stale_refused['status']=='REFUSED','stale scope overwrite accepted')
        # Falsifier: a perfectly correct but UNASSIGNED candidate must not
        # reach Git CAS through the project's trusted admission path.
        no_assignment=promotion.prepare('unassigned-valid')
        (Path(no_assignment['workspace'])/'app'/'price.py').write_text(
            'def total(qty):\n    return qty * 11\n')
        before_unassigned=promotion.accepted()
        try:
            project.promote_repair('unassigned-valid',acceptance_cmd=[sys.executable,str(v2)])
            raise AssertionError('unassigned repair was allowed')
        except ProjectRefused as exc:
            ensure(str(exc)=='repair_assignment_missing','unexpected refusal reason')
        ensure(promotion.accepted()==before_unassigned,'unassigned correct patch changed Git')
        # The signed assignment locks both the permitted filename and current
        # dependency basis before the receiver tests and conditionally accepts.
        repair_candidate=promotion.prepare('repair-v2')
        (Path(repair_candidate['workspace'])/'app'/'price.py').write_text(
            'def total(qty):\n    return qty * 11\n')
        repair=project.promote_repair('repair-v2',acceptance_cmd=[sys.executable,str(v2)])
        ensure(repair['status']=='PROMOTED','deterministic authorized repair failed '+str(repair))
        ensure(project.resolve_repair('repair-v2',repair['head'])=='RECORDED','project recovery checkpoint failed')
        good=observed_acceptance(promotion,work,v2)
        ensure(good['exit']==0,'post-repair accepted source not correct')
        ensure('return value.upper()' in git('--git-dir',str(promotion.repo),'show',
                                             'refs/heads/accepted:app/independent.py'),
               'lost Agent B valid contribution')
        a_owner=Principal(seed(clients['alice']._root_key));wa=Principal(seed(clients['alice']._worker_key))
        wb=Principal(seed(clients['bob']._worker_key))
        effect=LocalEffectStore(work/'effects.sqlite')
        effect.register_buyer(a_owner.public)
        payload={'project':project.id,'accepted':promotion.accepted(),'invoice':'fixture-101'}
        task_id='invoice-effect-101'
        delegation=a_owner.delegate(wa.public,task_id=task_id,mode='execute',expires=int(time.time())+300)
        request=wa.request(delegation,task_id=task_id,payload=payload,mode='execute')
        applied=effect.apply(delegation=delegation,request=request,task_id=task_id,payload=payload,
              effect=lambda db:db.execute('INSERT INTO application_effects VALUES (?,?)',('fixture-101',22)),
              observe=lambda db:db.execute('SELECT value FROM application_effects WHERE id=?',
                                           ('fixture-101',)).fetchone()==(22,),
              standing=lambda db:project.snapshot()['project'][-1]=='ACTIVE')
        ensure(applied['status']=='COMMITTED','local effect not committed')
        # Intentionally lose the returned result, then revoke original worker.
        effect.revoke(delegation)
        latency,world_refresh=clients['alice'].revoke()
        stopped=clients['alice'].propose('draft.write',clients['alice'].authorize('draft.write'))
        ensure(stopped['decision']=='STOPPED','World revocation not enforced')
        b_still=clients['bob'].propose('draft.write',clients['bob'].authorize('draft.write'))
        ensure(b_still['decision']=='ALLOWED','B authority lost after A revocation')
        replacement=a_owner.delegate(wb.public,task_id=task_id,mode='recover',expires=int(time.time())+300)
        recovery_req=wb.request(replacement,task_id=task_id,payload=payload,mode='recover')
        recovered=effect.recover(delegation=replacement,request=recovery_req,task_id=task_id,payload=payload)
        ensure(recovered['receipt']==applied['receipt'],'successor did not recover exact original signature')
        LocalEffectStore.verify_receipt(recovered['receipt'],effect.receiver_public)
        with closing(sqlite3.connect(work/'effects.sqlite')) as db:
            effects_rows=db.execute('SELECT COUNT(*) FROM application_effects').fetchone()[0]
        ensure(effects_rows==1,'lost response replay caused extra effect')
        persisted=ProjectLedger(work/'project.sqlite',promotion=promotion,world_verifier=world_verify).snapshot()
        ensure({x[0]:x[2] for x in persisted['deliverables']}==
               {'invoice-feature':'CURRENT','independent-formatter':'CURRENT'},'restart lost standing')
        result={'verdict':'DETERMINISTIC_INTEGRATION_PASS','autonomous_agent_repair':'NOT_TESTED',
                'world_source':WORLD_SHA,'world_receipt_check':'RECEIVER_VERIFIED_FULL_RECORD_NOT_OFFLINE',
                'participants':2,'different_owner_keys':True,
                'initial_contributions':[a['head'],b['head']],
                'dependency_change':'invoice_v1 -> invoice_v2','reopened':affected,
                'application_failure_exit':broken['exit'],'invalid_repair':invalid['reason'],
                'stale_repair':stale_refused['reason'],
                'unassigned_correct_repair':'REFUSED','repair_head':repair['head'],
                'post_repair_exit':good['exit'],'other_contribution_preserved':True,
                'world_a_post_revocation':stopped['decision'],'world_b_after_a_revoked':b_still['decision'],
                'world_revocation_latency_s':round(latency,5),
                'signed_successor_receipt_equal':True,'effect_rows':effects_rows,
                'project_status':persisted['project'][-1],
                'agent_process_isolation':'NOT_TESTED',
                'git_sqlite_atomic_promotion':'NOT_IMPLEMENTED'}
        (work/'RESULT.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return result
    finally:
        if proc is not None:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        if out is not None:out.close()

def main():
    world=os.environ.get('WORLD_REPO')
    if not world:raise SystemExit('WORLD_REPO must reference pinned OpenLine World checkout')
    seen=subprocess.run(['git','-C',world,'rev-parse','HEAD'],capture_output=True,text=True)
    if seen.returncode or seen.stdout.strip()!=WORLD_SHA:
        raise SystemExit('WORLD_REPO source SHA mismatch')
    with tempfile.TemporaryDirectory(prefix='openline-project-') as temp:
        result=execute(Path(temp),Path(world).resolve())
        print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
