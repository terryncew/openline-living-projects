"""Deterministic economics illustration — NO model API, no accepted repair.
All rates and outputs are fictional; this is a control-flow smoke test only.
"""
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from coach import Check, Coach, Completion, Meter, Model, Task


def run_demo():
    cheap=Model('openai','synthetic-student','0.2','0.2',2000,500)
    strong=Model('anthropic','synthetic-teacher','4','4',2000,500)
    task=Task('fictional-invoice','a'*40,'python-invoice','Repair a changed calculation','v2-contract')
    calls=[]
    def runner(m,mode,t,context):
        calls.append({'model':m.key,'mode':mode})
        if mode=='teach':return Completion('Use the v2 adjustment, preserve formatter',250,40)
        if m==strong:return Completion('SAFE_FIX',1000,200)
        return Completion('SAFE_FIX' if 'Teacher advice' in context else 'BROKEN_FIX',450,180)
    def verifier(task,proposal):
        return Check(proposal=='SAFE_FIX','toy-oracle-no-signature-v2')
    with TemporaryDirectory() as temp:
        meter=Meter(Path(temp)/'account.sqlite',16_000_000,{'openai':8_000_000,'anthropic':8_000_000})
        result=Coach(meter,[cheap],strong,runner,verifier).propose(task,'test-coach')
        assert result['status']=='VERIFIED_PROPOSAL'
        assert len(result['calls'])==3
        return {'kind':'SYNTHETIC_CONTROL_FLOW_ONLY','result':result['status'],
                'model_calls':calls,'saved_lesson_scoped_to_exact_task':meter.lesson(task.basis) is not None,
                'metered_estimate_micro_usd':meter.spent_or_held(),
                'promotion_authorized':result['promotion_authorized'],
                'genuine_model_execution':'NOT_TESTED',
                'model_cost_superiority':'NOT_TESTED',
                'trusted_project_repair':'NOT_TESTED'}


if __name__=='__main__':
    print(json.dumps(run_demo(),indent=2,sort_keys=True))
