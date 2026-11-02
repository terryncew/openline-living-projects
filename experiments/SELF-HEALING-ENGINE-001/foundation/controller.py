"""Self-repair controller. External coding agent proposes code; controller never writes repair code.

The trusted validator is outside the editable repository. An agent command must be supplied;
without one, no PROPOSE action occurs. OS sandboxing is a separate unsatisfied gate.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from .promotion import SafePromotion, atomically_write, PromotionRefused


class AgentUnavailable(RuntimeError):
    pass


class RepairController:
    def __init__(self,promotion:SafePromotion, *, trusted_validator:Path):
        self.promotion=promotion
        self.validator=Path(trusted_validator).resolve(strict=True)
        if not self.validator.is_file() or self.validator.is_symlink():
            raise ValueError('trusted_validator_file_required')

    def run(self, task_id:str, agent_argv:list[str]|None, *, timeout:float=60):
        state=self.promotion.prepare(task_id)
        path=Path(state['workspace']).parent/'controller.json'
        def emit(stage,detail):
            state.setdefault('history',[]).append({'stage':stage,'detail':detail})
            atomically_write(path,state)
        wd=Path(state['workspace'])
        # The validator is selected by the receiver. No agent-selected oracle.
        basecmd=[sys.executable,str(self.validator)]
        env={'PATH':os.environ.get('PATH','/usr/bin:/bin'),'HOME':str(wd.parent),
          'OPENLINE_TEST_DB':state['snapshot_db'],'PYTHONDONTWRITEBYTECODE':'1',
          'PYTHONNOUSERSITE':'1','LANG':'C.UTF-8','PYTHONPATH':str(wd)}
        initial=subprocess.run(basecmd,cwd=wd,env=env,capture_output=True,text=True,timeout=timeout)
        emit('DETECT',{'exit':initial.returncode,'stdout_sha256':hashlib.sha256(initial.stdout.encode()).hexdigest(),
                       'stderr_sha256':hashlib.sha256(initial.stderr.encode()).hexdigest()})
        if initial.returncode==0:
            emit('STOP',{'reason':'no_failure_independently_observed'})
            return {'status':'NO_REPAIR_REQUIRED','trace':str(path)}
        if not agent_argv:
            emit('NOT_EXECUTED',{'reason':'no_authorized_model_coding_agent_runtime'})
            return {'status':'AGENT_NOT_EXECUTED','trace':str(path)}
        prompt=wd.parent/'task_for_agent.json'
        # The error output is available; oracle implementation is outside the workspace.
        atomically_write(prompt,{'assignment':'Fix the application so the observed behavior meets its stated contract.',
               'observed_test_exit':initial.returncode,'stderr':initial.stderr[-5000:],'stdout':initial.stdout[-2000:],
               'editable_scope':['app/'],'prohibited':['oracle','accepted Git ref','receiver database'],
               'note':'Diagnose and propose your own source correction. No answer is provided.'})
        emit('DIAGNOSE',{'evidence_path':str(prompt),'prompt_sha256':hashlib.sha256(prompt.read_bytes()).hexdigest()})
        allowed = [str(x) for x in agent_argv]
        started=time.monotonic()
        try:
            proc=subprocess.run(allowed,cwd=wd,capture_output=True,text=True,timeout=timeout,
              env={**env,'OPENLINE_REPAIR_EVIDENCE':str(prompt)})
        except FileNotFoundError as exc:
            emit('NOT_EXECUTED',{'reason':'agent_command_missing'})
            return {'status':'AGENT_NOT_EXECUTED','trace':str(path)}
        emit('PROPOSE',{'exit':proc.returncode,'elapsed_s':round(time.monotonic()-started,3),
            'stdout_sha256':hashlib.sha256(proc.stdout.encode()).hexdigest(),
            'stderr_sha256':hashlib.sha256(proc.stderr.encode()).hexdigest()})
        if proc.returncode:
            emit('STOP',{'reason':'coding_agent_did_not_complete'})
            return {'status':'PROPOSAL_FAILED','trace':str(path)}
        result=self.promotion.promote(task_id,acceptance_cmd=basecmd,timeout=timeout)
        emit('TEST_PROMOTE',result)
        if result['status']!='PROMOTED':
            return {'status':'REPAIR_REFUSED','trace':str(path),'result':result}
        # Verify actual accepted Git object, not the candidate workspace's return message.
        accepted=self.promotion.accepted()
        verified=(accepted==result['head'])
        emit('VERIFY',{'accepted_sha':accepted,'matches_promoted':verified,'db_unchanged':result['db_unchanged']})
        if not verified: return {'status':'OUTCOME_UNCERTAIN','trace':str(path)}
        emit('CONTINUE',{'task_id':task_id,'last_verified_head':accepted})
        return {'status':'REPAIR_PROMOTED','head':accepted,'trace':str(path),'autonomy_not_certified':True}
