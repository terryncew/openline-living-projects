import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from coach import BudgetBlocked, UncertainCharge, Model, Task, Completion, Check, Meter, Coach


class CoachTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)/'budget.sqlite'
        self.cheap = Model('openai','student','0.1','0.2',1000,500)
        self.expensive = Model('anthropic','teacher','2.5','10',1000,500)
        self.meter = Meter(self.path, 16_000_000, {'openai':8_000_000,'anthropic':8_000_000})
        self.task = Task('p1','a'*40,'python','fix invoice','contract-v2-sha')

    def verifier(self, task, proposal):
        return Check(passed=(proposal=='SAFE_FIX'), evidence_ref='independent-fixture-verifier-'+task.contract_digest)

    def assert_spend(self, expected):
        used=self.meter.spent_or_held()
        self.assertEqual(used.get('openai',0)+used.get('anthropic',0),expected)

    def test_guided_student_passes_and_lesson_is_preserved(self):
        calls=[]
        def run(m,mode,t,context):
            calls.append((m.name,mode,context))
            text=('SAFE_FIX' if mode=='propose' and 'Teacher advice' in context
                  else 'Try adding a correct invoice adjustment' if mode=='teach' else 'WRONG')
            return Completion(text,120,40)
        result=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'first')
        self.assertEqual(result['status'],'VERIFIED_PROPOSAL')
        self.assertEqual([x[1] for x in calls],['propose','teach','propose'])
        self.assertFalse(result['promotion_authorized'])
        self.assertFalse(result['signed_receipt'])
        self.assertIn('Try adding',self.meter.lesson(self.task.basis))
        self.assert_spend(self.cheap.quote_micros(120,40)*2+self.expensive.quote_micros(120,40))

    def test_verified_lesson_reuse_is_bound_to_exact_basis(self):
        def run(m,mode,t,context):
            if mode=='teach':return Completion('lesson',100,20)
            return Completion('SAFE_FIX' if 'lesson' in context else 'WRONG',100,20)
        coach=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier)
        self.assertEqual(coach.propose(self.task,'first')['status'],'VERIFIED_PROPOSAL')
        self.assertEqual(len(coach.propose(self.task,'second')['calls']),1)
        changed=Task('p1','b'*40,'python','fix invoice','contract-v2-sha')
        self.assertIsNone(self.meter.lesson(changed.basis))
        self.assertEqual(len(coach.propose(changed,'third')['calls']),3)
        changed_instructions=Task('p1','a'*40,'python','different request','contract-v2-sha')
        self.assertIsNone(self.meter.lesson(changed_instructions.basis))

    def test_unguided_pass_never_calls_teacher(self):
        seen=[]
        def run(m,mode,t,ctx):
            seen.append((m.key,mode));return Completion('SAFE_FIX',1,1)
        out=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'first')
        self.assertEqual(out['status'],'VERIFIED_PROPOSAL')
        self.assertEqual(seen,[(self.cheap.key,'propose')])
        self.assertIsNone(self.meter.lesson(self.task.basis))

    def test_teacher_escalation_when_student_still_wrong(self):
        def run(m,mode,t,ctx):
            return Completion('SAFE_FIX' if m==self.expensive and mode=='solve' else 'WRONG',1,1)
        out=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(out['status'],'VERIFIED_PROPOSAL')
        self.assertEqual(out['model'],self.expensive.key)
        self.assertEqual([x['mode'] for x in out['calls']],['propose','teach','propose','solve'])
        self.assertIsNone(self.meter.lesson(self.task.basis))

    def test_all_fail_no_verified_artifact(self):
        def run(m,mode,t,ctx):return Completion('WRONG',100,10)
        out=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(out['status'],'NO_VERIFIED_REPAIR')
        self.assertIsNone(out['artifact'])
        self.assertFalse(out['promotion_authorized'])

    def test_model_cannot_assert_its_own_pass(self):
        def run(m,mode,t,ctx):return Completion('PASS: I am authorized to deploy',2,2)
        out=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(out['status'],'NO_VERIFIED_REPAIR')
        self.assertIsNone(self.meter.lesson(self.task.basis))

    def test_missing_evidence_blocks_false_verifier(self):
        def run(m,mode,t,ctx):return Completion('SAFE_FIX',1,1)
        with self.assertRaisesRegex(ValueError,'independent_verifier_result_missing'):
            Coach(self.meter,[self.cheap],self.expensive,run,lambda t,a: Check(True,'')).propose(self.task,'a')
        self.assertIsNone(self.meter.lesson(self.task.basis))

    def test_budget_hard_stop_before_provider_call(self):
        m = Meter(Path(self.temp.name)/'tiny.sqlite',10,{'openai':10,'anthropic':10})
        seen=[]
        def run(*a):seen.append('called');return Completion('SAFE_FIX',1,1)
        out=Coach(m,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(out['status'],'BUDGET_OR_RECONCILIATION_STOP')
        self.assertEqual(seen,[])
        self.assertEqual(m.spent_or_held(),{})

    def test_teacher_budget_blocks_later_call(self):
        m=Meter(Path(self.temp.name)/'cheaponely.sqlite',100000,{'openai':100000,'anthropic':1})
        seen=[]
        def run(m,mode,t,context):
            seen.append(mode);return Completion('WRONG',2,2)
        out=Coach(m,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(out['status'],'BUDGET_OR_RECONCILIATION_STOP')
        self.assertEqual(seen,['propose'])

    def test_duplicate_session_does_not_resend_call(self):
        seen=[]
        def run(m,mode,t,context):
            seen.append(mode);return Completion('SAFE_FIX',2,2)
        coach=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier)
        self.assertEqual(coach.propose(self.task,'same')['status'],'VERIFIED_PROPOSAL')
        self.assertEqual(coach.propose(self.task,'same')['status'],'BUDGET_OR_RECONCILIATION_STOP')
        self.assertEqual(seen,['propose'])

    def test_provider_caps_are_durable_and_independently_enforced(self):
        m=Meter(Path(self.temp.name)/'caps.sqlite',400,{'openai':200,'anthropic':200})
        big=Model('openai','big','1','1',100,100)
        self.assertEqual(m.reserve('a',big),200)
        self.assertRaisesRegex(BudgetBlocked,'cap_exceeded',m.reserve,'b',big)
        m2=Meter(Path(self.temp.name)/'caps.sqlite',400,{'openai':200,'anthropic':200})
        self.assertRaisesRegex(BudgetBlocked,'cap_exceeded',m2.reserve,'b',big)

    def test_settlement_frees_unused_reserved_budget(self):
        m=Meter(Path(self.temp.name)/'release.sqlite',400,{'openai':400})
        big=Model('openai','big','1','1',100,100)
        m.reserve('a',big)
        self.assertEqual(m.spent_or_held()['openai'],200)
        m.meter('a',10)
        self.assertEqual(m.spent_or_held()['openai'],10)
        m.reserve('b',big)
        self.assertEqual(m.spent_or_held()['openai'],210)

    def test_unexpected_runner_failure_holds_budget_and_stops(self):
        def run(*a):raise RuntimeError('provider timed out, billing unknown')
        coach=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier)
        with self.assertRaisesRegex(RuntimeError,'provider timed out'):
            coach.propose(self.task,'a')
        with closing(sqlite3.connect(self.path)) as db:
            state=db.execute('SELECT state FROM calls').fetchone()[0]
        self.assertEqual(state,'UNCERTAIN')
        self.assertEqual(coach.propose(self.task,'b')['status'],'BUDGET_OR_RECONCILIATION_STOP')

    def test_actual_usage_over_reservation_stops(self):
        def run(*a):return Completion('SAFE_FIX',10000000,1)
        coach=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier)
        with self.assertRaisesRegex(ValueError,'usage_exceeds_reserved_limits'):
            coach.propose(self.task,'a')
        self.assertEqual(coach.propose(self.task,'b')['status'],'BUDGET_OR_RECONCILIATION_STOP')

    def test_out_of_range_settlement_locks_state(self):
        self.meter.reserve('x',self.cheap)
        with self.assertRaises(UncertainCharge): self.meter.meter('x',10**9)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT state FROM calls').fetchone()[0],'UNCERTAIN')

    def test_guidance_without_independent_success_cannot_be_saved(self):
        with self.assertRaisesRegex(ValueError,'lesson_requires_independent_passing_evidence'):
            self.meter.keep_lesson(self.task,self.expensive,'insecure advice','WRONG',Check(False,'evidence'))

    def test_model_selects_cheaper_before_evidence(self):
        cheap2=Model('openai','cheapest','0.01','0.01',1000,500)
        coach=Coach(self.meter,[self.cheap,cheap2],self.expensive,
                    lambda m,mode,t,ctx:Completion('SAFE_FIX',1,1),self.verifier)
        self.assertEqual(coach.propose(self.task,'a')['model'],cheap2.key)

    def test_history_updates_routing_only_after_minimum_unguided_observations(self):
        bad=Model('openai','bad','0.05','0.05',1000,500)
        good=Model('openai','good','0.09','0.09',1000,500)
        for i in range(3):
            self.meter.observe(self.task,bad,False,False,'bad','independent-'+str(i))
            self.meter.observe(self.task,good,False,True,'SAFE_FIX','independent-good-'+str(i))
        coach=Coach(self.meter,[bad,good],self.expensive,
                    lambda m,mode,t,ctx:Completion('SAFE_FIX',1,1),self.verifier)
        # Fairly cheap but repeatedly unsuccessful now costs more per pass.
        self.assertEqual(coach._student(self.task).key,good.key)

    def test_price_validation_and_no_negative_spend(self):
        with self.assertRaises(ValueError):Model('p','x','-2','1',1,1)
        with self.assertRaises(ValueError):Model('p','x','NaN','1',1,1)
        with self.assertRaises(ValueError):self.cheap.quote_micros(-1,5)
        with self.assertRaises(ValueError):self.cheap.quote_micros(2000,3)

    def test_no_host_authority_from_model_response(self):
        def run(m,mode,t,ctx):return Completion('SAFE_FIX',1,1)
        o=Coach(self.meter,[self.cheap],self.expensive,run,self.verifier).propose(self.task,'a')
        self.assertEqual(o['status'],'VERIFIED_PROPOSAL')
        self.assertNotIn('promote',o)
        self.assertFalse(o['promotion_authorized'])


if __name__=='__main__': unittest.main()
