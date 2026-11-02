"""No-model conventional Git comparison for concurrent accepted work.

Proves that a competent conventional branch gate can preserve independent
changes: scope is checked against the candidate's BASE (three-dot equivalent),
then merging current main is validated and CAS-updated. Does not claim a
complete conventional multi-agent assignment/receipt/recovery solution.
"""
import json
from pathlib import Path
import subprocess
import tempfile


def git(*args, cwd=None):
    result=subprocess.run(['git',*map(str,args)],cwd=cwd,capture_output=True,text=True)
    if result.returncode: raise AssertionError((result.args,result.stdout,result.stderr))
    return result.stdout.strip()


def execute():
    with tempfile.TemporaryDirectory(prefix='conventional-cas-') as d:
        root=Path(d); repo=root/'work'; repo.mkdir()
        git('init','-q',cwd=repo)
        git('config','user.name','Trusted Receiver',cwd=repo)
        git('config','user.email','r@localhost',cwd=repo)
        (repo/'app').mkdir()
        (repo/'app'/'price.py').write_text('def total(qty):\n    return qty * 10\n')
        (repo/'app'/'independent.py').write_text('def label(value):\n    return value\n')
        git('add','app',cwd=repo);git('commit','-qm','initial H1',cwd=repo)
        h1=git('rev-parse','HEAD',cwd=repo)
        # Candidate made at H1, in scope price.py only.
        git('checkout','-qb','candidate',h1,cwd=repo)
        (repo/'app'/'price.py').write_text('def total(qty):\n    return qty * 11\n')
        git('add','app/price.py',cwd=repo);git('commit','-qm','authorized price change',cwd=repo)
        candidate=git('rev-parse','HEAD',cwd=repo)
        scope=git('diff','--name-only',h1,candidate,cwd=repo).splitlines()
        assert scope==['app/price.py'],scope
        # Unrelated, independently accepted contribution arrives at H2.
        git('checkout','-qb','accepted',h1,cwd=repo)
        (repo/'app'/'independent.py').write_text('def label(value):\n    return value.upper()\n')
        git('add','app/independent.py',cwd=repo);git('commit','-qm','independent accepted update',cwd=repo)
        h2=git('rev-parse','HEAD',cwd=repo)
        assert h2!=h1
        # The trust receiver merges candidate into current accepted work, not
        # fast-forwards a stale branch; both changes must remain intact.
        git('merge','--no-ff','-qm','receiver verified merge',candidate,cwd=repo)
        h3=git('rev-parse','HEAD',cwd=repo)
        assert git('rev-parse','HEAD^1',cwd=repo)==h2
        assert git('rev-parse','HEAD^2',cwd=repo)==candidate
        assert 'qty * 11' in (repo/'app'/'price.py').read_text()
        assert 'value.upper()' in (repo/'app'/'independent.py').read_text()
        assert git('diff','--name-only',h2,h3,cwd=repo).splitlines()==['app/price.py']
        # Emulate atomic receiver update on a protected ref under concurrency.
        git('update-ref','refs/heads/protected',h2,cwd=repo)
        git('update-ref','refs/heads/protected',h3,h2,cwd=repo)
        assert git('rev-parse','refs/heads/protected',cwd=repo)==h3
        # stale CAS must fail
        stale=subprocess.run(['git','update-ref','refs/heads/protected',h1,h2],cwd=repo,capture_output=True,text=True)
        assert stale.returncode!=0
        return {'verdict':'CONVENTIONAL_CONCURRENT_PRESERVATION_PASS',
                'scope_at_candidate_base':scope,'stale_cas_refused':True,
                'both_contributors_preserved':True,'repeated_change_recovery':'NOT_TESTED',
                'signed_receipts':'NOT_TESTED','model':'NONE',
                'security_claim':'INTEGRITY_LOCAL_GIT_ONLY',
                'h1':h1,'h2':h2,'h3':h3,
                'interpretation':'Single-branch concurrent preservation is Git+CI parity, not an exclusive OpenLine capability.'}

if __name__=='__main__':print(json.dumps(execute(),sort_keys=True,indent=2))
