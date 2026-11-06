"""Independent adversarial regression for Issue #165 STOP/CLEAR impersonation and replay.

The historical implementation failed both attacks. These tests must run
against the actual receiver/ProjectLedger control paths, not a mock gate.
"""
from __future__ import annotations
import contextlib
import io
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest

BASE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BASE))
from engine_loader import load_engines
load_engines()
import openline_cli as cli
from mcp_server import Server
from project import ProjectRefused
from openline_guard import ReceiverGuard, SigningIdentity, VerificationError

class StopClearAdversarialTests(unittest.TestCase):
    def test_mcp_boolean_cannot_approve_owner_clear(self):
        with tempfile.TemporaryDirectory(prefix='ks-mcp-sec-') as d:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(cli.cmd_init(SimpleNamespace(dir=d, project_id='mcp-authz', workers='alice,bob',validator=None,worker_uid=65534)),0)
            cfg=cli._load_config(Path(d))
            _,p,_=cli._build_engines(cfg,65534)
            owner=cli._read_key(Path(cfg['keys_dir'])/'owner.key')
            claim={'project_id':p.id,'action':'issue_stop','reason':'owner_stop','expected_epoch':1}
            p.issue_stop('owner_stop',cli._sig(owner,claim),expected_epoch=1)
            server=Server(cfg,65534)
            with self.assertRaisesRegex(ValueError,'externally signed'):
                server.call('openline_kill_switch_clear',{'reason':'attacker','owner_confirm':True})
            self.assertTrue(p.read_stop_state()['stopped'])
            good={'project_id':p.id,'action':'clear_stop','reason':'owner_clear','expected_epoch':2}
            result=server.call('openline_kill_switch_clear',{'reason':'owner_clear','signature':cli._sig(owner,good),'expected_epoch':2})
            self.assertFalse(result['isError'])
            self.assertFalse(p.read_stop_state()['stopped'])

    def test_old_signed_clear_and_stop_fail_after_epoch_change(self):
        with tempfile.TemporaryDirectory(prefix='ks-replay-sec-') as d:
            with contextlib.redirect_stdout(io.StringIO()):
                cli.cmd_init(SimpleNamespace(dir=d, project_id='replay', workers='alice,bob',validator=None,worker_uid=65534))
            cfg=cli._load_config(Path(d))
            _,p,_=cli._build_engines(cfg,65534)
            k=cli._read_key(Path(cfg['keys_dir'])/'owner.key')
            def sign(action,reason,epoch):
                return cli._sig(k,{'project_id':p.id,'action':action,'reason':reason,'expected_epoch':epoch})
            oldstop=sign('issue_stop','first',1)
            p.issue_stop('first',oldstop,expected_epoch=1)
            oldclear=sign('clear_stop','first-clear',2)
            p.clear_stop('first-clear',oldclear,expected_epoch=2)
            p.issue_stop('second',sign('issue_stop','second',3),expected_epoch=3)
            with self.assertRaisesRegex(ProjectRefused,'stale_owner_intent'):
                p.clear_stop('first-clear',oldclear,expected_epoch=2)
            self.assertTrue(p.read_stop_state()['stopped'])
            with self.assertRaisesRegex(ProjectRefused,'stale_owner_intent'):
                p.issue_stop('first',oldstop,expected_epoch=1)
            self.assertTrue(p.read_stop_state()['stopped'])
            p.clear_stop('second-clear',sign('clear_stop','second-clear',4),expected_epoch=4)
            self.assertFalse(p.read_stop_state()['stopped'])

    def test_receiver_guard_old_signed_clear_cannot_resume(self):
        with tempfile.TemporaryDirectory(prefix='ks-guard-sec-') as d:
            path=Path(d)/'data.sqlite'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE t(id TEXT PRIMARY KEY, value INTEGER)')
            owner=SigningIdentity()
            guard=ReceiverGuard(path)
            guard.register_issuer(owner.public)
            oldstop=owner.issue_stop_envelope(reason='first',expected_epoch=1)
            guard.issue_stop(oldstop)
            oldclear=owner.clear_stop_envelope(reason='first-clear',expected_epoch=2)
            guard.clear_stop(oldclear)
            guard.issue_stop(owner.issue_stop_envelope(reason='second',expected_epoch=3))
            with self.assertRaisesRegex(VerificationError,'stale_owner_intent'):
                guard.clear_stop(oldclear)
            self.assertTrue(guard.read_stop_state()['stopped'])
            guard.clear_stop(owner.clear_stop_envelope(reason='second-clear',expected_epoch=4))
            self.assertFalse(guard.read_stop_state()['stopped'])

if __name__=='__main__': unittest.main()
