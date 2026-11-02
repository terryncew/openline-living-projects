"""Tests for the MCP adapter interface; fake CLI is NOT an engine verification."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from openline_mcp_entry.engine import ConfigurationError, EngineError, OpenLineTools, OperatorConfig
from openline_mcp_entry.server import MCPServer

FAKE_CLI = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
pack = pathlib.Path(args[0])
mode = json.loads(pack.read_text())['mode']
path = pathlib.Path(args[args.index('--output-dir')+1])
path.joinpath('arguments.json').write_text(json.dumps(args))
if mode in ('commit', 'deny', 'quarantine', 'mismatch', 'ephemeral'):
    status = {'commit':'COMMIT','deny':'DENY','quarantine':'QUARANTINE','mismatch':'COMMIT','ephemeral':'COMMIT'}[mode]
    payload={'schema':'openline.check-result.v1','decision':status,
             'gate':{'key_mode':'ephemeral' if mode=='ephemeral' else 'pinned_file'},
             'decision_receipt_self_verified':True,'decision_receipt_sha256':'fake-test-hash'}
    print(json.dumps(payload))
    sys.exit(1 if mode in ('deny','quarantine','mismatch') else 0)
if mode=='impact':
    print(json.dumps({'schema':'openline.impact-pack-result.v1',
                      'result':{'reopen':['a'],'retain':['b'],'undetermined':['c']}}))
    sys.exit(0)
if mode=='bad-json':
    print('bad JSON')
    sys.exit(0)
if mode=='error':
    print(json.dumps({'error':'fake error'}))
    sys.exit(2)
'''


class LocalHarness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / 'mock-cli'
        self.fake.write_text(FAKE_CLI)
        self.fake.chmod(self.fake.stat().st_mode | stat.S_IXUSR)
        self.key = self.root / 'gate.key'
        self.key.write_text('fake-test-key; never real authority')
        self.packs = {}
        for name in ['commit', 'deny', 'quarantine', 'impact', 'error', 'mismatch', 'ephemeral', 'bad-json']:
            p = self.root / f'{name}.json'
            p.write_text(json.dumps({'mode':name}))
            self.packs[name] = p.name
        self.config = self.root/'operator.json'
        self.raw = {
            'schema': 'openline.mcp-entry.operator.v1',
            'check_profiles': {name:self.packs[name] for name in ['commit','deny','quarantine','mismatch','ephemeral','bad-json','error']},
            'impact_profiles': {'impact':'impact.json'},
            'gate_key':'gate.key',
            'gate_id':'real-receiver-identity',
            'records_dir':'.records',
            'check_binary':str(self.fake),
            'impact_binary':str(self.fake),
        }
        self.save_config()
        self.tools = OpenLineTools(OperatorConfig.load(self.config))
        self.mcp = MCPServer(self.tools)

    def save_config(self):
        self.config.write_text(json.dumps(self.raw))

    def call(self, name, args):
        self.mcp.handle({'jsonrpc':'2.0','id':1,'method':'initialize',
                         'params':{'protocolVersion':'2025-11-25'}})
        return self.mcp.handle({'jsonrpc':'2.0','id':2,'method':'tools/call',
                                'params':{'name':name,'arguments':args}})

    def test_mcp_initialize_and_discovery(self):
        r=self.mcp.handle({'jsonrpc':'2.0','id':1,'method':'initialize',
                           'params':{'protocolVersion':'2025-06-18'}})
        self.assertEqual(r['result']['protocolVersion'],'2025-06-18')
        names=[t['name'] for t in self.mcp.handle({'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}})['result']['tools']]
        self.assertEqual(names,['openline_check','openline_impact','openline_capabilities'])

    def test_not_initialized_is_refused(self):
        r=self.mcp.handle({'jsonrpc':'2.0','id':1,'method':'tools/list','params':{}})
        self.assertEqual(r['error']['code'],-32002)

    def test_notifications_are_silent(self):
        self.assertIsNone(self.mcp.handle({'jsonrpc':'2.0','method':'notifications/initialized','params':{}}))

    def test_capabilities_explicitly_excludes_repair(self):
        data=self.call('openline_capabilities',{})['result']['structuredContent']
        self.assertEqual(data['autonomous_repair'],'NOT_AVAILABLE')
        self.assertEqual(data['protected_effect_permission'],'NONE')

    def test_check_allows_only_pinned_profile_and_emits_record(self):
        r=self.call('openline_check',{'profile':'commit'})['result']
        self.assertFalse(r['isError'])
        out=r['structuredContent']
        self.assertEqual(out['result']['decision'],'COMMIT')
        self.assertEqual(out['runtime_permission'],'NONE')
        args=json.loads((self.root/'.records'/out['record_id']/'arguments.json').read_text())
        self.assertIn('--gate-key',args)
        self.assertEqual(args[args.index('--gate-id')+1],'real-receiver-identity')

    def test_denied_and_quarantined_are_normal_decisions(self):
        for name, decision in [('deny','DENY'),('quarantine','QUARANTINE')]:
            with self.subTest(name=name):
                r=self.call('openline_check',{'profile':name})['result']
                self.assertFalse(r['isError'])
                self.assertEqual(r['structuredContent']['result']['decision'], decision)

    def test_impact_returns_no_effect_permission(self):
        r=self.call('openline_impact',{'profile':'impact'})['result']
        self.assertFalse(r['isError'])
        d=r['structuredContent']
        self.assertEqual(d['result']['result']['reopen'],['a'])
        self.assertEqual(d['runtime_permission'],'NONE')

    def test_injection_fields_are_refused_without_running_cli(self):
        cases=[{'profile':'commit','policy':'other.json'},
               {'profile':'../../evil'}, {'profile':'commit','gate_key':'bad'},
               {'profile':'commit','command':['sh','-c','id']},
               {'profile':5}, {'profile':'not-configured'}, {}, []]
        for data in cases:
            with self.subTest(data=data):
                r=self.call('openline_check',data)['result']
                self.assertTrue(r['isError'])
        self.assertFalse((self.root/'.records').exists())

    def test_cli_errors_not_promoted_to_decisions(self):
        for name in ['mismatch','ephemeral','bad-json','error']:
            with self.subTest(name=name):
                r=self.call('openline_check',{'profile':name})['result']
                self.assertTrue(r['isError'])
                self.assertEqual(r['structuredContent']['runtime_permission'],'NONE')

    def test_missing_gate_key_refuses_check_profiles(self):
        del self.raw['gate_key']; self.save_config()
        with self.assertRaises(ConfigurationError):OperatorConfig.load(self.config)

    def test_config_cannot_escape_records_dir(self):
        self.raw['records_dir']='../out';self.save_config()
        with self.assertRaises(ConfigurationError):OperatorConfig.load(self.config)

    def test_config_rejects_unknown_fields(self):
        self.raw['authorized_effects']=True;self.save_config()
        with self.assertRaises(ConfigurationError):OperatorConfig.load(self.config)

    def test_operator_pack_must_exist(self):
        self.raw['check_profiles']['commit']='absent.json';self.save_config()
        with self.assertRaises(ConfigurationError):OperatorConfig.load(self.config)

    def test_unauthorized_tool_name_refused(self):
        r=self.call('openline_repair',{'profile':'commit'})
        self.assertEqual(r['error']['code'],-32602)

    def test_stdio_end_to_end_handshake_and_denial(self):
        env={**os.environ,'OPENLINE_MCP_CONFIG':str(self.config)}
        commands=[{'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2025-11-25'}},
                  {'jsonrpc':'2.0','method':'notifications/initialized'},
                  {'jsonrpc':'2.0','id':2,'method':'tools/list','params':{}},
                  {'jsonrpc':'2.0','id':3,'method':'tools/call','params':{'name':'openline_check','arguments':{'profile':'deny'}}}]
        p=subprocess.run([sys.executable,'-m','openline_mcp_entry.server'],
                         input='\n'.join(json.dumps(x) for x in commands)+'\n',
                         text=True,capture_output=True,env=env,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr)
        replies=[json.loads(line) for line in p.stdout.splitlines()]
        self.assertEqual(len(replies),3)
        self.assertEqual(replies[2]['result']['structuredContent']['result']['decision'],'DENY')
        self.assertNotIn('Traceback',p.stderr)


if __name__=='__main__':unittest.main()
