import ast
import base64
from contextlib import closing
import errno
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'adapter'))
sys.path.insert(0, str(ROOT / 'scripts'))
from rc5_paths import load
RC5 = load(ROOT.parents[1])
from backup_restore_rehearsal import bootstrap_isolated_deployment, _sig
from receiver_service import OpenLineReceiverService
from ipc_client import OpenLineIPCClient
from ipc_protocol import sign_ipc_request, canonical_json_bytes
from protect import ProtectError, verify_receipt
from validation_runner import ValidationJob, compute_validation_context_sha256
from validator import PROFILE, SocketValidationRunner, run_static
from receiver import validate_production_entrypoint
from gateway import Gateway, client_context, exchange
from make_test_pki import generate
from wire import canonical, send, recv, digest, strict
import durable_io
from vm_profile import domain, audit_domain

EVIDENCE = ROOT / 'evidence/software'
EVIDENCE.mkdir(parents=True, exist_ok=True)


def wait_for(fn, timeout=4):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if fn():
            return
        time.sleep(0.02)
    raise TimeoutError('service not ready')


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='olvm-')
        self.base = Path(self.tmp.name)
        self.base.chmod(0o755)
        self.env = bootstrap_isolated_deployment(self.base / 'fixture')
        self.cfg = self.env['config']
        self.native_openat2 = durable_io.kernel_supports_native_openat2()
        if not self.native_openat2:
            self.cfg['allow_enosys_openat2_fallback'] = True

        self.vdir = self.base / 'validator'
        self.vdir.mkdir(mode=0o700)
        self.sockdir = self.base / 'vs'
        self.sockdir.mkdir(mode=0o755)
        self.vsock = self.sockdir / 'v.sock'
        self.vlog = (self.base / 'validator.log').open('wb')

        # Copy validator runtime scripts into self.base/vbin (0o755) so uid 65534 can read them even if ROOT is under /root (0o700).
        self.vbin = self.base / 'vbin'
        self.vbin.mkdir(mode=0o755)
        for fname in ('validator.py', 'wire.py'):
            dst = self.vbin / fname
            shutil.copyfile(ROOT / 'adapter' / fname, dst)
            dst.chmod(0o755 if fname == 'validator.py' else 0o644)
        checker_copy = self.vbin / 'validator_contract.py'
        shutil.copyfile(self.cfg['paths']['validator_script'], checker_copy)
        checker_copy.chmod(0o644)
        self.cfg['paths']['validator_script'] = str(checker_copy)

        self.has_root_uid_switch = (os.getuid() == 0)
        if self.has_root_uid_switch:
            try:
                os.chown(self.vdir, 65534, 65534)
                os.chown(self.sockdir, 65534, 65534)
            except OSError:
                self.has_root_uid_switch = False

        if self.has_root_uid_switch:
            self.expected_validator_uid = 65534
            self.vproc = subprocess.Popen(
                [
                    sys.executable,
                    '-B',
                    str(self.vbin / 'validator.py'),
                    '--socket',
                    str(self.vsock),
                    '--receiver-uid',
                    str(os.getuid()),
                    '--checker',
                    str(checker_copy),
                    '--workdir',
                    str(self.vdir),
                ],
                user=65534,
                group=65534,
                extra_groups=[],
                stdout=self.vlog,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            self.runner = SocketValidationRunner(
                self.vsock,
                65534,
                checker_copy,
                allow_single_uid_test_harness=False,
                require_native_openat2=self.native_openat2,
            )
        else:
            self.expected_validator_uid = os.getuid()
            self.vproc = subprocess.Popen(
                [
                    sys.executable,
                    '-B',
                    str(self.vbin / 'validator.py'),
                    '--socket',
                    str(self.vsock),
                    '--receiver-uid',
                    str(os.getuid()),
                    '--checker',
                    str(checker_copy),
                    '--workdir',
                    str(self.vdir),
                    '--allow-single-uid-test-harness',
                ],
                stdout=self.vlog,
                stderr=subprocess.STDOUT,
                close_fds=True,
            )
            self.runner = SocketValidationRunner(
                self.vsock,
                os.getuid(),
                checker_copy,
                allow_single_uid_test_harness=True,
                require_native_openat2=self.native_openat2,
            )

        wait_for(lambda: self.vsock.exists() or self.vproc.poll() is not None)
        if self.vproc.poll() is not None:
            raise RuntimeError((self.base / 'validator.log').read_text())

        self.svc = OpenLineReceiverService(self.cfg, validation_runner=self.runner, require_distinct_uids=False)
        self.runner.abort_check = self.svc._should_abort_validation
        self.svc.start_background()
        pins = generate(self.base / 'pki')
        self.pins = pins
        self.gcfg = {
            'bind': '127.0.0.1',
            'port': 0,
            'cert': str(self.base / 'pki/server.pem'),
            'key': str(self.base / 'pki/server.key'),
            'ca': str(self.base / 'pki/ca.pem'),
            'client_cert_sha256': pins['worker'],
            'principal_id': 'worker:bob',
            'deployment_id': self.cfg['deployment_id'],
            'project_id': self.cfg['project_id'],
            'receiver_id': self.cfg['receiver_id'],
            'worker_socket': self.cfg['paths']['worker_socket'],
            'receiver_uid': os.getuid(),
            'receiver_pub': self.cfg['receiver_pub'],
        }
        self.gate = Gateway(self.gcfg)
        self.gt = threading.Thread(target=self.gate.serve, daemon=True)
        self.gt.start()
        wait_for(lambda: hasattr(self.gate, 'port'))
        self.ctx = client_context(
            str(self.base / 'pki/ca.pem'),
            str(self.base / 'pki/worker.pem'),
            str(self.base / 'pki/worker.key'),
        )
        self.obs = []

    def tearDown(self):
        if hasattr(self, 'gate'):
            self.gate.stop()
            self.gt.join(timeout=2)
        if hasattr(self, 'svc'):
            self.svc.stop()
        if hasattr(self, 'vproc'):
            self.vproc.terminate()
            self.vproc.wait(timeout=3)
            self.vlog.close()
        if hasattr(self, 'obs'):
            (EVIDENCE / (self.id().split('.')[-1] + '.json')).write_text(json.dumps(self.obs, indent=2) + '\n')
        if hasattr(self, 'tmp'):
            self.tmp.cleanup()

    def envelope(self, op, payload=None, **kw):
        return sign_ipc_request(
            self.env['bob_key'],
            deployment_id=kw.pop('deployment_id', self.cfg['deployment_id']),
            project_id=kw.pop('project_id', self.cfg['project_id']),
            receiver_id=kw.pop('receiver_id', self.cfg['receiver_id']),
            channel=kw.pop('channel', 'worker'),
            request_id=kw.pop('request_id', 'r-' + os.urandom(8).hex()),
            principal_id=kw.pop('principal_id', 'worker:bob'),
            operation=op,
            payload=payload or {},
            **kw,
        )

    def call(self, op, payload=None, env=None, **kw):
        req = env or self.envelope(op, payload, **kw)
        r = exchange('127.0.0.1', self.gate.port, self.ctx, req, self.cfg['receiver_pub'])
        self.obs.append({'operation': op, 'response': r})
        return r

    def control(self, who, op, payload):
        c = OpenLineIPCClient(
            socket_path=self.cfg['paths']['control_socket'],
            channel='control',
            deployment_id=self.cfg['deployment_id'],
            project_id=self.cfg['project_id'],
            receiver_id=self.cfg['receiver_id'],
            principal_id='control:' + who,
            signer_key=self.env[who + '_key'],
            pinned_receiver_pub=self.cfg['receiver_pub'],
        )
        r = c.call(op, payload)
        self.obs.append({'control': op, 'response': r})
        return r

    def assign(self, name='repair-1'):
        claim = {
            'project_id': self.cfg['project_id'],
            'assignment_id': name,
            'deliverable_id': 'invoice-feature',
            'worker_member': 'bob',
            'basis': 'invoice_v2',
            'allowed_paths': ['app/price.py'],
            'action': 'repair_assignment',
        }
        payload = {k: v for k, v in claim.items() if k not in ('project_id', 'action')}
        payload['contributor_signature'] = _sig(self.env['alice_key'], claim)
        self.assertEqual(self.control('alice', 'control.assign', payload)['status'], 'OK')
        return self.call('assignment.prepare', {'assignment_id': name})

    def proposal(self, name='repair-1', content=b'def total(qty):\n    return qty * 11\n', path='app/price.py'):
        return {
            'assignment_id': name,
            'files': [
                {
                    'path': path,
                    'op': 'upsert',
                    'mode': '100644',
                    'sha256': digest(content),
                    'content_b64': base64.b64encode(content).decode(),
                }
            ],
        }

    def observe(self):
        # Receiver-side target existence and logical authority state, not guest assertions.
        p = self.cfg['paths']
        for key in ('receiver_key_file', 'accepted_git', 'project_db', 'effects_db'):
            self.assertTrue(Path(p[key]).exists(), key)
        with sqlite3.connect(p['effects_db']) as db:
            effects = db.execute('SELECT * FROM effects ORDER BY id').fetchall()
        result = {
            'key_sha256': digest(Path(p['receiver_key_file']).read_bytes()),
            'accepted': self.svc.promotion.accepted(),
            'stop': self.svc.project.read_stop_state(),
            'effects': effects,
        }
        self.obs.append({'receiver_observation': result})
        return result

    def test_authorized_repair_signed_receipt_and_real_validator_uid(self):
        before = self.observe()
        self.assertEqual(self.assign()['status'], 'OK')
        r = self.call('proposal.submit', self.proposal())
        self.assertEqual(r['status'], 'ACCEPTED', r)
        after = self.observe()
        self.assertNotEqual(before['accepted'], after['accepted'])
        self.assertEqual(before['key_sha256'], after['key_sha256'])
        self.assertEqual(before['effects'], after['effects'])
        v = verify_receipt(
            r['result']['receipt'],
            self.cfg['receiver_pub'],
            accepted_git=Path(self.cfg['paths']['accepted_git']),
            project_db=Path(self.cfg['paths']['project_db']),
        )
        self.obs.append({'independent_receipt_verification': v})
        self.assertEqual(v['crypto'], 'VERIFIED')
        self.assertTrue(v['git_verified'])
        self.assertTrue(v['continuity_verified'])
        state = json.loads((Path(self.cfg['paths']['promotion_dir']) / 'task-repair-1/state.json').read_text())
        self.assertEqual(state['verification']['validator_uid'], self.expected_validator_uid)
        self.assertEqual(state['verification']['validator_pid'], self.vproc.pid)
        self.assertNotEqual(state['verification']['validator_pid'], os.getpid())
        if self.has_root_uid_switch:
            self.assertNotEqual(state['verification']['validator_uid'], os.getuid())
        self.obs.append({
            'kernel_checked_validator': state['verification'],
            'multi_uid_host_support': self.has_root_uid_switch,
            'native_openat2_kernel_support': self.native_openat2,
        })

    def test_forged_expired_nonce_and_conflicting_requests(self):
        before = self.observe()
        env = self.envelope('project.status')
        env['signature'] = '00' * 64
        self.assertEqual(self.call('project.status', env=env)['code'], 'SIGNATURE_INVALID')
        now = int(time.time())
        self.assertEqual(self.call('project.status', issued_at=now - 10, expires_at=now - 1)['code'], 'EXPIRED_REQUEST')
        first = self.envelope('project.status', request_id='fixed', nonce='f' * 32)
        self.assertEqual(self.call('project.status', env=first)['status'], 'OK')
        self.assertTrue(self.call('project.status', env=first)['replayed'])
        self.assertEqual(self.call('project.status', request_id='other', nonce='f' * 32)['code'], 'NONCE_REPLAY')
        self.assertEqual(self.call('project.status', {'changed': 1}, request_id='fixed', nonce='f' * 32)['code'], 'IDEMPOTENCY_CONFLICT')
        self.assertEqual(before, self.observe())

    def test_tls_bad_certificate_control_lane_and_truncated_transport(self):
        before = self.observe()
        other = client_context(
            str(self.base / 'pki/ca.pem'),
            str(self.base / 'pki/other.pem'),
            str(self.base / 'pki/other.key'),
        )
        with self.assertRaises((OSError, EOFError)):
            exchange('127.0.0.1', self.gate.port, other, self.envelope('project.status'), self.cfg['receiver_pub'])
        with self.assertRaises((OSError, EOFError)):
            self.call('control.stop', {'reason': 'guest root is not owner'})
        for data in [struct.pack('!I', 99999999), struct.pack('!I', 100) + b'{', struct.pack('!I', 13) + b'{"a":1,"a":2}']:
            with socket.create_connection(('127.0.0.1', self.gate.port), timeout=3) as raw:
                with self.ctx.wrap_socket(raw, server_hostname='openline.local') as s:
                    s.settimeout(1.0)
                    s.sendall(data)
                    try:
                        s.recv(1)
                    except OSError:
                        pass
        self.assertEqual(before, self.observe())
        self.assertEqual(self.call('project.status')['status'], 'OK')

    def test_out_of_scope_and_executable_candidate_denied(self):
        self.assign()
        before = self.observe()
        out = self.call('proposal.submit', self.proposal(path='../keys/receiver.key'))
        self.assertNotEqual(out['status'], 'ACCEPTED')
        bad = self.call('proposal.submit', self.proposal(content=b'import os\nos.system("true")\n'))
        self.assertNotEqual(bad['status'], 'ACCEPTED')
        self.assertEqual(before, self.observe())

    def test_stop_clear_does_not_resurrect_assignment(self):
        self.assign()
        before = self.observe()
        epoch = before['stop']['epoch']
        claim = {'project_id': self.cfg['project_id'], 'action': 'issue_stop', 'reason': 'fixture', 'expected_epoch': epoch}
        r = self.control('owner', 'control.stop', {'reason': 'fixture', 'expected_epoch': epoch, 'owner_signature': _sig(self.env['owner_key'], claim)})
        self.assertEqual(r['status'], 'OK', r)
        stopped = self.observe()
        self.assertNotEqual(stopped['stop'], before['stop'])
        self.assertNotEqual(self.call('proposal.submit', self.proposal())['status'], 'ACCEPTED')
        epoch = stopped['stop']['epoch']
        claim.update(action='clear_stop', expected_epoch=epoch)
        r = self.control('owner', 'control.clear', {'reason': 'fixture', 'expected_epoch': epoch, 'owner_signature': _sig(self.env['owner_key'], claim)})
        self.assertEqual(r['status'], 'OK', r)
        self.assertNotEqual(self.call('proposal.submit', self.proposal())['status'], 'ACCEPTED')
        self.assertEqual(before['accepted'], self.observe()['accepted'])

    def test_revoked_member_and_stale_worker_key(self):
        env = self.envelope('project.status')
        self.assertEqual(self.call('project.status', env=env)['status'], 'OK')
        claim = {'project_id': self.cfg['project_id'], 'member_id': 'bob', 'action': 'revoke_member'}
        r = self.control('owner', 'control.revoke_member', {'member_id': 'bob', 'owner_signature': _sig(self.env['owner_key'], claim)})
        self.assertEqual(r['status'], 'OK', r)
        self.assertEqual(self.call('project.status', env=env)['code'], 'MEMBER_REVOKED')
        self.assertEqual(self.call('project.status')['code'], 'MEMBER_REVOKED')

    def test_receiver_restart_preserves_replay_ledger_and_receipts(self):
        self.assign()
        env = self.envelope('proposal.submit', self.proposal())
        first = self.call('proposal.submit', env=env)
        self.assertEqual(first['status'], 'ACCEPTED', first)
        before = self.observe()
        self.svc.stop()
        self.runner = SocketValidationRunner(
            self.vsock,
            self.expected_validator_uid,
            self.cfg['paths']['validator_script'],
            allow_single_uid_test_harness=not self.has_root_uid_switch,
            require_native_openat2=self.native_openat2,
        )
        self.svc = OpenLineReceiverService(self.cfg, validation_runner=self.runner, require_distinct_uids=False)
        self.runner.abort_check = self.svc._should_abort_validation
        self.svc.start_background()
        second = self.call('proposal.submit', env=env)
        self.assertTrue(second['replayed'])
        self.assertEqual(first['receipt_sha256'], second['receipt_sha256'])
        self.assertEqual(before, self.observe())

    def test_validator_unavailable_fails_closed(self):
        self.assign()
        before = self.observe()
        self.vproc.terminate()
        self.vproc.wait(timeout=3)
        r = self.call('proposal.submit', self.proposal())
        self.assertNotEqual(r['status'], 'ACCEPTED')
        self.assertEqual(before, self.observe())

    def test_validator_cannot_open_existing_receiver_targets(self):
        paths = self.cfg['paths']
        targets = [paths[k] for k in ('receiver_key_file', 'project_db', 'effects_db')] + [str(Path(paths['accepted_git']) / 'HEAD')]
        for path in targets:
            self.assertTrue(Path(path).is_file())
        script = (
            'import os,json,sys\nr=[]\nfor p in sys.argv[1:]:\n'
            ' for flag in (os.O_RDONLY,os.O_WRONLY):\n'
            '  try:\n   f=os.open(p,flag);os.close(f);r.append({"path":p,"mode":flag,"opened":True})\n'
            '  except OSError as e:r.append({"path":p,"mode":flag,"opened":False,"errno":e.errno})\n'
            'print(json.dumps({"uid":os.getuid(),"results":r}))'
        )
        if self.has_root_uid_switch:
            out = subprocess.run(
                [sys.executable, '-I', '-c', script, *targets],
                user=65534,
                group=65534,
                extra_groups=[],
                capture_output=True,
                text=True,
                check=True,
            )
            evidence = json.loads(out.stdout)
            self.obs.append(evidence)
            self.assertEqual(evidence['uid'], 65534)
            self.assertTrue(all(not x['opened'] and x['errno'] == 13 for x in evidence['results']))
        else:
            # Verify EPERM blocker on user=65534 in unprivileged single-UID container, plus validator protocol path refusal.
            with self.assertRaises(PermissionError) as ctx:
                subprocess.run(
                    [sys.executable, '-I', '-c', 'pass'],
                    user=65534,
                    group=65534,
                    extra_groups=[],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            for bad_target in targets:
                bad_req = {
                    'schema': 'openline.vm.validation.v1',
                    'job_id': 'j-bad',
                    'assignment': 'repair-1',
                    'expected_head': '0' * 40,
                    'proposed_head': '1' * 40,
                    'context_sha256': '0' * 64,
                    'profile': PROFILE,
                    'files': {bad_target: base64.b64encode(b'x').decode(), 'app/independent.py': base64.b64encode(b'x').decode()},
                    'project_snapshot': base64.b64encode(b'x').decode(),
                    'effects_snapshot': base64.b64encode(b'x').decode(),
                }
                with self.assertRaises(ValueError):
                    run_static(bad_req, self.cfg['paths']['validator_script'], str(self.vdir), None)
            self.obs.append({
                'multi_uid_dac_probe': 'NOT_TESTED_IN_SINGLE_UID_CONTAINER',
                'container_uid': os.getuid(),
                'setresuid_65534_errno': ctx.exception.errno,
                'validator_protocol_target_path_refusal': 'VERIFIED',
            })

    def test_gateway_rejects_malformed_and_cross_project_envelopes_before_backend(self):
        before = self.observe()
        forwards_before = self.gate.backend_forwards

        # 1. Cross-project / cross-deployment / wrong-receiver envelopes must be dropped at the gateway before backend connect.
        for bad_kw in (
            {'project_id': 'other-project'},
            {'deployment_id': 'other-deploy'},
            {'receiver_id': 'other-receiver'},
            {'principal_id': 'worker:alice'},
            {'channel': 'control'},
        ):
            bad_env = self.envelope('project.status', **bad_kw)
            with self.assertRaises((OSError, EOFError)):
                exchange('127.0.0.1', self.gate.port, self.ctx, bad_env, self.cfg['receiver_pub'])

        # 2. Tampered payload_sha256 or missing request_id must be dropped before backend connect.
        tampered = self.envelope('project.status', {'a': 1})
        tampered['payload'] = {'a': 2}
        with self.assertRaises((OSError, EOFError)):
            exchange('127.0.0.1', self.gate.port, self.ctx, tampered, self.cfg['receiver_pub'])

        missing_req_id = dict(self.envelope('project.status'))
        missing_req_id.pop('request_id', None)
        with socket.create_connection(('127.0.0.1', self.gate.port), timeout=3) as raw:
            with self.ctx.wrap_socket(raw, server_hostname='openline.local') as s:
                s.settimeout(1.0)
                send(s, canonical(missing_req_id))
                with self.assertRaises((OSError, EOFError)):
                    recv(s, timeout=1.0)

        self.assertEqual(self.gate.backend_forwards, forwards_before)
        self.assertEqual(before, self.observe())

        # 3. Gateway constructor refuses non-worker principal_id.
        bad_gcfg = dict(self.gcfg, principal_id='control:owner')
        with self.assertRaises(PermissionError):
            Gateway(bad_gcfg)

    def test_validator_rejects_context_mismatch_tree_mutation_and_extra_worktree_files(self):
        # 1. Context SHA-256 mismatch inside validator.run_static must be refused.
        proj_bytes = Path(self.cfg['paths']['project_db']).read_bytes()
        eff_bytes = Path(self.cfg['paths']['effects_db']).read_bytes()
        bad_ctx_req = {
            'schema': 'openline.vm.validation.v1',
            'job_id': 'j-ctx',
            'assignment': 'repair-1',
            'expected_head': '0' * 40,
            'proposed_head': '1' * 40,
            'context_sha256': 'f' * 64,
            'profile': PROFILE,
            'files': {
                'app/price.py': base64.b64encode(b'def total(qty):\n    return qty * 11\n').decode(),
                'app/independent.py': base64.b64encode(b'def label(value):\n    return value.upper()\n').decode(),
            },
            'project_snapshot': base64.b64encode(proj_bytes).decode(),
            'effects_snapshot': base64.b64encode(eff_bytes).decode(),
        }
        with self.assertRaises(ValueError) as ctx_err:
            run_static(bad_ctx_req, self.cfg['paths']['validator_script'], str(self.vdir), None)
        self.assertIn('context_sha256 mismatch', str(ctx_err.exception))

        # 2. Extra unauthorized file in merged_worktree must be refused by SocketValidationRunner.
        wt = self.base / 'bad_wt'
        (wt / 'app').mkdir(parents=True)
        (wt / 'app/price.py').write_text('def total(qty):\n    return qty * 11\n')
        (wt / 'app/independent.py').write_text('def label(value):\n    return value.upper()\n')
        (wt / 'app/extra_backdoor.py').write_text('x = 1\n')
        job = ValidationJob(
            job_id='j-extra',
            assignment_id='repair-1',
            merged_worktree=wt,
            project_db=Path(self.cfg['paths']['project_db']),
            effects_snapshot_db=Path(self.cfg['paths']['effects_db']),
            validator_script=Path(self.cfg['paths']['validator_script']),
            proposed_head='1' * 40,
            expected_head='0' * 40,
            timeout_s=5.0,
        )
        outcome = self.runner.run(job)
        self.assertFalse(outcome.passed)
        self.assertIn('unexpected files in merged_worktree', outcome.reason)
        self.obs.append({'extra_file_outcome': outcome.reason})

    def test_conventional_baseline_parity(self):
        # Conventional baseline: direct AST contract check + SHA-256 digest verification on valid & invalid proposals.
        valid_src = b'def total(qty):\n    return qty * 11\n'
        invalid_src = b'def total(qty):\n    return qty * 99\n'

        def conventional_check(price_bytes, expected_total=22):
            tree = ast.parse(price_bytes.decode('utf-8'))
            if len(tree.body) != 1 or not isinstance(tree.body[0], ast.FunctionDef) or tree.body[0].name != 'total':
                return False
            stmt = tree.body[0].body[0]
            if not (isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.BinOp) and isinstance(stmt.value.right, ast.Constant)):
                return False
            return (2 * stmt.value.right.value) == expected_total

        self.assign('repair-parity')
        r_bad = self.call('proposal.submit', self.proposal('repair-parity', content=invalid_src))
        self.assertFalse(conventional_check(invalid_src))
        self.assertNotEqual(r_bad['status'], 'ACCEPTED')

        r_good = self.call('proposal.submit', self.proposal('repair-parity', content=valid_src))
        self.assertTrue(conventional_check(valid_src))
        self.assertEqual(r_good['status'], 'ACCEPTED')
        self.obs.append({
            'conventional_baseline': 'PARITY',
            'invalid_rejected_both': r_bad['status'] != 'ACCEPTED',
            'valid_accepted_both': r_good['status'] == 'ACCEPTED',
        })

    def test_overnight_guest_root_five_targets_and_snapshot_chunk_gates(self):
        # Exercises all 5 priority guest-root attack targets (keys, Git, DBs, STOP authority, effects)
        # plus OVN-01 (snapshot.chunk preliminary_admit & CandidateTransferError idempotency finalization).
        self.assign('repair-ovn')
        before = self.observe()

        # 1. Legitimate snapshot.chunk read works before STOP
        ok_chunk = self.call('snapshot.chunk', {'assignment_id': 'repair-ovn', 'target': 'app/price.py', 'offset': 0, 'length': 64})
        self.assertEqual(ok_chunk['status'], 'OK', ok_chunk)

        # 2. Target 1 & 2 & 3: snapshot.chunk path traversal to receiver.key, accepted.git/HEAD, project.sqlite -> signed REFUSED (OUT_OF_SCOPE_PATH)
        for bad_target in ('../keys/receiver.key', '.git/HEAD', '../accepted.git/HEAD', '../project.sqlite', '../effects.sqlite'):
            env_bad = self.envelope('snapshot.chunk', {'assignment_id': 'repair-ovn', 'target': bad_target, 'offset': 0, 'length': 32})
            r_bad = self.call('snapshot.chunk', env=env_bad)
            self.assertEqual(r_bad['status'], 'REFUSED', r_bad)
            self.assertEqual(r_bad['code'], 'OUT_OF_SCOPE_PATH', r_bad)
            # Replaying the exact same request returns replayed=True (proving OVN-01 idempotency finalization!)
            r_replay = self.call('snapshot.chunk', env=env_bad)
            self.assertTrue(r_replay['replayed'], r_replay)

        # 3. Boolean offset coercion attempt in snapshot.chunk -> signed REFUSED (MALFORMED_ENVELOPE)
        r_bool = self.call('snapshot.chunk', {'assignment_id': 'repair-ovn', 'target': 'app/price.py', 'offset': True, 'length': 16})
        self.assertEqual(r_bool['status'], 'REFUSED', r_bool)
        self.assertEqual(r_bool['code'], 'MALFORMED_ENVELOPE', r_bool)

        # 4. Target 4: All control-lane operations attempted over worker gateway are dropped pre-backend
        forwards_before = self.gate.backend_forwards
        for ctrl_op in ('control.stop', 'control.clear', 'control.assign', 'control.revoke_member', 'control.rotate_key', 'control.backup'):
            with self.assertRaises((OSError, EOFError)):
                self.call(ctrl_op, {'reason': 'guest-root-attempt'})
        self.assertEqual(self.gate.backend_forwards, forwards_before)

        # 5. Issue legitimate owner STOP and verify snapshot.chunk is now REFUSED on the stopped project (OVN-01)
        epoch = before['stop']['epoch']
        claim = {'project_id': self.cfg['project_id'], 'action': 'issue_stop', 'reason': 'ovn-stop', 'expected_epoch': epoch}
        self.assertEqual(self.control('owner', 'control.stop', {'reason': 'ovn-stop', 'expected_epoch': epoch, 'owner_signature': _sig(self.env['owner_key'], claim)})['status'], 'OK')
        after_stop_chunk = self.call('snapshot.chunk', {'assignment_id': 'repair-ovn', 'target': 'app/price.py', 'offset': 0, 'length': 64})
        self.assertEqual(after_stop_chunk['status'], 'REFUSED', after_stop_chunk)

        # 6. Target 5: Verify receiver key, accepted Git ref, and effects DB are untouched
        after = self.observe()
        self.assertEqual(before['key_sha256'], after['key_sha256'])
        self.assertEqual(before['accepted'], after['accepted'])
        self.assertEqual(before['effects'], after['effects'])


class StaticTests(unittest.TestCase):
    def test_native_openat2_unsupported_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'present').write_text('exists')
            with mock.patch.object(durable_io, '_try_native_openat2', return_value=(-1, errno.ENOSYS)):
                with self.assertRaises(durable_io.OpenAt2Error):
                    durable_io.open_beneath(tmp, 'present')
                with self.assertRaises(durable_io.OpenAt2Error):
                    durable_io.read_bytes_beneath(tmp, 'present')

    def test_domain_rejects_shared_mount_host_device_and_management_channel(self):
        xml = domain('/tmp/worker.qcow2', '/tmp/seed.iso')
        self.assertEqual(audit_domain(xml, '/tmp/worker.qcow2', '/tmp/seed.iso')['vm_execution'], 'NOT_TESTED')
        for bad in ['<filesystem/>', '<hostdev/>', '<channel/>', '<vsock/>', '<kernel>/boot/vmlinuz</kernel>', '<loader>/usr/share/OVMF.fd</loader>', '<memoryBacking/>', '<controller type="virtio-serial"/>', '<script path="/bin/sh"/>']:
            with self.assertRaises(ValueError):
                audit_domain(xml.replace('</devices>', bad + '</devices>'), '/tmp/worker.qcow2', '/tmp/seed.iso')
        with self.assertRaises(ValueError):
            audit_domain(xml.replace('<memballoon model="none" />', '<memballoon model="virtio" />'), '/tmp/worker.qcow2', '/tmp/seed.iso')

    def test_validator_cannot_claim_receiver_uid(self):
        with self.assertRaises(PermissionError):
            SocketValidationRunner('/tmp/none', os.getuid(), '/tmp/none')
        with self.assertRaises(PermissionError):
            SocketValidationRunner('/tmp/none', 0, '/tmp/none')
        with self.assertRaises(PermissionError):
            SocketValidationRunner('/tmp/none', True, '/tmp/none')

    def test_contract_changed_events_bound_into_validation_context_and_production_entrypoint_guards(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / 'proj.sqlite'
            with closing(sqlite3.connect(db_path)) as db:
                db.executescript('''
                    CREATE TABLE projects(id TEXT, contract TEXT, status TEXT);
                    CREATE TABLE deliverables(id TEXT, member_id TEXT, standing TEXT);
                    CREATE TABLE dependencies(deliverable_id TEXT, depends_on TEXT);
                    CREATE TABLE dependency_contracts(project_id TEXT, dep_key TEXT, contract TEXT);
                    CREATE TABLE assignments(id TEXT, deliverable_id TEXT, worker_member TEXT, basis TEXT, allowed_paths TEXT, state TEXT);
                    CREATE TABLE members(project_id TEXT, member_id TEXT, owner_pub TEXT, worker_pub TEXT, active INT);
                    CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, payload TEXT);
                ''')
                db.execute("INSERT INTO events(kind, payload) VALUES ('CONTRACT_CHANGED', '{\"contract\":\"invoice_v2\"}')")
                db.commit()
            h1 = compute_validation_context_sha256(db_path)
            with closing(sqlite3.connect(db_path)) as db:
                db.execute("INSERT INTO events(kind, payload) VALUES ('CONTRACT_CHANGED', '{\"contract\":\"invoice_v3\"}')")
                db.commit()
            h2 = compute_validation_context_sha256(db_path)
            self.assertNotEqual(h1, h2)

        # Verify production entrypoint refuses test harness flags and matching validator_uid
        with self.assertRaises(PermissionError):
            validate_production_entrypoint({'allow_single_uid_test_harness': True, 'validator_uid': 65534})
        with self.assertRaises(PermissionError):
            validate_production_entrypoint({'allow_enosys_openat2_fallback': True, 'validator_uid': 65534})
        with self.assertRaises(PermissionError):
            validate_production_entrypoint({'validator_uid': os.getuid()})


if __name__ == '__main__':
    unittest.main(verbosity=2)
