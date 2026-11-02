"""Test generated consumer connector payloads and local read-only MCP probe."""
import json
from pathlib import Path
import shlex
import stat
import tempfile
import unittest
from unittest import mock

from openline_mcp_entry.onboard import generate, probe
from tests.test_entry import FAKE_CLI


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.addCleanup(self.t.cleanup)
        self.home = Path(self.t.name)
        self.cli = self.home / "mock-cli"
        self.cli.write_text(FAKE_CLI)
        self.cli.chmod(self.cli.stat().st_mode | stat.S_IXUSR)
        (self.home / 'check.json').write_text(json.dumps({'mode':'deny'}))
        (self.home / 'impact.json').write_text(json.dumps({'mode':'impact'}))
        (self.home / 'gate.key').write_text('fake-key')
        self.config = self.home / 'operator.json'
        self.config.write_text(json.dumps({
          'schema':'openline.mcp-entry.operator.v1',
          'check_profiles':{'test-check':'check.json'},
          'impact_profiles':{'test-impact':'impact.json'},
          'gate_key':'gate.key','records_dir':'.records',
          'check_binary':str(self.cli),'impact_binary':str(self.cli)
        }))

    def test_cursor_config_matches_host_format(self):
        value = json.loads(generate('cursor', str(self.config)))
        e = value['mcpServers']['openline-local']
        self.assertEqual(e['args'], ['-m','openline_mcp_entry.server'])
        self.assertEqual(e['env']['OPENLINE_MCP_CONFIG'], str(self.config))

    def test_claude_desktop_config_matches_host_format(self):
        value = json.loads(generate('claude-desktop', str(self.config), 'my-openline'))
        self.assertEqual(list(value['mcpServers']), ['my-openline'])

    def test_codex_uses_official_stdio_mcp_add(self):
        command = shlex.split(generate('codex', str(self.config)))
        self.assertEqual(command[:4], ['codex','mcp','add','openline-local'])
        self.assertIn('--env', command)
        self.assertEqual(command[command.index('--')+1:][-2:], ['-m','openline_mcp_entry.server'])

    def test_bad_server_name_refused(self):
        for name in ['../../openline', 'anything; rm -rf /', '']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                generate('cursor', str(self.config), name)

    def test_nonexistent_config_refused(self):
        with self.assertRaises(FileNotFoundError):
            generate('codex', str(self.home/'absent.json'))

    def test_probe_real_stdio_handshake_with_fake_engine(self):
        result = probe(str(self.config))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['scope'], 'LOCAL_CAPABILITY_ONLY')
        self.assertFalse(result['real_signed_check_executed'])
        self.assertFalse((self.home/'.records').exists())

    def test_probe_failure_is_not_pass(self):
        with mock.patch('openline_mcp_entry.onboard.subprocess.run', side_effect=OSError('no executable')):
            with self.assertRaisesRegex(ValueError, 'mcp_probe_process_failed'):
                probe(str(self.config))

if __name__=='__main__': unittest.main()
