"""Tests for scripts/asgctl.py: read-only behaviour, fail-closed handling, and no secret leakage."""
import contextlib
import http.server
import io
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import asgctl  # noqa: E402


def serve(body, status=200):
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            data = json.dumps(body).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class AsgctlTests(unittest.TestCase):
    def test_role_files_are_valid_and_use_known_check_types(self):
        for path in (ROOT / 'setup' / 'roles').glob('*.json'):
            role = json.loads(path.read_text(encoding='utf-8'))
            self.assertEqual(role['role'], path.stem)
            for section in ('doctor', 'verify'):
                ids = [c['id'] for c in role.get(section, [])]
                self.assertEqual(len(ids), len(set(ids)), f'duplicate ids in {path.name}:{section}')
                for check in role.get(section, []):
                    self.assertIn(check['type'], asgctl.CHECKS, f'{path.name}: {check["id"]}')
            known = {c['id'] for s in ('doctor', 'verify') for c in role.get(s, [])}
            for step in role.get('steps', []):
                for need in step.get('needs', []):
                    self.assertIn(need, known)

    def test_unknown_check_type_fails_closed(self):
        out = asgctl.run_checks([{'id': 'x', 'type': 'definitely_not_a_check'}])
        self.assertEqual(out[0]['status'], 'fail')
        self.assertFalse(asgctl.summarize(out)['healthy'])

    def test_bad_or_unknown_role_is_rejected(self):
        for name in ('../hub', 'HUB', 'nope-role'):
            with self.assertRaises(SystemExit):
                asgctl.load_role(name, ROOT / 'setup' / 'roles')

    def test_env_check_reports_names_never_values(self):
        secret = 'sentinel-value-must-not-appear-1234567890'
        with patch.dict(os.environ, {'ASG_TEST_TOKEN': secret}):
            out = asgctl.check_env_vars({'id': 'e', 'type': 'env_vars', 'names': ['ASG_TEST_TOKEN', 'ASG_TEST_MISSING']})
        text = json.dumps(out)
        self.assertNotIn(secret, text)
        self.assertIn('ASG_TEST_TOKEN', text)
        self.assertEqual(out['status'], 'warn')
        required = asgctl.check_env_vars({'id': 'e', 'type': 'env_vars', 'names': ['ASG_TEST_MISSING'], 'required': True})
        self.assertEqual(required['status'], 'fail')

    def test_listen_flags_exposed_binds_and_accepts_loopback(self):
        spec = {'id': 'l', 'type': 'listen', 'port': 8788, 'expect': 'loopback'}
        with patch.object(asgctl, 'listeners', return_value=['0.0.0.0']):
            self.assertEqual(asgctl.check_listen(spec)['status'], 'fail')
        with patch.object(asgctl, 'listeners', return_value=['127.0.0.1']):
            self.assertEqual(asgctl.check_listen(spec)['status'], 'ok')
        with patch.object(asgctl, 'listeners', return_value=['127.0.0.1', '192.0.2.5']):
            self.assertEqual(asgctl.check_listen(spec)['status'], 'fail')
        with patch.object(asgctl, 'listeners', return_value=[]):
            self.assertEqual(asgctl.check_listen(spec)['status'], 'warn')

    def test_http_probes_only_touch_loopback(self):
        out = asgctl.check_http_health({'id': 'h', 'type': 'http_health', 'url': 'http://192.0.2.1:8788/healthz'})
        self.assertEqual(out['status'], 'fail')
        self.assertIn('ValueError', out['detail'])

    def test_http_health_accepts_gateway_and_rejects_others(self):
        good = serve({'app': 'agent-security-gateway', 'ok': True, 'routes': 3})
        bad = serve({'app': 'something-else', 'ok': True})
        down = serve({'app': 'agent-security-gateway', 'ok': False})
        self.addCleanup(lambda: [(s.shutdown(), s.server_close()) for s in (good, bad, down)])
        spec = lambda s: {'id': 'h', 'type': 'http_health', 'app': 'agent-security-gateway',
                          'url': f'http://127.0.0.1:{s.server_address[1]}/healthz'}
        self.assertEqual(asgctl.check_http_health(spec(good))['status'], 'ok')
        self.assertEqual(asgctl.check_http_health(spec(bad))['status'], 'fail')
        self.assertEqual(asgctl.check_http_health(spec(down))['status'], 'fail')

    def test_firewall_rule_check_requires_inbound_enabled_block_for_the_lab_subnet(self):
        spec = {'id': 'f', 'type': 'firewall_rule', 'name': 'r', 'remote_address': '172.29.91.0/29'}
        good = {'enabled': 'True', 'direction': 'Inbound', 'action': 'Block', 'remote': '172.29.91.0/255.255.255.248'}
        with patch.object(asgctl, 'IS_WINDOWS', True):
            with patch.object(asgctl, 'ps_json', return_value=(good, '')):
                self.assertEqual(asgctl.check_firewall_rule(spec)['status'], 'ok')
            for patch_ in ({'enabled': 'False'}, {'action': 'Allow'}, {'direction': 'Outbound'}, {'remote': '10.0.0.0/8'}):
                with patch.object(asgctl, 'ps_json', return_value=({**good, **patch_}, '')):
                    self.assertEqual(asgctl.check_firewall_rule(spec)['status'], 'fail', patch_)
            with patch.object(asgctl, 'ps_json', return_value=(None, '')):
                self.assertEqual(asgctl.check_firewall_rule(spec)['status'], 'fail')

    def test_vm_check_flags_extra_integration_services_and_missing_checkpoint(self):
        spec = {'id': 'v', 'type': 'hyperv_vm', 'name': 'x', 'switch_type': 'Internal', 'checkpoint': 'baseline-clean'}
        good = {'state': 'Running', 'auto_cp': False, 'switch_types': ['Internal'],
                'svc': ['Microsoft:abc\\' + asgctl.TIME_SYNC_GUID], 'checkpoints': ['baseline-clean']}
        with patch.object(asgctl, 'IS_WINDOWS', True):
            with patch.object(asgctl, 'ps_json', return_value=(good, '')):
                self.assertEqual(asgctl.check_hyperv_vm(spec)['status'], 'ok')
            for change in ({'switch_types': ['External']}, {'svc': good['svc'] + ['Microsoft:abc\\OTHER']},
                           {'auto_cp': True}, {'checkpoints': []}):
                with patch.object(asgctl, 'ps_json', return_value=({**good, **change}, '')):
                    self.assertEqual(asgctl.check_hyperv_vm(spec)['status'], 'fail', change)

    def test_deep_checks_are_skipped_without_the_flag(self):
        spec = {'id': 'g', 'type': 'guest_egress', 'name': 'x', 'targets': ['172.29.91.1:22'], 'deep': True}
        with patch.object(asgctl, 'IS_WINDOWS', True), patch.object(asgctl, 'lab_ssh') as ssh:
            self.assertEqual(asgctl.check_guest_egress(spec, deep=False)['status'], 'skip')
            ssh.assert_not_called()

    def test_guest_egress_rejects_malformed_targets_and_reports_reachable_hosts(self):
        spec = {'id': 'g', 'type': 'guest_egress', 'name': 'x', 'guest_ip': '172.29.91.2'}
        with patch.object(asgctl, 'IS_WINDOWS', True):
            with self.assertRaises(ValueError):
                asgctl.check_guest_egress({**spec, 'targets': ['1.1.1.1;reboot:22']})
            with patch.object(asgctl, 'lab_ssh', return_value=(0, 'blocked 1.1.1.1:443\nexit=0')):
                self.assertEqual(asgctl.check_guest_egress({**spec, 'targets': ['1.1.1.1:443']})['status'], 'ok')
            with patch.object(asgctl, 'lab_ssh', return_value=(0, 'REACHABLE 172.29.91.1:22\nexit=0')):
                self.assertEqual(asgctl.check_guest_egress({**spec, 'targets': ['172.29.91.1:22']})['status'], 'fail')
            deep_ok = 'REACHABLE 172.29.91.1:22\nfirewall_restored=0\nexit=0'
            with patch.object(asgctl, 'lab_ssh', return_value=(0, deep_ok)):
                out = asgctl.check_guest_egress({**spec, 'targets': ['172.29.91.1:22'], 'deep': True}, deep=True)
                self.assertIn('NOT restored', out['detail'])

    def test_plan_marks_open_steps(self):
        role = {'steps': [{'step': 'a', 'needs': ['x']}, {'step': 'b', 'needs': ['y']}, {'step': 'c', 'manual': True}]}
        plan = asgctl.build_plan(role, [{'id': 'x', 'status': 'ok'}, {'id': 'y', 'status': 'fail'}])
        self.assertEqual([s['state'] for s in plan], ['done', 'todo', 'manual'])

    def test_cli_emits_json_and_exit_code_reflects_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, 'demo.json').write_text(json.dumps({'role': 'demo', 'doctor': [
                {'id': 'py', 'type': 'python_version', 'min': '3.10'}, {'id': 'bad', 'type': 'python_version', 'min': '99.0'}]}))
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                code = asgctl.main(['doctor', '--role', 'demo', '--role-dir', tmp])
            report = json.loads(buf.getvalue())
            self.assertEqual(code, 1)
            self.assertEqual({c['id']: c['status'] for c in report['checks']}, {'py': 'ok', 'bad': 'fail'})

    def test_script_has_no_write_side_effects(self):
        text = (ROOT / 'scripts' / 'asgctl.py').read_text(encoding='utf-8')
        for forbidden in ('write_text', 'os.remove', 'shutil.rmtree', 'New-NetFirewallRule', 'Set-', 'Remove-', 'Stop-VM', 'New-VM'):
            self.assertNotIn(forbidden, text)
        self.assertIn('sudo nft flush ruleset', text)  # the one guest-side test action, guarded by --deep and restored by a trap


if __name__ == '__main__':
    unittest.main()
