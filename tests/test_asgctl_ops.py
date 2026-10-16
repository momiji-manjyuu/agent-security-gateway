"""Tests for scripts/asgctl_ops.py: secrets init, fragment merge, runs register."""
import contextlib
import copy
import http.server
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import asgctl_ops as ops  # noqa: E402

FRAGMENT = ROOT / 'examples' / 'disposable-search-agent' / 'asg' / 'config.fragment.json'
HASH_A = 'a' * 64
HASH_B = 'b' * 64


def base_config():
    return {
        'bind': '127.0.0.1', 'port': 8788,
        'agents': {'win_controller_1': {'token_sha256': HASH_A, 'trust_tier': 'privileged_core',
                                         'allowed_client_cidrs': ['127.0.0.1/32'],
                                         'allowed_capabilities': ['inspect'], 'allowed_routes': ['security.inspect_only']}},
        'routes': {'security.inspect_only': {'kind': 'inspect_only', 'allowed_callers': ['*'], 'required_capability': 'inspect'}},
    }


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ops.main(argv)
    return code, out.getvalue(), err.getvalue()


class SecretsInitTests(unittest.TestCase):
    def test_creates_private_files_and_prints_only_the_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, _ = run_cli(['secrets', 'init', '--dir', tmp, '--name', 'docker90_search'])
            self.assertEqual(code, 0)
            report = json.loads(out)
            entry = report['files'][0]
            token = (Path(tmp) / 'docker90_search.token').read_text(encoding='utf-8').strip()
            self.assertGreaterEqual(len(token), 32)
            self.assertNotIn(token, out)
            self.assertEqual(entry['token_sha256'], ops.gateway.hash_token(token))
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE((Path(tmp) / 'docker90_search.token').stat().st_mode), 0o600)

    def test_never_overwrites_and_rejects_bad_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_cli(['secrets', 'init', '--dir', tmp, '--name', 'a1'])
            before = (Path(tmp) / 'a1.token').read_text(encoding='utf-8')
            _, out, _ = run_cli(['secrets', 'init', '--dir', tmp, '--name', 'a1'])
            self.assertEqual(json.loads(out)['files'][0]['status'], 'exists_not_modified')
            self.assertEqual((Path(tmp) / 'a1.token').read_text(encoding='utf-8'), before)
            for bad in ('../x', 'a b', '1abc', ''):
                code, _, err = run_cli(['secrets', 'init', '--dir', tmp, '--name', bad])
                self.assertEqual(code, 1, bad)
            code, _, _ = run_cli(['secrets', 'init', '--dir', tmp, '--name', 'dup', '--name', 'dup'])
            self.assertEqual(code, 1)

    def test_key_kind_has_no_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, out, _ = run_cli(['secrets', 'init', '--dir', tmp, '--name', 'hmac_shared', '--kind', 'key'])
            entry = json.loads(out)['files'][0]
            self.assertNotIn('token_sha256', entry)
            self.assertTrue((Path(tmp) / 'hmac_shared.key').exists())


class FragmentMergeTests(unittest.TestCase):
    def fragment(self):
        return json.loads(FRAGMENT.read_text(encoding='utf-8'))

    def merge(self, config=None, mapping=None, hashes=None):
        fragment = ops.substitute_ids(self.fragment(), mapping or {})
        return ops.merge_fragment(config or base_config(), fragment, hashes or {})

    def test_new_agent_without_a_real_hash_is_refused(self):
        _, _, conflicts = self.merge(mapping={'controller': 'win_controller_1'})
        self.assertTrue(any('docker90_search' in c and 'token hash' in c for c in conflicts))
        self.assertTrue(any('unresolved placeholder' in c for c in conflicts))

    def test_existing_agent_keeps_token_and_cidrs_and_only_widens_scope(self):
        merged, changes, conflicts = self.merge(mapping={'controller': 'win_controller_1'}, hashes={'docker90_search': HASH_B})
        self.assertEqual(conflicts, [])
        agent = merged['agents']['win_controller_1']
        self.assertEqual(agent['token_sha256'], HASH_A)
        self.assertEqual(agent['allowed_client_cidrs'], ['127.0.0.1/32'])
        self.assertEqual(agent['allowed_capabilities'], ['inspect', 'delegate_web_research'])
        self.assertIn('docker90.web_research.task', agent['allowed_routes'])
        self.assertEqual(merged['agents']['docker90_search']['token_sha256'], HASH_B)
        self.assertEqual(merged['routes']['docker90.web_research.task']['allowed_callers'], ['win_controller_1'])
        self.assertTrue(merged['require_known_run_id'])
        self.assertTrue(all(set(c) <= {'op', 'path', 'added'} for c in changes))

    def test_differing_existing_route_is_a_conflict_not_an_overwrite(self):
        config = base_config()
        config['routes']['docker90.artifacts.submit'] = {'kind': 'inspect_only', 'allowed_callers': ['x']}
        before = copy.deepcopy(config)
        merged, _, conflicts = self.merge(config, {'controller': 'win_controller_1'}, {'docker90_search': HASH_B})
        self.assertTrue(any('docker90.artifacts.submit' in c for c in conflicts))
        self.assertEqual(config, before)  # input untouched

    def test_identical_existing_definitions_are_a_no_op(self):
        merged, _, _ = self.merge(mapping={'controller': 'win_controller_1'}, hashes={'docker90_search': HASH_B})
        _, changes, conflicts = ops.merge_fragment(merged, ops.substitute_ids(self.fragment(), {'controller': 'win_controller_1'}),
                                                   {'docker90_search': HASH_B})
        self.assertEqual((changes, conflicts), ([], []))

    def test_top_level_value_conflict(self):
        config = base_config()
        config['require_known_run_id'] = False
        _, _, conflicts = self.merge(config, {'controller': 'win_controller_1'}, {'docker90_search': HASH_B})
        self.assertTrue(any(c.startswith('require_known_run_id') for c in conflicts))

    def test_route_that_differs_only_by_callers_can_be_widened_but_never_narrowed(self):
        route = {'kind': 'inspect_only', 'allowed_callers': ['a', 'b'], 'required_capability': 'x'}
        frag = {'routes': {'r1': {**route, 'allowed_callers': ['b', 'c']}}}
        merged, changes, conflicts = ops.merge_fragment({'routes': {'r1': route}}, frag, {})
        self.assertEqual((conflicts, merged['routes']['r1']['allowed_callers']), ([], ['a', 'b', 'c']))
        self.assertEqual(changes, [{'op': 'extend', 'path': 'routes.r1.allowed_callers', 'added': ['c']}])
        # nothing removed when the fragment lists fewer callers
        merged, changes, _ = ops.merge_fragment({'routes': {'r1': route}}, {'routes': {'r1': {**route, 'allowed_callers': ['a']}}}, {})
        self.assertEqual((changes, merged['routes']['r1']['allowed_callers']), ([], ['a', 'b']))
        # a wildcard route is left alone
        star = {**route, 'allowed_callers': ['*']}
        self.assertEqual(ops.merge_fragment({'routes': {'r1': star}}, frag, {})[1:], ([], []))
        # any other difference is still a conflict
        other = {'routes': {'r1': {**route, 'required_capability': 'y', 'allowed_callers': ['c']}}}
        self.assertTrue(ops.merge_fragment({'routes': {'r1': route}}, other, {})[2])

    def test_map_can_expand_caller_lists_but_not_agent_ids(self):
        frag = {'agents': {'controller': {}}, 'routes': {'r': {'allowed_callers': ['controller', 'worker']}}}
        out = ops.substitute_ids({'routes': frag['routes']}, {'controller': 'a,b'})
        self.assertEqual(out['routes']['r']['allowed_callers'], ['a', 'b', 'worker'])
        with self.assertRaises(ops.OpsError):
            ops.substitute_ids(frag, {'controller': 'a,b'})
        renamed = ops.substitute_ids(frag, {'controller': 'solo'})
        self.assertIn('solo', renamed['agents'])

    def write_files(self, tmp):
        cfg = Path(tmp) / 'config.json'
        cfg.write_text(json.dumps(base_config(), indent=2), encoding='utf-8')
        return cfg

    def test_dry_run_changes_nothing_and_write_makes_a_backup(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.write_files(tmp)
            original = cfg.read_text(encoding='utf-8')
            args = ['fragment', 'merge', '--into', str(cfg), '--from', str(FRAGMENT), '--map', 'controller=win_controller_1',
                    '--token-sha256', f'docker90_search={HASH_B}']
            code, out, _ = run_cli(args)
            self.assertEqual((code, json.loads(out)['status']), (0, 'dry_run'))
            self.assertEqual(cfg.read_text(encoding='utf-8'), original)
            code, out, _ = run_cli(args + ['--write', '--skip-validate'])
            report = json.loads(out)
            self.assertEqual((code, report['status']), (0, 'written'))
            self.assertEqual(Path(report['backup']).read_text(encoding='utf-8'), original)
            self.assertIn('docker90_search', json.loads(cfg.read_text(encoding='utf-8'))['agents'])
            self.assertEqual([p.name for p in Path(tmp).glob('*.json') if '.bak' not in p.name and p.name != 'config.json'], [])

    def test_refused_merge_leaves_the_file_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.write_files(tmp)
            original = cfg.read_text(encoding='utf-8')
            code, out, _ = run_cli(['fragment', 'merge', '--into', str(cfg), '--from', str(FRAGMENT), '--write', '--skip-validate'])
            self.assertEqual((code, json.loads(out)['status']), (1, 'refused'))
            self.assertEqual(cfg.read_text(encoding='utf-8'), original)

    def test_invalid_candidate_is_not_installed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.write_files(tmp)
            original = cfg.read_text(encoding='utf-8')
            with patch.object(ops, 'validate_candidate', return_value=(False, 'bad')):
                code, out, _ = run_cli(['fragment', 'merge', '--into', str(cfg), '--from', str(FRAGMENT), '--map', 'controller=win_controller_1',
                                        '--token-sha256', f'docker90_search={HASH_B}', '--write'])
            self.assertEqual((code, json.loads(out)['status']), (1, 'refused_invalid_config'))
            self.assertEqual(cfg.read_text(encoding='utf-8'), original)
            self.assertEqual(sorted(p.name for p in Path(tmp).iterdir()), ['config.json'])

    def test_bad_map_and_hash_arguments(self):
        for extra in (['--map', 'noequals'], ['--token-sha256', 'x=']):
            code, _, _ = run_cli(['fragment', 'merge', '--into', 'a', '--from', 'b'] + extra)
            self.assertEqual(code, 1)


class RunsRegisterTests(unittest.TestCase):
    def start(self, status=200, body=None):
        seen = {}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                length = int(self.headers.get('Content-Length', 0))
                seen['path'] = self.path
                seen['headers'] = {k.lower(): v for k, v in self.headers.items()}
                seen['body'] = json.loads(self.rfile.read(length))
                data = json.dumps(body if body is not None else {'run_id': 'run_x', 'expires_at': '2030-01-01T00:00:00Z',
                                                                  'allowed_routes': ['r'], 'secret_extra': 'must-not-be-echoed'}).encode()
                self.send_response(status)
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close()))
        return f'http://127.0.0.1:{server.server_address[1]}', seen

    def token_file(self, tmp, value='tok-abcdefghijklmnopqrstuvwxyz0123456789'):
        path = Path(tmp) / 'ctl.token'
        path.write_text(value + '\n', encoding='utf-8')
        return path, value

    def test_sends_the_documented_headers_and_returns_only_known_fields(self):
        url, seen = self.start()
        with tempfile.TemporaryDirectory() as tmp:
            path, token = self.token_file(tmp)
            result = ops.runs_register(url, path, {'allowed_routes': ['r'], 'ttl_seconds': 60})
        self.assertEqual(seen['path'], '/v1/runs')
        self.assertEqual(seen['headers']['x-agent-capability'], 'register_run')
        self.assertEqual(seen['headers']['x-asg-route'], 'security.runs.register')
        self.assertEqual(seen['headers']['authorization'], f'Bearer {token}')
        self.assertEqual(set(result), {'run_id', 'expires_at', 'allowed_routes'})

    def test_cli_output_never_contains_the_token(self):
        url, _ = self.start()
        with tempfile.TemporaryDirectory() as tmp:
            path, token = self.token_file(tmp)
            body = Path(tmp) / 'body.json'
            body.write_text(json.dumps({'allowed_routes': ['r'], 'ttl_seconds': 60}), encoding='utf-8')
            code, out, err = run_cli(['runs', 'register', '--url', url, '--token-file', str(path), '--body', str(body)])
        self.assertEqual(code, 0)
        self.assertNotIn(token, out + err)

    def test_refuses_non_loopback_urls_and_https(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _ = self.token_file(tmp)
            for url in ('http://192.0.2.10:8788', 'http://example.com', 'https://127.0.0.1:8788', 'http://127.0.0.1.evil.test'):
                with self.assertRaises(ops.OpsError, msg=url):
                    ops.runs_register(url, path, {})

    def test_http_errors_report_the_code_not_the_body_or_token(self):
        url, _ = self.start(status=403, body={'error': 'run_scope_denied', 'detail': 'internal-detail-should-not-show'})
        with tempfile.TemporaryDirectory() as tmp:
            path, token = self.token_file(tmp)
            with self.assertRaises(ops.OpsError) as ctx:
                ops.runs_register(url, path, {})
        message = str(ctx.exception)
        self.assertIn('403', message)
        self.assertIn('run_scope_denied', message)
        self.assertNotIn('internal-detail', message)
        self.assertNotIn(token, message)

    def test_missing_or_empty_token_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ops.OpsError):
                ops.runs_register('http://127.0.0.1:1', Path(tmp) / 'nope', {})
            empty = Path(tmp) / 'e'
            empty.write_text('\n', encoding='utf-8')
            with self.assertRaises(ops.OpsError):
                ops.runs_register('http://127.0.0.1:1', empty, {})


class TunnelPresetTests(unittest.TestCase):
    base = ROOT / 'presets' / 'parent' / 'tunnel'

    def test_key_script_restricts_the_key_to_loopback_forwarding_and_never_overwrites(self):
        text = (self.base / 'New-AsgTunnelKey.ps1').read_text(encoding='utf-8')
        for needle in ('restrict,port-forwarding', 'permitopen=', 'permitlisten=', "127\\.0\\.0\\.1", 'refusing to overwrite', '/inheritance:r'):
            self.assertIn(needle, text)
        # `restrict` alone still allows remote commands; a forced command and a pinned opposite direction are required.
        self.assertIn('command=\"echo asg-tunnel-only\"', text)
        self.assertIn('permitopen=`"127.0.0.1:1`"', text)   # reverse-mode key cannot open local forwards
        self.assertIn('permitlisten=`"127.0.0.1:1`"', text)  # local-mode key cannot listen for reverse forwards
        self.assertNotIn('Get-Content $key ', text)  # the private key is never read or printed

    def test_task_script_defaults_to_plan_only_and_pins_a_single_loopback_forward(self):
        text = (self.base / 'Install-AsgTunnelTask.ps1').read_text(encoding='utf-8')
        for needle in ('[switch]$Apply', 'plan only', 'ExitOnForwardFailure=yes', 'StrictHostKeyChecking=yes', 'BatchMode=yes', 'IdentitiesOnly=yes',
                       '-L 127.0.0.1:${LocalPort}:127.0.0.1:${HubPort}', '-RunLevel Limited', 'while (`$true)', 'EncodedCommand'):
            self.assertIn(needle, text)
        self.assertNotIn('0.0.0.0', text)
        self.assertNotIn('GatewayPorts', text)
        unit = (self.base / 'asg-tunnel.service').read_text(encoding='utf-8')
        self.assertIn('-L 127.0.0.1:8788:127.0.0.1:8788', unit)
        self.assertIn('ExitOnForwardFailure=yes', unit)


if __name__ == '__main__':
    unittest.main()
