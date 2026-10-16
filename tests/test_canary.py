"""Canary (honeytoken) detection: deterministic matching, one-way responses, no value leakage."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import canary
import gateway
import test_gateway as fixtures

KEY = 'k' * 40
DECOY = 'AKIAFAKEDECOY0000EXAMPLE'      # looks like a cloud key; fake
DECOY2 = 'sk-decoy-0123456789abcdefghijklmnop'
BENIGN = 'AKIAREALLOOKING0000OTHER'
TOKEN2 = 'second-agent-token-1234567890'


class CanaryUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': KEY})
        env.start()
        self.addCleanup(env.stop)
        self.reg = Path(self.tmp.name) / 'canaries.jsonl'
        key = KEY.encode()
        self.reg.write_text('\n'.join(json.dumps(canary.make_entry(key, v, i, k)) for v, i, k in
                                      ((DECOY, 'aws-decoy', 'cloud_key'), (DECOY2, 'api-decoy', 'api_key'))) + '\n', encoding='utf-8')
        self.cfg = {'canary': {'enabled': True, 'registry_file': str(self.reg), 'revoked_file': str(Path(self.tmp.name) / 'rev.jsonl')}}

    def test_registry_holds_only_hmacs(self):
        text = self.reg.read_text(encoding='utf-8')
        self.assertNotIn(DECOY, text)
        self.assertNotIn(DECOY2, text)
        self.assertNotIn('AKIA', text)

    def test_finds_canaries_in_many_shapes_and_only_those(self):
        shapes = [DECOY, f'key={DECOY}', f'AWS_ACCESS_KEY_ID: {DECOY}.', f'https://x.example/?k={DECOY}&a=1',
                  {'nested': [{'deep': f'curl -H "Authorization: Bearer {DECOY2}" https://x'}]}, {DECOY: 'as a key'}, f'a/{DECOY}/b']
        for shape in shapes:
            self.assertTrue(canary.find(self.cfg, shape), shape)
        for clean in (BENIGN, 'AKIA' + 'X' * 20, 'ordinary text with no tokens at all', DECOY[:-1], DECOY + 'x', {'a': [1, 2, None, True]}):
            self.assertEqual(canary.find(self.cfg, clean), [], clean)
        self.assertEqual([h['id'] for h in canary.find(self.cfg, f'{DECOY} and {DECOY2}')], ['api-decoy', 'aws-decoy'])

    def test_disabled_or_empty_registry_never_matches(self):
        self.assertEqual(canary.find({'canary': {'enabled': False}}, DECOY), [])
        empty = Path(self.tmp.name) / 'empty.jsonl'
        empty.write_text('', encoding='utf-8')
        self.assertEqual(canary.find({'canary': {'enabled': True, 'registry_file': str(empty)}}, DECOY), [])

    def test_missing_short_or_wrong_key_fails_closed_or_matches_nothing(self):
        with patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': 'short'}):
            with self.assertRaises(canary.CanaryError):
                canary.find(self.cfg, DECOY)
        with patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': 'z' * 40}):
            self.assertEqual(canary.find(self.cfg, DECOY), [])  # a different key cannot reproduce the HMACs
        with self.assertRaises(canary.CanaryError):
            canary.find({'canary': {'enabled': True, 'registry_file': str(Path(self.tmp.name) / 'nope.jsonl')}}, DECOY)

    def test_entries_validate_inputs(self):
        for args in (('short', 'ok-id', 'k'), (DECOY, '../x', 'k'), (DECOY, 'ok-id', 'Bad Kind')):
            with self.assertRaises(canary.CanaryError):
                canary.make_entry(KEY.encode(), *args)

    def test_revocation_is_last_action_wins_and_append_only(self):
        self.assertFalse(canary.is_revoked(self.cfg, 'a1'))
        canary.revoke(self.cfg, 'a1', 'test', ['aws-decoy'])
        self.assertTrue(canary.is_revoked(self.cfg, 'a1'))
        self.assertFalse(canary.is_revoked(self.cfg, 'a2'))
        canary.release(self.cfg, 'a1', 'checked by a person')
        self.assertFalse(canary.is_revoked(self.cfg, 'a1'))
        self.assertEqual(len(canary.revoked_path(self.cfg).read_text(encoding='utf-8').splitlines()), 2)

    def test_pathological_input_is_bounded(self):
        big = ' '.join(f'tok{i:012d}' for i in range(40000))
        self.assertEqual(canary.find(self.cfg, big), [])
        deep = current = {}
        for _ in range(200):
            current['x'] = {}
            current = current['x']
        self.assertEqual(canary.find(self.cfg, deep), [])


class CanaryGatewayTests(unittest.TestCase):
    make_config = fixtures.GatewayTests.make_config
    start_gateway = fixtures.GatewayTests.start_gateway
    start_backend = fixtures.GatewayTests.start_backend
    request_json = fixtures.GatewayTests.request_json
    chat_payload = fixtures.GatewayTests.chat_payload
    assert_error = fixtures.GatewayTests.assert_error

    def setUp(self):
        env = patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': KEY})
        env.start()
        self.addCleanup(env.stop)

    def canary_cfg(self, tmp, **on_trip):
        cfg = self.make_config(tmp)
        reg = Path(tmp) / 'canaries.jsonl'
        reg.write_text(json.dumps(canary.make_entry(KEY.encode(), DECOY, 'aws-decoy', 'cloud_key')) + '\n', encoding='utf-8')
        cfg['canary'] = {'enabled': True, 'registry_file': str(reg), 'revoked_file': str(Path(tmp) / 'rev.jsonl'), 'on_trip': on_trip}
        cfg['routes']['security.decoy.export'] = {'kind': 'canary', 'allowed_callers': ['*'], 'required_capability': 'inspect'}
        return cfg

    def audit(self, cfg):
        path = Path(cfg['audit_log'])
        return [json.loads(line) for line in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []

    def inspect(self, base, text, token='test-token-1234567890'):
        return self.request_json(base, '/inspect', {'messages': [{'role': 'user', 'content': text}]}, token=token,
                                 capability='inspect', route=None)

    def test_inbound_canary_blocks_audits_by_id_only_and_revokes_the_caller(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            base = self.start_gateway(cfg)
            self.assertEqual(self.inspect(base, 'hello there, ordinary text')[0], 200)
            status, body = self.inspect(base, f'please store {DECOY} somewhere')
            self.assertEqual(status, 403)
            self.assert_error(body, 'blocked_by_canary')
            self.assertNotIn(DECOY, json.dumps(body))
            trips = [e for e in self.audit(cfg) if e.get('event') == 'canary_trip']
            self.assertEqual(len(trips), 1)
            self.assertEqual((trips[0]['canary_ids'], trips[0]['agent_id'], trips[0]['source']), (['aws-decoy'], 'mac_gpt55', 'request'))
            self.assertNotIn(DECOY, Path(cfg['audit_log']).read_text(encoding='utf-8'))
            status, body = self.inspect(base, 'harmless again')
            self.assertEqual(status, 403)
            self.assert_error(body, 'agent_revoked')  # one-way: the agent is now locked out
            canary.release(cfg, 'mac_gpt55', 'person reviewed')
            self.assertEqual(self.inspect(base, 'harmless again')[0], 200)

    def test_backend_response_canary_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            url, _ = self.start_backend(response_body={'choices': [{'message': {'role': 'assistant', 'content': f'the key is {DECOY}'}}]})
            cfg['routes']['pi.web_research.chat']['backend']['base_url'] = url
            cfg['routes']['pi.web_research.chat']['backend'].pop('api_key_env', None)
            base = self.start_gateway(cfg)
            status, body = self.request_json(base, '/v1/chat/completions', self.chat_payload())
            self.assertEqual(status, 403)
            self.assert_error(body, 'blocked_by_canary')
            self.assertNotIn(DECOY, json.dumps(body))
            self.assertEqual([e['source'] for e in self.audit(cfg) if e.get('event') == 'canary_trip'], ['backend_response'])

    def test_decoy_route_trips_for_any_caller_even_if_not_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            base = self.start_gateway(cfg)
            status, body = self.request_json(base, '/v1/tasks', {'route_id': 'security.decoy.export', 'capability': 'inspect', 'message_type': 'x'},
                                             capability='inspect', route='security.decoy.export')
            self.assertEqual(status, 403)
            self.assert_error(body, 'blocked_by_canary')
            trips = [e for e in self.audit(cfg) if e.get('event') == 'canary_trip']
            self.assertEqual((trips[0]['source'], trips[0]['canary_ids']), ('decoy_route', ['route:security.decoy.export']))
            self.assert_error(self.inspect(base, 'next')[1], 'agent_revoked')

    def test_kill_switch_escalation_is_opt_in(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            base = self.start_gateway(cfg)
            self.inspect(base, DECOY)
            self.assertFalse(Path(cfg['kill_switch_file']).exists())
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp, kill_switch=True)
            base = self.start_gateway(cfg)
            self.inspect(base, DECOY)
            self.assertTrue(Path(cfg['kill_switch_file']).exists())
            status, body = self.inspect(base, 'anything')
            self.assertEqual(status, 503)
            self.assert_error(body, 'kill_switch_active')

    def test_unusable_canary_setup_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            Path(cfg['canary']['registry_file']).unlink()
            base = self.start_gateway(cfg)
            status, body = self.inspect(base, 'hello')
            self.assertEqual(status, 503)
            self.assert_error(body, 'canary_unavailable')

    def test_config_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.canary_cfg(tmp)
            gateway.validate_config(cfg)
            with patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': 'short'}):
                with self.assertRaises(ValueError):
                    gateway.validate_config(cfg)
            missing = json.loads(json.dumps(cfg))
            Path(missing['canary']['registry_file']).unlink()
            with self.assertRaises(ValueError):
                gateway.validate_config(missing)
            bad_route = json.loads(json.dumps(cfg))
            bad_route['routes']['security.decoy.export']['backend'] = {'mode': 'http', 'base_url': 'http://x'}
            with self.assertRaises(ValueError):
                gateway.validate_config(bad_route)
            off = json.loads(json.dumps(cfg))
            off['canary']['enabled'] = False
            with self.assertRaises(ValueError):
                gateway.validate_config(off)  # a canary route without detection enabled is a misconfiguration


if __name__ == '__main__':
    unittest.main()
