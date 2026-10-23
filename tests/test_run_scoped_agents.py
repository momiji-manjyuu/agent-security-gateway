"""Per-run worker identities: hash-only, bound to one run, expire with it, revoked alone on a canary trip."""
import json
import os
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

import test_gateway as fixtures  # noqa: I001  (sets sys.path)
import canary
import gateway

KEY = 'k' * 40
DECOY = 'AKIAFAKEDECOY0000EXAMPLE'
PARENT = 'test-token-1234567890'
TA, TB = 'run-a-worker-token-0123456789abcdef', 'run-b-worker-token-0123456789abcdef'


class RunScopedAgentTests(unittest.TestCase):
    make_config = fixtures.GatewayTests.make_config
    start_gateway = fixtures.GatewayTests.start_gateway

    def setUp(self):
        env = patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': KEY})
        env.start()
        self.addCleanup(env.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = self.make_config(self.tmp.name)
        reg = Path(self.tmp.name) / 'canaries.jsonl'
        reg.write_text(json.dumps(canary.make_entry(KEY.encode(), DECOY, 'aws-decoy', 'cloud_key')) + '\n', encoding='utf-8')
        cfg['canary'] = {'enabled': True, 'registry_file': str(reg), 'revoked_file': str(Path(self.tmp.name) / 'rev.jsonl'),
                         'on_trip': {'revoke_agent': True}}
        cfg['agents']['fcw'] = {'token_sha256': '', 'run_scoped': True, 'trust_tier': 'web_dmz',
                                'allowed_client_cidrs': ['127.0.0.1/32'], 'allowed_capabilities': ['inspect'],
                                'allowed_routes': ['security.inspect_only']}
        gateway.validate_config(cfg)
        self.cfg = cfg
        self.base = self.start_gateway(cfg)

    def call(self, path, payload, token, *, route, capability, run_id=None):
        headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token,
                   'X-ASG-Route': route, 'X-Agent-Capability': capability}
        if run_id:
            headers['X-ASG-Run-Id'] = run_id
        req = urllib.request.Request(self.base + path, data=json.dumps(payload).encode(), method='POST', headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, json.loads(r.read().decode() or '{}')
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode() or '{}')

    def register(self, run_id, run_agents=None, ttl=600, callers=('mac_gpt55', 'fcw')):
        body = {'route_id': 'security.runs.register', 'capability': 'register_run', 'taint': ['trusted_instruction'],
                'run_id': run_id, 'allowed_routes': ['security.inspect_only'], 'allowed_callers': list(callers), 'ttl_seconds': ttl}
        if run_agents is not None:
            body['run_agents'] = run_agents
        return self.call('/v1/runs', body, PARENT, route='security.runs.register', capability='register_run')

    def work(self, token, run_id, text='ordinary page summary'):
        body = {'route_id': 'security.inspect_only', 'capability': 'inspect', 'taint': ['untrusted_web'],
                'messages': [{'role': 'user', 'content': text}]}
        return self.call('/v1/tasks', body, token, route='security.inspect_only', capability='inspect', run_id=run_id)

    def code(self, resp):
        return (resp[1].get('error') or {}).get('code')

    def audit(self):
        return [json.loads(x) for x in Path(self.cfg['audit_log']).read_text(encoding='utf-8').splitlines()]

    def test_identity_is_hash_only_and_bound_to_its_run(self):
        self.assertEqual(self.register('run-a', {'fcw': gateway.hash_token(TA)})[0], 200)
        self.assertEqual(self.register('run-b', {'fcw': gateway.hash_token(TB)})[0], 200)
        stored = Path(self.cfg['run_store']['path']).read_text(encoding='utf-8')
        self.assertNotIn(TA, stored)
        self.assertIn(gateway.hash_token(TA), stored)
        audit_text = Path(self.cfg['audit_log']).read_text(encoding='utf-8')
        self.assertNotIn(gateway.hash_token(TA), audit_text)
        self.assertNotIn(TA, audit_text)
        self.assertEqual(self.work(TA, 'run-a')[0], 200)
        self.assertEqual(self.audit()[-1]['agent_id'], 'fcw@run-a')
        self.assertEqual(self.work(TA, 'run-b')[0], 401)   # not valid for another run
        self.assertEqual(self.work(TA, None)[0], 401)      # not valid without its run
        self.assertEqual(self.work(TB, 'run-b')[0], 200)

    def test_canary_trip_revokes_only_that_run(self):
        self.register('run-a', {'fcw': gateway.hash_token(TA)})
        self.register('run-b', {'fcw': gateway.hash_token(TB)})
        resp = self.work(TA, 'run-a', f'leak {DECOY}')
        self.assertEqual((resp[0], self.code(resp)), (403, 'blocked_by_canary'))
        trips = [e for e in self.audit() if e.get('event') == 'canary_trip']
        self.assertEqual(trips[-1]['agent_id'], 'fcw@run-a')
        self.assertEqual(self.code(self.work(TA, 'run-a')), 'agent_revoked')
        self.assertEqual(self.work(TB, 'run-b')[0], 200)                 # other run unaffected
        self.assertFalse(canary.is_revoked(self.cfg, 'fcw'))             # template not revoked
        self.assertEqual(self.register('run-c', {'fcw': gateway.hash_token('run-c-token-0123456789abcdef')})[0], 200)
        self.assertEqual(self.work('run-c-token-0123456789abcdef', 'run-c')[0], 200)  # no manual release needed
        self.assertEqual(self.register('run-p')[0], 200)                 # parent unaffected

    def test_revocation_and_expiry_end_the_identity(self):
        self.register('run-a', {'fcw': gateway.hash_token(TA)})
        self.assertEqual(self.work(TA, 'run-a')[0], 200)
        self.register('run-a', ttl=1, callers=('mac_gpt55',))  # parent revoke: latest record wins, no run_agents
        self.assertEqual(self.work(TA, 'run-a')[0], 401)
        self.register('run-x', {'fcw': gateway.hash_token(TB)}, ttl=1)
        time.sleep(2.1)
        self.assertEqual(self.code(self.work(TB, 'run-x')), 'run_expired')

    def test_registration_validation(self):
        h = gateway.hash_token(TA)
        self.assertEqual(self.register('r1', {'mac_gpt55': h})[0], 403)                 # not a run_scoped template
        self.assertEqual(self.register('r2', {'fcw': h}, callers=('mac_gpt55',))[0], 400)  # template must be a caller
        self.assertEqual(self.register('r3', {'fcw': 'XYZ'})[0], 400)
        self.assertEqual(self.register('r4', {'fcw': gateway.hash_token(PARENT)})[0], 400)  # reuse of a static token
        self.assertEqual(self.register('r5', {})[0], 400)
        self.assertEqual(self.register('r6', {'fcw': h, 'a': h, 'b': h, 'c': h, 'd': h})[0], 400)

    def test_config_validation(self):
        for bad in ({'run_scoped': 'yes'},):
            cfg = json.loads(json.dumps(self.cfg))
            cfg['agents']['fcw'].update(bad)
            with self.assertRaises(Exception):
                gateway.validate_config(cfg)
        cfg = json.loads(json.dumps(self.cfg))
        cfg['agents']['x@y'] = dict(cfg['agents']['fcw'])
        with self.assertRaises(Exception):
            gateway.validate_config(cfg)


if __name__ == '__main__':
    unittest.main()
