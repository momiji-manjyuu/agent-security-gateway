import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway

MODEL = 'fixture-model'
PIN = {'model': MODEL, 'deployment': 'fixture-deployment', 'backend': 'fixture-backend'}
HEADERS = {'X-Fleet-Requested-Model': MODEL, 'X-Fleet-Served-Model': MODEL,
           'X-Fleet-Deployment': PIN['deployment'], 'X-Fleet-Backend': PIN['backend'],
           'X-Fleet-Fallback': 'false', 'X-Fleet-Attempts': '1'}


class FakeResponse:
    status = 200
    def __init__(self, body, headers):
        self.body, self.headers = body, headers
    def __enter__(self):
        return self
    def __exit__(self, *args):
        pass
    def read(self, limit=None):
        return self.body if limit is None else self.body[:limit]


class FleetPinTests(unittest.TestCase):
    def forward(self, value, headers=HEADERS, pin=PIN, raw=None):
        backend = {'base_url': 'http://127.0.0.1:9/v1', 'model': MODEL, 'api_key_env': ''}
        if pin is not None:
            backend['fleet_pin'] = pin
        d = gateway.RouteDecision('fixture', {'backend': backend}, 'inspect', None, None, [], [])
        agent = gateway.VerifiedAgent('fixture', {})
        data = json.dumps(value).encode() if raw is None else raw
        with patch.object(gateway.urllib.request, 'urlopen', return_value=FakeResponse(data, headers)):
            return gateway.forward_openai_chat({'backend_hmac_key_env': ''}, {'messages': []}, d, agent)

    def test_valid_receipt_overwrites_body_forgery(self):
        status, out = self.forward({'model': MODEL, '_asg_backend_receipt': {'admin': True}})
        self.assertEqual(status, 200)
        self.assertEqual(out['_asg_backend_receipt'], {**PIN, 'fallback': False, 'attempts': 1})

    def test_missing_fallback_attempt_model_and_deployment_denied(self):
        for field, value in (('X-Fleet-Fallback', 'true'), ('X-Fleet-Attempts', '2'),
                             ('X-Fleet-Served-Model', 'fixture'), ('X-Fleet-Deployment', 'fixture'),
                             ('X-Fleet-Requested-Model', None)):
            with self.subTest(field=field):
                with self.assertRaises(gateway.GatewayError) as cm:
                    self.forward({'model': MODEL}, {**HEADERS, field: value})
                self.assertEqual(cm.exception.code, 'backend_identity_denied')
        with self.assertRaises(gateway.GatewayError):
            self.forward({'model': 'fixture'})

    def test_pinned_response_size_and_utf8_fail_closed(self):
        with self.assertRaises(gateway.GatewayError) as cm:
            self.forward({}, raw=b' ' * 65537)
        self.assertEqual(cm.exception.code, 'backend_response_limit')
        with self.assertRaises(UnicodeDecodeError):
            self.forward({}, raw=b'\xff')

    def test_unpinned_behavior_unchanged(self):
        _, out = self.forward({'model': 'fixture'}, headers={}, pin=None)
        self.assertEqual(out, {'model': 'fixture'})

    def test_invalid_pin_config_denied(self):
        for pin in ({'model': MODEL}, {**PIN, 'backend': 'http://fixture'}, {**PIN, 'model': 'fixture'}):
            cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
            cfg['agents']['fixture'] = {'token_sha256': '0' * 64, 'allowed_capabilities': ['inspect'],
                                        'allowed_routes': ['fixture.chat']}
            cfg['routes']['fixture.chat'] = {'kind': 'openai_chat_completions', 'allowed_callers': ['fixture'],
                                             'required_capability': 'inspect',
                                             'backend': {'mode': 'http', 'base_url': 'http://127.0.0.1:9/v1',
                                                         'model': MODEL, 'fleet_pin': pin}}
            with self.assertRaisesRegex(ValueError, 'fleet_pin'):
                gateway.validate_config(cfg)


if __name__ == '__main__':
    unittest.main()
