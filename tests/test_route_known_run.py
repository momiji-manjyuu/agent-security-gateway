"""Route opt-in must tighten run checks without weakening a global requirement."""
import copy
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway


class RouteKnownRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def cfg(self, known=False, runs=None):
        return {'require_known_run_id': known, 'runs': runs or {},
                'run_store': {'path': str(Path(self.tmp.name) / 'runs.jsonl')}}

    def decision(self, route, run_id):
        return gateway.RouteDecision('fixture.route', route, 'inspect', run_id, None, ['sandbox_output'], [])

    def test_route_requires_missing_and_unknown_run_with_global_permissive(self):
        cfg = self.cfg()
        for rid in (None, 'unknown'):
            with self.assertRaises(gateway.GatewayError) as cm:
                gateway.enforce_run_scope(self.decision({'require_known_run_id': True}, rid), cfg, 'fixture')
            self.assertEqual(cm.exception.code, 'run_scope_denied')

    def test_route_false_cannot_weaken_global_requirement(self):
        cfg = self.cfg(True)
        with self.assertRaises(gateway.GatewayError):
            gateway.enforce_run_scope(self.decision({'require_known_run_id': False}, 'unknown'), cfg, 'fixture')

    def test_existing_route_unknown_behavior_preserved(self):
        cfg = self.cfg()
        decision = self.decision({}, 'unknown')
        gateway.enforce_run_scope(decision, cfg, 'fixture')
        self.assertIn('unknown_run_id_allowed', decision.warnings)

    def test_registered_run_keeps_caller_and_route_restrictions(self):
        cfg = self.cfg(runs={'fixture': {'allowed_callers': ['fixture'], 'allowed_routes': ['fixture.route']}})
        d = self.decision({'require_known_run_id': True}, 'fixture')
        gateway.enforce_run_scope(d, cfg, 'fixture')
        with self.assertRaises(gateway.GatewayError):
            gateway.enforce_run_scope(d, cfg, 'other')

    def test_invalid_flag_fails_config_validation(self):
        for bad in ('true', 1, None):
            cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
            next(iter(cfg['routes'].values()))['require_known_run_id'] = bad
            with self.assertRaisesRegex(ValueError, 'require_known_run_id must be a boolean'):
                gateway.validate_config(cfg)


if __name__ == '__main__':
    unittest.main()
