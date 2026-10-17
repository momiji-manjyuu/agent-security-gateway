"""asgctl incident bundle: chain verification, selection, no artifact content, tamper evidence."""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import asgctl_ops as ops  # noqa: E402
import proxy  # noqa: E402

SECRETISH = 'artifact-body-text-that-must-never-be-copied'


def ts(minutes_ago):
    return (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime('%Y-%m-%dT%H:%M:%S+00:00')


class IncidentBundleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.audit = self.root / 'audit.jsonl'
        logger = proxy.AuditLogger(self.audit)
        for minutes, event in ((120, {'event': 'allow', 'agent_id': 'worker_a', 'run_id': 'run_old'}),
                               (20, {'event': 'allow', 'agent_id': 'worker_a', 'run_id': 'run_1', 'route_id': 'r1'}),
                               (19, {'event': 'allow', 'agent_id': 'other', 'run_id': 'run_x'}),
                               (10, {'event': 'canary_trip', 'agent_id': 'worker_a', 'canary_ids': ['aws-decoy'], 'source': 'request'}),
                               (9, {'event': 'deny', 'agent_id': 'worker_a', 'reason': 'agent_revoked'})):
            logger.write({**event, 'timestamp': ts(minutes)})
        store = self.root / 'artifacts' / 'manifests' / '2026-10-16'
        store.mkdir(parents=True)
        for art, agent in (('art_' + 'a' * 32, 'worker_a'), ('art_' + 'b' * 32, 'other')):
            (store / f'{art}.json').write_text(json.dumps({'artifact_id': art, 'producer_agent_id': agent, 'status': 'verified', 'created_at': ts(15),
                                                           'content_sha256': 'c' * 64, 'route_id': 'r1', 'content_text': SECRETISH}), encoding='utf-8')
        self.cfg = self.root / 'config.json'
        self.cfg.write_text(json.dumps({'audit_log': str(self.audit), 'artifact_store': {'path': str(self.root / 'artifacts')},
                                        'canary': {'enabled': True, 'registry_file': str(self.root / 'c.jsonl'), 'revoked_file': str(self.root / 'rev.jsonl')}}),
                            encoding='utf-8')
        (self.root / 'rev.jsonl').write_text(json.dumps({'action': 'revoke', 'agent_id': 'worker_a'}) + '\n', encoding='utf-8')

    def bundle(self, **kw):
        return ops.incident_bundle(self.cfg, self.root / 'bundle', **kw)

    def test_bundle_selects_the_agent_window_and_verifies_the_chain(self):
        report = self.bundle(agent='worker_a', minutes_before=30)
        self.assertEqual((report['chain_ok'], report['trips'], report['run_ids']), (True, 1, ['run_1']))
        events = [json.loads(l) for l in (self.root / 'bundle' / 'events.jsonl').read_text(encoding='utf-8').splitlines()]
        self.assertEqual([e['event'] for e in events], ['allow', 'canary_trip', 'deny'])  # old event and other agent excluded
        self.assertNotIn('run_old', json.dumps(events))
        self.assertNotIn('run_x', json.dumps(events))

    def test_artifacts_are_metadata_only_and_limited_to_the_agent(self):
        self.bundle(agent='worker_a')
        text = (self.root / 'bundle' / 'artifacts.json').read_text(encoding='utf-8')
        artifacts = json.loads(text)
        self.assertEqual([a['artifact_id'] for a in artifacts], ['art_' + 'a' * 32])
        for path in (self.root / 'bundle').iterdir():
            self.assertNotIn(SECRETISH, path.read_text(encoding='utf-8'))

    def test_manifest_hashes_match_the_files(self):
        report = self.bundle(agent='worker_a')
        manifest = json.loads((self.root / 'bundle' / 'MANIFEST.json').read_text(encoding='utf-8'))
        for name, info in manifest['files'].items():
            data = (self.root / 'bundle' / name).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), info['sha256'], name)
        self.assertEqual(manifest['bundle_sha256'], report['bundle_sha256'])
        self.assertIn('Artifact CONTENT is intentionally not included', (self.root / 'bundle' / 'HANDLING.txt').read_text(encoding='utf-8'))

    def test_tampering_with_the_audit_log_is_reported(self):
        lines = self.audit.read_text(encoding='utf-8').splitlines()
        event = json.loads(lines[1])
        event['agent_id'] = 'someone_else'
        lines[1] = json.dumps(event, sort_keys=True)
        self.audit.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        report = self.bundle(agent='worker_a')
        self.assertFalse(report['chain_ok'])
        chain = json.loads((self.root / 'bundle' / 'chain_report.json').read_text(encoding='utf-8'))
        self.assertEqual((chain['ok'], chain['first_break']), (False, 2))

    def test_removed_line_breaks_the_chain(self):
        lines = self.audit.read_text(encoding='utf-8').splitlines()
        del lines[2]
        self.audit.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        self.assertFalse(ops.verify_audit_chain(lines)['ok'])

    def test_refusals(self):
        (self.root / 'bundle').mkdir()
        with self.assertRaises(ops.OpsError):
            self.bundle(agent='worker_a')  # exists
        with self.assertRaises(ops.OpsError):
            ops.incident_bundle(self.cfg, self.root / 'b2', agent='nobody')  # no trips for that agent
        with self.assertRaises(ops.OpsError):
            ops.incident_bundle(self.cfg, self.root / 'b3', agent='../x')

    def test_cli_exit_code_flags_a_broken_chain(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(ops.main(['incident', 'bundle', '--config', str(self.cfg), '--out', str(self.root / 'b_ok'), '--agent', 'worker_a']), 0)
        lines = self.audit.read_text(encoding='utf-8').splitlines()
        lines[0] = lines[0].replace('worker_a', 'tampered')
        self.audit.write_text('\n'.join(lines) + '\n', encoding='utf-8')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ops.main(['incident', 'bundle', '--config', str(self.cfg), '--out', str(self.root / 'b_bad'), '--agent', 'worker_a']), 2)


if __name__ == '__main__':
    unittest.main()
