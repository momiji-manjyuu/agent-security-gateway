"""asgctl canary: init/add/list/release/drill never print or store the decoy text."""
import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import asgctl_ops as ops  # noqa: E402
import canary  # noqa: E402

KEY = 'q' * 40


def run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = ops.main(argv)
    return code, out.getvalue(), err.getvalue()


class CanaryOpsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': KEY})
        env.start()
        self.addCleanup(env.stop)
        self.cfg_path = Path(self.tmp.name) / 'config.json'
        self.cfg_path.write_text(json.dumps({'canary': {'enabled': True, 'registry_file': str(Path(self.tmp.name) / 'c.jsonl'),
                                                         'revoked_file': str(Path(self.tmp.name) / 'r.jsonl')}}), encoding='utf-8')

    def cli(self, *argv):
        return run_cli(['canary', *argv])

    def test_init_requires_a_key_and_a_canary_section(self):
        with patch.dict(os.environ, {'ASG_CANARY_HMAC_KEY': 'short'}):
            self.assertEqual(self.cli('init', '--config', str(self.cfg_path))[0], 1)
        bare = Path(self.tmp.name) / 'bare.json'
        bare.write_text('{}', encoding='utf-8')
        self.assertEqual(self.cli('init', '--config', str(bare))[0], 1)
        code, out, _ = self.cli('init', '--config', str(self.cfg_path))
        self.assertEqual((code, json.loads(out)['created']), (0, True))
        self.assertFalse(json.loads(self.cli('init', '--config', str(self.cfg_path))[1])['created'])

    def test_add_writes_the_decoy_to_a_private_file_and_only_an_hmac_to_the_registry(self):
        self.cli('init', '--config', str(self.cfg_path))
        decoy = Path(self.tmp.name) / 'decoy' / 'credentials'
        code, out, err = self.cli('add', '--config', str(self.cfg_path), '--id', 'aws-home', '--kind', 'cloud_key', '--out', str(decoy))
        self.assertEqual(code, 0, err)
        value = decoy.read_text(encoding='utf-8').strip()
        self.assertTrue(value.startswith('AKIA') and len(value) == 20)
        registry_text = (Path(self.tmp.name) / 'c.jsonl').read_text(encoding='utf-8')
        for text in (out, err, registry_text):
            self.assertNotIn(value, text)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(decoy.stat().st_mode), 0o600)
        cfg = json.loads(self.cfg_path.read_text(encoding='utf-8'))
        self.assertEqual([h['id'] for h in canary.find(cfg, f'leaked: {value}')], ['aws-home'])

    def test_add_refuses_duplicates_overwrites_unknown_kinds_and_missing_registry(self):
        decoy = Path(self.tmp.name) / 'd1'
        self.assertEqual(self.cli('add', '--config', str(self.cfg_path), '--id', 'x1', '--kind', 'cloud_key', '--out', str(decoy))[0], 1)  # no registry yet
        self.cli('init', '--config', str(self.cfg_path))
        self.assertEqual(self.cli('add', '--config', str(self.cfg_path), '--id', 'x1', '--kind', 'cloud_key', '--out', str(decoy))[0], 0)
        self.assertEqual(self.cli('add', '--config', str(self.cfg_path), '--id', 'x1', '--kind', 'api_key', '--out', str(Path(self.tmp.name) / 'd2'))[0], 1)
        self.assertEqual(self.cli('add', '--config', str(self.cfg_path), '--id', 'x2', '--kind', 'api_key', '--out', str(decoy))[0], 1)  # file exists
        self.assertEqual(self.cli('add', '--config', str(self.cfg_path), '--id', 'x3', '--kind', 'nope', '--out', str(Path(self.tmp.name) / 'd3'))[0], 1)
        self.assertEqual(len((Path(self.tmp.name) / 'c.jsonl').read_text(encoding='utf-8').splitlines()), 1)

    def test_list_release_and_drill(self):
        self.cli('init', '--config', str(self.cfg_path))
        self.cli('add', '--config', str(self.cfg_path), '--id', 'tok1', '--kind', 'session_token', '--out', str(Path(self.tmp.name) / 't'))
        cfg = json.loads(self.cfg_path.read_text(encoding='utf-8'))
        canary.revoke(cfg, 'agent_a', 'test', ['tok1'])
        listing = json.loads(self.cli('list', '--config', str(self.cfg_path))[1])
        self.assertEqual(([c['id'] for c in listing['canaries']], listing['revoked_agents']), (['tok1'], ['agent_a']))
        self.assertNotIn('hmac', json.dumps(listing))
        self.assertEqual(self.cli('release', '--config', str(self.cfg_path), '--agent', '../bad')[0], 1)
        self.assertEqual(self.cli('release', '--config', str(self.cfg_path), '--agent', 'agent_a', '--note', 'checked')[0], 0)
        self.assertEqual(json.loads(self.cli('list', '--config', str(self.cfg_path))[1])['revoked_agents'], [])
        code, out, _ = self.cli('drill', '--config', str(self.cfg_path))
        report = json.loads(out)
        self.assertEqual((code, report['ok'], report['touched_real_state']), (0, True, False))
        self.assertEqual(len((Path(self.tmp.name) / 'c.jsonl').read_text(encoding='utf-8').splitlines()), 1)  # drill added nothing


if __name__ == '__main__':
    unittest.main()
