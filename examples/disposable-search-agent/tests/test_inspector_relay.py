import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract
import inspector_relay as relay


def body(model):
    return {'model': model, 'messages': [{'role': 'system', 'content': 'classify'},
            {'role': 'user', 'content': 'SECRET-LOOKING-CONTENT-123 please classify'}],
            'max_tokens': 16, 'temperature': 0, 'stream': False}


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.log = os.path.join(self.tmp.name, 'relay.log')
        patches = [patch.object(relay, 'LOG_PATH', self.log), patch.object(relay, 'INSPECTOR_MODEL', 'insp'),
                   patch.object(relay, '_slots', threading.BoundedSemaphore(2))]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.server = relay.Server(('127.0.0.1', 0), relay.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.url = 'http://127.0.0.1:%d/v1/chat/completions' % self.server.server_address[1]

    def post(self, payload=None):
        req = urllib.request.Request(self.url, data=json.dumps(payload or body('insp')).encode(), method='POST',
                                     headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def events(self):
        return [json.loads(x) for x in Path(self.log).read_text(encoding='utf-8').splitlines()]

    def test_concurrent_requests_run_in_parallel(self):
        def slow(*a, **k):
            time.sleep(0.6)
            return 'ok'
        with patch.object(relay.model_broker, 'complete', side_effect=slow):
            results = []
            started = time.monotonic()
            threads = [threading.Thread(target=lambda: results.append(self.post())) for _ in range(2)]
            [t.start() for t in threads]
            [t.join() for t in threads]
            elapsed = time.monotonic() - started
        self.assertEqual([r[0] for r in results], [200, 200])
        self.assertLess(elapsed, 1.1)  # serial would take >= 1.2 s

    def test_bounded_concurrency_fails_closed_when_busy(self):
        gate = threading.Event()
        def blocked(*a, **k):
            gate.wait(5)
            return 'ok'
        with patch.object(relay, 'DEADLINE_SECONDS', 9), patch.object(relay, 'MIN_RETRY_SECONDS', 8), \
                patch.object(relay.model_broker, 'complete', side_effect=blocked):
            holders = [threading.Thread(target=self.post) for _ in range(2)]
            [t.start() for t in holders]
            time.sleep(0.3)
            status, reply = self.post()  # third request: no slot within (deadline - min_retry) = 1 s
            gate.set()
            [t.join() for t in holders]
        self.assertEqual((status, reply['error']['code']), (503, 'inspector_busy'))

    def test_one_retry_on_transient_failure(self):
        calls = []
        def flaky(*a, **k):
            calls.append(1)
            if len(calls) == 1:
                raise ConnectionResetError('reset')
            return 'description'
        with patch.object(relay.model_broker, 'complete', side_effect=flaky):
            status, reply = self.post()
        self.assertEqual(status, 200)
        self.assertEqual(reply['choices'][0]['message']['content'], 'description')
        self.assertEqual(self.events()[-1]['attempts'], 2)

    def test_at_most_two_attempts_then_non_200(self):
        with patch.object(relay.model_broker, 'complete', side_effect=contract.BoundaryError('invalid_contract')) as c:
            status, reply = self.post()
        self.assertEqual((status, c.call_count), (502, 2))
        self.assertEqual(self.events()[-1]['error_class'], 'BoundaryError')

    def test_invalid_requests_refused_and_never_reach_upstream(self):
        with patch.object(relay.model_broker, 'complete') as c:
            for bad in (body('other-model'), dict(body('insp'), tools=[]), dict(body('insp'), temperature=1)):
                self.assertEqual(self.post(bad)[0], 400)
        c.assert_not_called()

    def test_log_is_metadata_only(self):
        with patch.object(relay.model_broker, 'complete', return_value='MODEL-OUTPUT-XYZ'):
            self.post()
        text = Path(self.log).read_text(encoding='utf-8')
        self.assertNotIn('SECRET-LOOKING-CONTENT-123', text)
        self.assertNotIn('MODEL-OUTPUT-XYZ', text)
        event = self.events()[-1]
        self.assertEqual(event['status'], 200)
        self.assertTrue({'ms', 'req', 'attempts', 'queue_ms', 'request_bytes', 'response_chars'} <= set(event))


if __name__ == '__main__':
    unittest.main()
