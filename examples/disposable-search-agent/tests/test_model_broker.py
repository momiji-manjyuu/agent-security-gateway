import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract
import model_broker
import runtime


class ModelTests(unittest.TestCase):
    def request(self):
        return {'version': 1, 'type': 'inference_request', 'question': 'Test question',
                'documents': [{'source_id': 's1', 'text': 'Public note'}]}

    def bundle(self):
        bundle = runtime.demo_bundle()
        bundle['question'] = 'Test question'
        return bundle

    def test_broker_cannot_be_given_a_destination_or_another_source(self):
        request = self.request()
        request['base_url'] = 'http://127.0.0.1/'
        with self.assertRaises(contract.BoundaryError):
            model_broker.worker_inference(request, self.bundle())
        request = self.request()
        request['documents'][0]['source_id'] = 's99'
        with self.assertRaises(contract.BoundaryError):
            model_broker.worker_inference(request, self.bundle())

    def test_broker_uses_one_fresh_session_and_configured_worker_model(self):
        with patch.object(model_broker, 'WORKER_MODEL', 'worker-model-test'), \
                patch.object(model_broker, 'complete', return_value='{}') as complete:
            model_broker.worker_inference(self.request(), self.bundle())
        self.assertEqual(complete.call_args.args[0], 'worker-model-test')
        self.assertEqual(len(complete.call_args.args[1]), 2)
        self.assertNotIn('base_url', json.dumps(complete.call_args.args[1]))

    def test_stdio_worker_round_trip_and_result_validation(self):
        result = {'version': 1, 'findings': [{'source_id': 's1', 'excerpt': 'Public note'}]}
        command = [sys.executable, '-I', str(runtime.ROOT / 'worker.py')]
        def infer(request, bundle, timeout):
            self.assertEqual(request['question'], bundle['question'])
            return json.dumps(result)
        with patch.dict(os.environ, {'WORKER_MODEL_MODE': 'broker'}):
            actual = runtime.model_process(command, self.bundle(), infer=infer, timeout=5)
        self.assertEqual(actual, result)
        result['findings'][0]['source_id'] = 's99'
        with patch.dict(os.environ, {'WORKER_MODEL_MODE': 'broker'}), self.assertRaises(Exception):
            runtime.model_process(command, self.bundle(), infer=infer, timeout=2)

    def test_model_container_retains_network_and_secret_isolation(self):
        command = runtime.docker_command('disposable-search-test', model=True)
        self.assertIn('--network=none', command)
        self.assertIn('WORKER_MODEL_MODE=broker', command)
        self.assertFalse(any('TOKEN=' in arg or 'KEY=' in arg or 'volume' in arg for arg in command))


class EndpointConfigTests(unittest.TestCase):
    def test_complete_fails_closed_without_an_operator_set_endpoint(self):
        for host, port in (('', 4000), ('model.internal', 0), ('', 0)):
            with patch.object(model_broker, 'WORKER_MODEL', 'worker-model-test'), \
                    patch.object(model_broker, 'INSPECTOR_MODEL', 'inspector-model-test'), \
                    patch.object(model_broker, 'MODEL_HOST', host), patch.object(model_broker, 'MODEL_PORT', port):
                with patch.object(model_broker.http.client, 'HTTPConnection') as connect:
                    with self.assertRaises(Exception):
                        model_broker.complete('worker-model-test', [{'role': 'user', 'content': 'x'}])
                    connect.assert_not_called()

    def test_complete_fails_closed_without_configured_model_names(self):
        # Unset/blank model names, and any caller-chosen model, must not reach HTTP.
        for worker, inspector, model in (('', 'inspector-model-test', 'inspector-model-test'),
                                         ('worker-model-test', '', 'worker-model-test'),
                                         ('worker-model-test', 'inspector-model-test', 'caller-chosen-model')):
            with patch.object(model_broker, 'WORKER_MODEL', worker), \
                    patch.object(model_broker, 'INSPECTOR_MODEL', inspector), \
                    patch.object(model_broker, 'MODEL_HOST', 'model.internal'), \
                    patch.object(model_broker, 'MODEL_PORT', 4000):
                with patch.object(model_broker.http.client, 'HTTPConnection') as connect:
                    with self.assertRaises(Exception):
                        model_broker.complete(model, [{'role': 'user', 'content': 'x'}])
                    connect.assert_not_called()

    def test_endpoint_is_read_from_the_environment_only(self):
        with open(model_broker.__file__, encoding='utf-8') as fh:
            source = fh.read()
        self.assertIn("os.environ.get('MODEL_BROKER_HOST'", source)
        self.assertNotRegex(source, r"MODEL_HOST\s*=\s*['\"][0-9]")

    def test_model_names_are_read_from_the_environment_only(self):
        with open(model_broker.__file__, encoding='utf-8') as fh:
            source = fh.read()
        self.assertIn("os.environ.get('MODEL_BROKER_WORKER_MODEL'", source)
        self.assertIn("os.environ.get('MODEL_BROKER_INSPECTOR_MODEL'", source)
        self.assertNotRegex(source, r"(?:WORKER_MODEL|INSPECTOR_MODEL)\s*=\s*['\"][^'\"]+['\"]")


if __name__ == '__main__':
    unittest.main()
