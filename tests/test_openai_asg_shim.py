import importlib.util
import json
import sys
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("openai_asg_shim", ROOT / "scripts" / "openai_asg_shim.py")
assert SPEC is not None
shim = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["openai_asg_shim"] = shim
SPEC.loader.exec_module(shim)


class FakeASGHandler(shim.http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        self.server.request_count = getattr(self.server, "request_count", 0) + 1  # type: ignore[attr-defined]
        self.server.last_path = self.path  # type: ignore[attr-defined]
        self.server.last_headers = dict(self.headers)  # type: ignore[attr-defined]
        self.server.last_body = json.loads(raw.decode("utf-8"))  # type: ignore[attr-defined]
        response_status = getattr(self.server, "response_status", 200)
        response_statuses = getattr(self.server, "response_statuses", None)
        if response_statuses:
            response_status = response_statuses.pop(0)
        if self.path == "/v1/results":
            response_body = {
                "ok": True,
                "receipt_type": "asg_result_audit",
                "decision": "allow",
                "request_id": "req-result",
                "route_id": "mac.result_receipt.notify",
                "delivery": {"raw_report_forwarded": False, "backend_status": 200},
            }
        else:
            response_body = {
                "id": "chatcmpl-test",
                "object": "chat.completion",
                "choices": [{"message": {"role": "assistant", "content": "shim ok"}}],
            }
        if response_status == 429:
            response_body = {"error": "rate_limited", "request_id": "req-rate-limited"}
        encoded = json.dumps(response_body).encode("utf-8")
        self.send_response(response_status)
        if response_status == 429:
            self.send_header("Retry-After", "0.01")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt, *args):
        return


class OpenAIASGShimTests(unittest.TestCase):
    def setUp(self) -> None:
        with shim._RESULT_RATE_LOCK:
            shim._RESULT_SEND_TIMES.clear()

    def start_fake_asg(self) -> tuple[str, shim.http.server.ThreadingHTTPServer]:
        server = shim.http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeASGHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        host, port = server.server_address
        return f"http://{host}:{port}", server

    def start_shim(self, config: shim.ShimConfig) -> str:
        server = shim.ThreadingHTTPServer(("127.0.0.1", 0), shim.ShimHandler)
        server.config = config
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        host, port = server.server_address
        return f"http://{host}:{port}"

    def request_json(self, base_url: str, path: str, payload: dict | None = None) -> tuple[int, dict]:
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            base_url + path,
            data=data,
            method="GET" if payload is None else "POST",
            headers={"Content-Type": "application/json", "X-Request-ID": "req-test"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            finally:
                exc.close()

    def make_config(self, asg_base_url: str) -> shim.ShimConfig:
        return shim.ShimConfig(
            bind="127.0.0.1",
            port=0,
            asg_base_url=asg_base_url,
            asg_path="/v1/chat/completions",
            asg_token="shim-token",
            route_id="mac.local_llm.chat",
            capability="delegate_local_llm",
            taint=["trusted_instruction"],
            model_id="asg/mac-local-llm",
            model_alias="asg/mac-local-llm",
            result_message_type="worker_report",
            timeout_seconds=5,
            max_body_bytes=8192,
            strip_tooling=True,
            allowed_message_roles={"user", "assistant"},
        )

    def test_models_endpoint_is_local(self):
        base = self.start_shim(self.make_config("http://127.0.0.1:1"))
        status, body = self.request_json(base, "/v1/models")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"][0]["id"], "asg/mac-local-llm")

    def test_chat_forwarding_injects_fixed_asg_policy_fields(self):
        asg_base, fake_asg = self.start_fake_asg()
        base = self.start_shim(self.make_config(asg_base))
        payload = {
            "model": "caller-model",
            "messages": [{"role": "user", "content": "hello"}],
            "metadata": {
                "route_id": "caller.route",
                "capability": "caller_capability",
                "taint": ["untrusted_web"],
                "run_id": "run-1",
            },
        }
        status, body = self.request_json(base, "/v1/chat/completions", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["choices"][0]["message"]["content"], "shim ok")

        self.assertEqual(fake_asg.last_headers["Authorization"], "Bearer shim-token")  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_headers["X-Asg-Route"], "mac.local_llm.chat")  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_headers["X-Agent-Capability"], "delegate_local_llm")  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_headers["X-Request-Id"], "req-test")  # type: ignore[attr-defined]
        outbound = fake_asg.last_body  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_path, "/v1/chat/completions")  # type: ignore[attr-defined]
        self.assertEqual(outbound["model"], "asg/mac-local-llm")
        self.assertEqual(outbound["metadata"]["route_id"], "mac.local_llm.chat")
        self.assertEqual(outbound["metadata"]["capability"], "delegate_local_llm")
        self.assertEqual(outbound["metadata"]["taint"], ["trusted_instruction"])
        self.assertEqual(outbound["metadata"]["run_id"], "run-1")

    def test_results_mode_wraps_chat_input_as_audited_result(self):
        asg_base, fake_asg = self.start_fake_asg()
        config = self.make_config(asg_base)
        config = shim.dataclasses.replace(
            config,
            asg_path="/v1/results",
            route_id="mac.result_receipt.notify",
            capability="notify_audited_result",
            taint=["model_output"],
            model_id="asg/mac-result-receipt",
            model_alias="asg/mac-result-receipt",
            result_message_type="worker_report",
        )
        base = self.start_shim(config)
        payload = {
            "model": "caller-model",
            "messages": [
                {"role": "system", "content": "private control prompt"},
                {"role": "user", "content": "work completed"},
                {"role": "tool", "content": "hidden tool output"},
            ],
            "metadata": {
                "route_id": "caller.route",
                "capability": "caller_capability",
                "taint": ["untrusted_web"],
                "run_id": "run-1",
                "task_id": "task-1",
            },
        }
        status, body = self.request_json(base, "/v1/chat/completions", payload)
        self.assertEqual(status, 200)
        self.assertEqual(body["object"], "chat.completion")
        receipt = json.loads(body["choices"][0]["message"]["content"])
        self.assertEqual(receipt["receipt_type"], "asg_result_audit")
        self.assertFalse(receipt["delivery"]["raw_report_forwarded"])

        self.assertEqual(fake_asg.last_path, "/v1/results")  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_headers["X-Asg-Route"], "mac.result_receipt.notify")  # type: ignore[attr-defined]
        self.assertEqual(fake_asg.last_headers["X-Agent-Capability"], "notify_audited_result")  # type: ignore[attr-defined]
        outbound = fake_asg.last_body  # type: ignore[attr-defined]
        self.assertEqual(outbound["route_id"], "mac.result_receipt.notify")
        self.assertEqual(outbound["capability"], "notify_audited_result")
        self.assertEqual(outbound["taint"], ["model_output"])
        self.assertEqual(outbound["message_type"], "worker_report")
        self.assertEqual(outbound["messages"], [{"role": "user", "content": "work completed"}])
        self.assertEqual(outbound["run_id"], "run-1")
        self.assertEqual(outbound["task_id"], "task-1")
        self.assertEqual(outbound["metadata"]["route_id"], "mac.result_receipt.notify")
        self.assertEqual(outbound["metadata"]["capability"], "notify_audited_result")
        self.assertEqual(outbound["metadata"]["taint"], ["model_output"])
        self.assertEqual(outbound["metadata"]["source_model"], "caller-model")
        self.assertNotIn("model", outbound)

    def test_results_mode_retries_429_with_backoff(self):
        asg_base, fake_asg = self.start_fake_asg()
        fake_asg.response_statuses = [429, 200]  # type: ignore[attr-defined]
        config = shim.dataclasses.replace(
            self.make_config(asg_base),
            asg_path="/v1/results",
            route_id="mac.result_receipt.notify",
            capability="notify_audited_result",
            taint=["model_output"],
            model_id="asg/mac-result-receipt",
            model_alias="asg/mac-result-receipt",
            rate_limit_backoff_seconds=0.01,
            rate_limit_backoff_max_seconds=0.01,
        )
        base = self.start_shim(config)
        payload = {"model": "caller-model", "messages": [{"role": "user", "content": "work completed"}]}
        status, body = self.request_json(base, "/v1/chat/completions", payload)

        self.assertEqual(status, 200)
        receipt = json.loads(body["choices"][0]["message"]["content"])
        self.assertEqual(receipt["receipt_type"], "asg_result_audit")
        self.assertEqual(fake_asg.request_count, 2)  # type: ignore[attr-defined]

    def test_results_mode_does_not_retry_429_when_retries_are_zero(self):
        asg_base, fake_asg = self.start_fake_asg()
        fake_asg.response_statuses = [429, 200]  # type: ignore[attr-defined]
        config = shim.dataclasses.replace(
            self.make_config(asg_base),
            asg_path="/v1/results",
            route_id="mac.result_receipt.notify",
            capability="notify_audited_result",
            taint=["model_output"],
            model_id="asg/mac-result-receipt",
            model_alias="asg/mac-result-receipt",
            rate_limit_max_retries=0,
        )
        base = self.start_shim(config)
        payload = {"model": "caller-model", "messages": [{"role": "user", "content": "work completed"}]}
        status, body = self.request_json(base, "/v1/chat/completions", payload)

        self.assertEqual(status, 429)
        self.assertEqual(body["error"], "rate_limited")
        self.assertEqual(fake_asg.request_count, 1)  # type: ignore[attr-defined]

    def test_results_mode_local_rate_limit_waits_for_send_slot(self):
        config = shim.dataclasses.replace(
            self.make_config("http://127.0.0.1:1"),
            asg_path="/v1/results",
            results_max_per_minute=2,
        )
        now = [1000.0]
        sleeps: list[float] = []

        def monotonic() -> float:
            return now[0]

        def sleep(seconds: float) -> None:
            sleeps.append(seconds)
            now[0] += seconds

        with mock.patch.object(shim.time, "monotonic", monotonic), mock.patch.object(shim.time, "sleep", sleep):
            shim.wait_for_result_send_slot(config)
            shim.wait_for_result_send_slot(config)
            shim.wait_for_result_send_slot(config)

        self.assertEqual(sleeps, [60.0])
        with shim._RESULT_RATE_LOCK:
            self.assertEqual(list(shim._RESULT_SEND_TIMES), [1060.0])

    def test_rate_limit_sleep_prefers_retry_after_and_clamps_to_max(self):
        config = shim.dataclasses.replace(
            self.make_config("http://127.0.0.1:1"),
            rate_limit_backoff_seconds=5.0,
            rate_limit_backoff_max_seconds=2.0,
        )
        self.assertEqual(shim.rate_limit_sleep_seconds(config, 1, 0.25), 0.25)
        self.assertEqual(shim.rate_limit_sleep_seconds(config, 1, 10.0), 2.0)

        exponential_config = shim.dataclasses.replace(
            self.make_config("http://127.0.0.1:1"),
            rate_limit_backoff_seconds=1.0,
            rate_limit_backoff_max_seconds=10.0,
        )
        self.assertEqual(shim.rate_limit_sleep_seconds(exponential_config, 3, None), 4.0)

    def test_parse_float_rejects_non_finite_values(self):
        with mock.patch.dict(shim.os.environ, {"ASG_SHIM_429_BACKOFF_SECONDS": "nan"}):
            with self.assertRaises(shim.ShimError):
                shim._parse_float("ASG_SHIM_429_BACKOFF_SECONDS", 1.0, minimum=0.1, maximum=60.0)

    def test_chat_forwarding_strips_tooling_and_control_roles_by_default(self):
        asg_base, fake_asg = self.start_fake_asg()
        base = self.start_shim(self.make_config(asg_base))
        payload = {
            "model": "caller-model",
            "messages": [
                {"role": "system", "content": "private control prompt"},
                {"role": "user", "content": "hello", "name": "caller"},
                {"role": "assistant", "content": "hi", "tool_calls": [{"id": "call_1"}]},
                {"role": "tool", "tool_call_id": "call_1", "content": "tool result"},
            ],
            "tools": [{"type": "function", "function": {"name": "delete_file"}}],
            "tool_choice": "auto",
        }
        status, _ = self.request_json(base, "/v1/chat/completions", payload)
        self.assertEqual(status, 200)
        outbound = fake_asg.last_body  # type: ignore[attr-defined]
        self.assertNotIn("tools", outbound)
        self.assertNotIn("tool_choice", outbound)
        self.assertEqual(
            outbound["messages"],
            [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
            ],
        )

    def test_invalid_json_is_rejected_before_forwarding(self):
        base = self.start_shim(self.make_config("http://127.0.0.1:1"))
        request = urllib.request.Request(
            base + "/v1/chat/completions",
            data=b"not-json",
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request, timeout=5)
        self.assertEqual(caught.exception.code, 400)
        body = json.loads(caught.exception.read().decode("utf-8"))
        self.assertEqual(body["error"]["code"], "invalid_json")

    def test_streaming_request_gets_sse_chunks_from_full_asg_response(self):
        asg_base, _ = self.start_fake_asg()
        base = self.start_shim(self.make_config(asg_base))
        request = urllib.request.Request(
            base + "/v1/chat/completions",
            data=json.dumps(
                {
                    "model": "caller-model",
                    "stream": True,
                    "messages": [{"role": "user", "content": "hello"}],
                }
            ).encode("utf-8"),
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers["Content-Type"], "text/event-stream; charset=utf-8")
            text = response.read().decode("utf-8")
        self.assertIn('"object": "chat.completion.chunk"', text)
        self.assertIn('"content": "shim ok"', text)
        self.assertTrue(text.rstrip().endswith("data: [DONE]"))


if __name__ == "__main__":
    unittest.main()
