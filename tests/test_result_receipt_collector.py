import importlib.util
import json
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("result_receipt_collector", ROOT / "scripts" / "result_receipt_collector.py")
assert SPEC is not None
collector = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["result_receipt_collector"] = collector
SPEC.loader.exec_module(collector)


class ResultReceiptCollectorTests(unittest.TestCase):
    def start_collector(self, config: collector.CollectorConfig) -> str:
        server = collector.ThreadingHTTPServer(("127.0.0.1", 0), collector.CollectorHandler)
        server.config = config
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(thread.join, 2)
        self.addCleanup(server.server_close)
        host, port = server.server_address
        return f"http://{host}:{port}"

    def request_json(self, base_url: str, path: str, payload: dict, token: str = "collector-token") -> tuple[int, dict]:
        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": "req-test",
            "X-ASG-Agent-Id": "nuc7cjyh",
            "X-ASG-Route-Id": "mac.result_receipt.notify",
        }
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, json.loads(exc.read().decode("utf-8"))
            finally:
                exc.close()

    def make_config(self, store_path: Path) -> collector.CollectorConfig:
        return collector.CollectorConfig(
            bind="127.0.0.1",
            port=0,
            store_path=store_path,
            token="collector-token",
            max_body_bytes=8192,
        )

    def receipt(self) -> dict:
        return {
            "ok": True,
            "receipt_type": "asg_result_audit",
            "decision": "allow",
            "request_id": "req-result",
            "route_id": "mac.result_receipt.notify",
            "content_sha256": "abc123",
        }

    def test_stores_valid_receipt_without_raw_report_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "receipts.jsonl"
            base = self.start_collector(self.make_config(store_path))
            status, body = self.request_json(base, "/asg/result-receipts", self.receipt())
            self.assertEqual(status, 200)
            self.assertTrue(body["stored"])
            record = json.loads(store_path.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(record["receipt"]["receipt_type"], "asg_result_audit")
            self.assertEqual(record["headers"]["x_asg_agent_id"], "nuc7cjyh")
            self.assertEqual(record["headers"]["x_asg_route_id"], "mac.result_receipt.notify")

    def test_rejects_missing_auth_when_token_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self.start_collector(self.make_config(Path(tmp) / "receipts.jsonl"))
            status, body = self.request_json(base, "/asg/result-receipts", self.receipt(), token="")
            self.assertEqual(status, 401)
            self.assertEqual(body["error"]["code"], "unauthorized")

    def test_rejects_non_receipt_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self.start_collector(self.make_config(Path(tmp) / "receipts.jsonl"))
            status, body = self.request_json(base, "/asg/result-receipts", {"ok": True})
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_receipt")


if __name__ == "__main__":
    unittest.main()
