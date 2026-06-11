import importlib.util
import datetime as dt
import hashlib
import hmac
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

    def request_json(
        self,
        base_url: str,
        path: str,
        payload: dict,
        token: str = "collector-token",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        headers = {
            "Content-Type": "application/json",
            "X-Request-ID": "req-test",
            "X-ASG-Agent-Id": "nuc7cjyh",
            "X-ASG-Route-Id": "mac.result_receipt.notify",
        }
        if token:
            headers["Authorization"] = "Bearer " + token
        if extra_headers:
            headers.update(extra_headers)
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
            anchor_store_path=store_path.with_name("audit-anchors.jsonl"),
            token="collector-token",
            max_body_bytes=8192,
            hmac_key="",
            signature_max_age_seconds=300,
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

    def test_stores_valid_audit_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt_store = Path(tmp) / "receipts.jsonl"
            anchor_store = Path(tmp) / "anchors.jsonl"
            config = self.make_config(receipt_store)
            config = collector.dataclasses.replace(config, anchor_store_path=anchor_store)
            base = self.start_collector(config)
            payload = {
                "anchor_type": "asg_audit_anchor",
                "latest_hash": "a" * 64,
                "line_count": 12,
                "timestamp": "2026-06-11T00:00:00+00:00",
            }
            status, body = self.request_json(base, "/asg/audit-anchors", payload)
            self.assertEqual(status, 200)
            self.assertTrue(body["stored"])
            record = json.loads(anchor_store.read_text(encoding="utf-8").splitlines()[-1])
            self.assertEqual(record["anchor"]["latest_hash"], "a" * 64)
            self.assertEqual(record["anchor"]["line_count"], 12)
            self.assertFalse(receipt_store.exists())

    def test_rejects_invalid_audit_anchor(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = self.start_collector(self.make_config(Path(tmp) / "receipts.jsonl"))
            payload = {
                "anchor_type": "asg_audit_anchor",
                "latest_hash": "not-a-hash",
                "line_count": 1,
                "timestamp": "2026-06-11T00:00:00+00:00",
            }
            status, body = self.request_json(base, "/asg/audit-anchors", payload)
            self.assertEqual(status, 400)
            self.assertEqual(body["error"]["code"], "invalid_anchor")

    def signed_headers(
        self,
        payload: dict,
        *,
        hmac_key: str = "collector-hmac-key",
        timestamp: str | None = None,
        route_id: str = "mac.result_receipt.notify",
    ) -> dict[str, str]:
        raw = json.dumps(payload).encode("utf-8")
        body_sha256 = hashlib.sha256(raw).hexdigest()
        timestamp = timestamp or dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        canonical = collector.backend_signature_canonical(
            "POST",
            "/asg/result-receipts",
            body_sha256,
            "nuc7cjyh",
            route_id,
            "",
            "",
            timestamp,
        )
        return {
            "X-ASG-Request-SHA256": body_sha256,
            "X-ASG-Timestamp": timestamp,
            "X-ASG-Signature": "sha256=" + hmac.new(hmac_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest(),
        }

    def test_accepts_valid_asg_signature_when_hmac_key_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            store_path = Path(tmp) / "receipts.jsonl"
            config = self.make_config(store_path)
            config = collector.dataclasses.replace(config, hmac_key="collector-hmac-key")
            base = self.start_collector(config)
            payload = self.receipt()
            status, body = self.request_json(base, "/asg/result-receipts", payload, extra_headers=self.signed_headers(payload))
            self.assertEqual(status, 200)
            self.assertTrue(body["stored"])

    def test_rejects_missing_asg_signature_when_hmac_key_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp) / "receipts.jsonl")
            config = collector.dataclasses.replace(config, hmac_key="collector-hmac-key")
            base = self.start_collector(config)
            status, body = self.request_json(base, "/asg/result-receipts", self.receipt())
            self.assertEqual(status, 401)
            self.assertEqual(body["error"]["code"], "signature_required")

    def test_rejects_tampered_asg_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp) / "receipts.jsonl")
            config = collector.dataclasses.replace(config, hmac_key="collector-hmac-key")
            base = self.start_collector(config)
            payload = self.receipt()
            headers = self.signed_headers(payload)
            replacement = "1" if headers["X-ASG-Signature"].endswith("0") else "0"
            headers["X-ASG-Signature"] = headers["X-ASG-Signature"][:-1] + replacement
            status, body = self.request_json(base, "/asg/result-receipts", payload, extra_headers=headers)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "signature_invalid")

    def test_rejects_expired_asg_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = self.make_config(Path(tmp) / "receipts.jsonl")
            config = collector.dataclasses.replace(config, hmac_key="collector-hmac-key", signature_max_age_seconds=300)
            base = self.start_collector(config)
            payload = self.receipt()
            old_timestamp = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=3600)).isoformat(timespec="seconds")
            headers = self.signed_headers(payload, timestamp=old_timestamp)
            status, body = self.request_json(base, "/asg/result-receipts", payload, extra_headers=headers)
            self.assertEqual(status, 403)
            self.assertEqual(body["error"]["code"], "signature_stale")


if __name__ == "__main__":
    unittest.main()
