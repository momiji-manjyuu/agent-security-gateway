#!/usr/bin/env python3
"""Minimal receiver for ASG result audit receipts."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import hmac
import http.server
import json
import os
import stat
import sys
import time
import urllib.parse
import uuid
from pathlib import Path
from typing import Any


APP_NAME = "asg-result-receipt-collector"
VERSION = "0.1.0"
DEFAULT_MAX_BODY_BYTES = 262_144


class CollectorError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclasses.dataclass(frozen=True)
class CollectorConfig:
    bind: str
    port: int
    store_path: Path
    anchor_store_path: Path
    token: str
    max_body_bytes: int
    hmac_key: str
    signature_max_age_seconds: int


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def _parse_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _env(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise CollectorError(500, "invalid_config", f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise CollectorError(500, "invalid_config", f"{name} must be between {minimum} and {maximum}")
    return value


def _read_token() -> str:
    token = _env("ASG_RECEIPT_COLLECTOR_TOKEN")
    token_file = _env("ASG_RECEIPT_COLLECTOR_TOKEN_FILE")
    if token and token_file:
        raise CollectorError(500, "invalid_config", "set ASG_RECEIPT_COLLECTOR_TOKEN or ASG_RECEIPT_COLLECTOR_TOKEN_FILE, not both")
    if token:
        return token
    if token_file:
        try:
            return Path(token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise CollectorError(500, "invalid_config", "could not read ASG_RECEIPT_COLLECTOR_TOKEN_FILE") from exc
    return ""


def load_config_from_env() -> CollectorConfig:
    return CollectorConfig(
        bind=_env("ASG_RECEIPT_COLLECTOR_BIND", "127.0.0.1"),
        port=_parse_int("ASG_RECEIPT_COLLECTOR_PORT", 8789, minimum=1, maximum=65_535),
        store_path=Path(_env("ASG_RECEIPT_COLLECTOR_STORE", "~/.agent-security-gateway/result-receipts.jsonl")).expanduser(),
        anchor_store_path=Path(_env("ASG_RECEIPT_COLLECTOR_ANCHOR_STORE", "~/.agent-security-gateway/audit-anchors.jsonl")).expanduser(),
        token=_read_token(),
        max_body_bytes=_parse_int("ASG_RECEIPT_COLLECTOR_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, minimum=1, maximum=10 * 1024 * 1024),
        hmac_key=_env("ASG_RECEIPT_COLLECTOR_HMAC_KEY"),
        signature_max_age_seconds=_parse_int("ASG_RECEIPT_COLLECTOR_SIGNATURE_MAX_AGE_SECONDS", 300, minimum=1, maximum=86_400),
    )


def json_error(code: str, message: str, request_id: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def parse_timestamp(value: str) -> dt.datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def backend_signature_canonical(
    method: str,
    backend_path: str,
    body_sha256: str,
    agent_id: str,
    route_id: str,
    run_id: str,
    task_id: str,
    timestamp: str,
) -> str:
    return "\n".join(
        [
            method.upper(),
            backend_path or "/",
            body_sha256,
            agent_id,
            route_id,
            run_id,
            task_id,
            timestamp,
        ]
    )


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass


def append_receipt(config: CollectorConfig, record: dict[str, Any]) -> None:
    append_jsonl(config.store_path, record)


def append_anchor(config: CollectorConfig, record: dict[str, Any]) -> None:
    append_jsonl(config.anchor_store_path, record)


def validate_audit_anchor(payload: dict[str, Any]) -> None:
    if payload.get("anchor_type") != "asg_audit_anchor":
        raise CollectorError(400, "invalid_anchor", "anchor_type must be asg_audit_anchor")
    latest_hash = payload.get("latest_hash")
    if not isinstance(latest_hash, str) or len(latest_hash) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in latest_hash):
        raise CollectorError(400, "invalid_anchor", "latest_hash must be a SHA-256 hex digest")
    line_count = payload.get("line_count")
    if isinstance(line_count, bool) or not isinstance(line_count, int) or line_count < 0:
        raise CollectorError(400, "invalid_anchor", "line_count must be a non-negative integer")
    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or not timestamp.strip():
        raise CollectorError(400, "invalid_anchor", "timestamp must be a non-empty string")
    try:
        parse_timestamp(timestamp)
    except ValueError as exc:
        raise CollectorError(400, "invalid_anchor", "timestamp must be an ISO-8601 timestamp") from exc


class CollectorHandler(http.server.BaseHTTPRequestHandler):
    server_version = "ASGResultReceiptCollector/" + VERSION

    def do_GET(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-ID") or "collector_" + uuid.uuid4().hex
        if self.path in {"/healthz", "/readyz"}:
            self.write_json(200, {"ok": True, "app": APP_NAME, "version": VERSION})
            return
        self.write_json(404, json_error("not_found", "not found", request_id))

    def do_POST(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-ID") or "collector_" + uuid.uuid4().hex
        config = self.server.config  # type: ignore[attr-defined]
        try:
            if self.path == "/asg/result-receipts":
                self.handle_result_receipt(config, request_id)
                return
            if self.path == "/asg/audit-anchors":
                self.handle_audit_anchor(config, request_id)
                return
            raise CollectorError(404, "not_found", "not found")
        except CollectorError as exc:
            self.write_json(exc.status, json_error(exc.code, exc.message, request_id))
        except Exception:  # noqa: BLE001
            self.write_json(500, json_error("internal_error", "internal error", request_id))

    def handle_result_receipt(self, config: CollectorConfig, request_id: str) -> None:
        self.verify_auth(config)
        raw_body, payload = self.read_json_body(config)
        self.verify_signature(config, raw_body)
        if payload.get("receipt_type") != "asg_result_audit":
            raise CollectorError(400, "invalid_receipt", "receipt_type must be asg_result_audit")
        record = {
            "received_at": utc_now(),
            "request_id": request_id,
            "remote_addr": self.client_address[0],
            "headers": {
                "x_asg_agent_id": self.headers.get("X-ASG-Agent-Id", ""),
                "x_asg_route_id": self.headers.get("X-ASG-Route-Id", ""),
                "x_asg_request_sha256": self.headers.get("X-ASG-Request-SHA256", ""),
                "x_asg_timestamp": self.headers.get("X-ASG-Timestamp", ""),
            },
            "receipt": payload,
        }
        append_receipt(config, record)
        self.write_json(200, {"ok": True, "stored": True, "request_id": request_id})

    def handle_audit_anchor(self, config: CollectorConfig, request_id: str) -> None:
        self.verify_auth(config)
        _, payload = self.read_json_body(config)
        validate_audit_anchor(payload)
        record = {
            "received_at": utc_now(),
            "request_id": request_id,
            "remote_addr": self.client_address[0],
            "anchor": payload,
        }
        append_anchor(config, record)
        self.write_json(200, {"ok": True, "stored": True, "request_id": request_id})

    def verify_auth(self, config: CollectorConfig) -> None:
        if not config.token:
            return
        expected = "Bearer " + config.token
        if self.headers.get("Authorization", "") != expected:
            raise CollectorError(401, "unauthorized", "missing or invalid bearer token")

    def verify_signature(self, config: CollectorConfig, raw_body: bytes) -> None:
        if not config.hmac_key:
            return
        signature = self.headers.get("X-ASG-Signature", "")
        if not signature:
            raise CollectorError(401, "signature_required", "missing ASG signature")
        timestamp = self.headers.get("X-ASG-Timestamp", "")
        if not timestamp:
            raise CollectorError(401, "signature_required", "missing ASG timestamp")
        body_sha256 = hashlib.sha256(raw_body).hexdigest()
        header_body_sha256 = self.headers.get("X-ASG-Request-SHA256", "")
        if not hmac.compare_digest(header_body_sha256, body_sha256):
            raise CollectorError(403, "signature_invalid", "request body hash does not match ASG header")
        try:
            parsed_timestamp = parse_timestamp(timestamp)
        except ValueError as exc:
            raise CollectorError(403, "signature_invalid", "invalid ASG timestamp") from exc
        age = abs((dt.datetime.now(dt.timezone.utc) - parsed_timestamp).total_seconds())
        if age > config.signature_max_age_seconds:
            raise CollectorError(403, "signature_stale", "ASG signature timestamp is outside the allowed freshness window")
        path = urllib.parse.urlsplit(self.path).path or "/"
        canonical = backend_signature_canonical(
            "POST",
            path,
            body_sha256,
            self.headers.get("X-ASG-Agent-Id", ""),
            self.headers.get("X-ASG-Route-Id", ""),
            self.headers.get("X-ASG-Run-Id", ""),
            self.headers.get("X-ASG-Task-Id", ""),
            timestamp,
        )
        expected = "sha256=" + hmac.new(config.hmac_key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            raise CollectorError(403, "signature_invalid", "ASG signature is invalid")

    def read_json_body(self, config: CollectorConfig) -> tuple[bytes, dict[str, Any]]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise CollectorError(400, "invalid_json", "invalid Content-Length") from exc
        if length < 0 or length > config.max_body_bytes:
            raise CollectorError(413, "request_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise CollectorError(400, "invalid_json", "request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise CollectorError(400, "invalid_json", "request body must be a JSON object")
        return raw, payload

    def write_json(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (utc_now(), fmt % args))


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    config: CollectorConfig


def serve(config: CollectorConfig) -> None:
    server = ThreadingHTTPServer((config.bind, config.port), CollectorHandler)
    server.config = config
    print(f"{APP_NAME} listening on http://{config.bind}:{config.port}", flush=True)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASG result audit receipt collector")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("serve")
    sub.add_parser("validate-config")
    args = parser.parse_args(argv)

    config = load_config_from_env()
    if args.command == "validate-config":
        print(
            json.dumps(
                {
                    "ok": True,
                    "app": APP_NAME,
                    "bind": config.bind,
                    "port": config.port,
                    "store_path": str(config.store_path),
                    "anchor_store_path": str(config.anchor_store_path),
                    "auth_required": bool(config.token),
                    "signature_required": bool(config.hmac_key),
                    "signature_max_age_seconds": config.signature_max_age_seconds,
                },
                sort_keys=True,
            )
        )
        return 0
    if args.command == "serve":
        serve(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
