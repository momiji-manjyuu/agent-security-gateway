#!/usr/bin/env python3
"""OpenAI-compatible shim that forwards worker traffic through ASG.

The shim is intended to run on worker hosts whose local agent runtime can only
talk to a plain OpenAI-compatible base URL. It receives local OpenAI requests,
adds the fixed ASG identity headers and route metadata, and forwards the request
to Agent Security Gateway.
"""

from __future__ import annotations

import argparse
import dataclasses
import http.server
import json
import math
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import deque
from pathlib import Path
from typing import Any


APP_NAME = "openai-asg-shim"
VERSION = "0.1.0"
DEFAULT_MAX_BODY_BYTES = 524_288
DEFAULT_TIMEOUT_SECONDS = 300
DEFAULT_RESULTS_MAX_PER_MINUTE = 20
DEFAULT_429_MAX_RETRIES = 5
DEFAULT_429_BACKOFF_SECONDS = 1.0
DEFAULT_429_BACKOFF_MAX_SECONDS = 30.0
ALLOWED_ASG_PATHS = {"/v1/chat/completions", "/v1/results"}

_RESULT_RATE_LOCK = threading.Lock()
_RESULT_SEND_TIMES: deque[float] = deque()


class ShimError(Exception):
    def __init__(self, status: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


@dataclasses.dataclass(frozen=True)
class ShimConfig:
    bind: str
    port: int
    asg_base_url: str
    asg_path: str
    asg_token: str
    route_id: str
    capability: str
    taint: list[str]
    model_id: str
    model_alias: str
    result_message_type: str
    timeout_seconds: float
    max_body_bytes: int
    strip_tooling: bool
    allowed_message_roles: set[str]
    results_max_per_minute: int = DEFAULT_RESULTS_MAX_PER_MINUTE
    rate_limit_max_retries: int = DEFAULT_429_MAX_RETRIES
    rate_limit_backoff_seconds: float = DEFAULT_429_BACKOFF_SECONDS
    rate_limit_backoff_max_seconds: float = DEFAULT_429_BACKOFF_MAX_SECONDS


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) else default


def _read_token() -> str:
    token = _env("ASG_SHIM_TOKEN")
    token_file = _env("ASG_SHIM_TOKEN_FILE")
    if token and token_file:
        raise ShimError(500, "invalid_config", "set ASG_SHIM_TOKEN or ASG_SHIM_TOKEN_FILE, not both")
    if token:
        return token
    if token_file:
        try:
            return Path(token_file).expanduser().read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ShimError(500, "invalid_config", "could not read ASG_SHIM_TOKEN_FILE") from exc
    raise ShimError(500, "invalid_config", "ASG_SHIM_TOKEN_FILE or ASG_SHIM_TOKEN is required")


def _parse_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = _env(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ShimError(500, "invalid_config", f"{name} must be an integer") from exc
    if value < minimum or value > maximum:
        raise ShimError(500, "invalid_config", f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    raw = _env(name, str(default))
    try:
        value = float(raw)
    except ValueError as exc:
        raise ShimError(500, "invalid_config", f"{name} must be a number") from exc
    if not math.isfinite(value) or value < minimum or value > maximum:
        raise ShimError(500, "invalid_config", f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_taint(value: str) -> list[str]:
    result = [item.strip() for item in value.split(",") if item.strip()]
    if not result:
        raise ShimError(500, "invalid_config", "ASG_SHIM_TAINT must contain at least one taint")
    return result


def _parse_bool(name: str, default: bool) -> bool:
    raw = _env(name, "true" if default else "false").lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ShimError(500, "invalid_config", f"{name} must be a boolean")


def _parse_roles(value: str) -> set[str]:
    roles = {item.strip().lower() for item in value.split(",") if item.strip()}
    if not roles:
        raise ShimError(500, "invalid_config", "ASG_SHIM_ALLOWED_MESSAGE_ROLES must not be empty")
    return roles


def _parse_asg_path(value: str) -> str:
    path = value.strip() or "/v1/chat/completions"
    if not path.startswith("/"):
        path = "/" + path
    if path not in ALLOWED_ASG_PATHS:
        allowed = ", ".join(sorted(ALLOWED_ASG_PATHS))
        raise ShimError(500, "invalid_config", f"ASG_SHIM_ASG_PATH must be one of: {allowed}")
    return path


def load_config_from_env() -> ShimConfig:
    asg_base_url = _env("ASG_SHIM_ASG_BASE_URL").rstrip("/")
    route_id = _env("ASG_SHIM_ROUTE_ID")
    capability = _env("ASG_SHIM_CAPABILITY")
    if not asg_base_url:
        raise ShimError(500, "invalid_config", "ASG_SHIM_ASG_BASE_URL is required")
    parsed = urllib.parse.urlsplit(asg_base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ShimError(500, "invalid_config", "ASG_SHIM_ASG_BASE_URL must be an absolute http(s) URL")
    if not route_id:
        raise ShimError(500, "invalid_config", "ASG_SHIM_ROUTE_ID is required")
    if not capability:
        raise ShimError(500, "invalid_config", "ASG_SHIM_CAPABILITY is required")
    asg_path = _parse_asg_path(_env("ASG_SHIM_ASG_PATH", "/v1/chat/completions"))
    result_message_type = _env("ASG_SHIM_RESULT_MESSAGE_TYPE", "worker_report")
    if not result_message_type:
        raise ShimError(500, "invalid_config", "ASG_SHIM_RESULT_MESSAGE_TYPE must not be empty")
    port = _parse_int("ASG_SHIM_PORT", 18088, minimum=1, maximum=65_535)
    timeout_seconds = _parse_int("ASG_SHIM_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS, minimum=1, maximum=600)
    max_body_bytes = _parse_int("ASG_SHIM_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, minimum=1, maximum=50 * 1024 * 1024)
    results_max_per_minute = _parse_int("ASG_SHIM_RESULTS_MAX_PER_MINUTE", DEFAULT_RESULTS_MAX_PER_MINUTE, minimum=1, maximum=60)
    rate_limit_max_retries = _parse_int("ASG_SHIM_429_MAX_RETRIES", DEFAULT_429_MAX_RETRIES, minimum=0, maximum=10)
    rate_limit_backoff_seconds = _parse_float(
        "ASG_SHIM_429_BACKOFF_SECONDS",
        DEFAULT_429_BACKOFF_SECONDS,
        minimum=0.1,
        maximum=60.0,
    )
    rate_limit_backoff_max_seconds = _parse_float(
        "ASG_SHIM_429_BACKOFF_MAX_SECONDS",
        DEFAULT_429_BACKOFF_MAX_SECONDS,
        minimum=0.1,
        maximum=300.0,
    )
    model_alias = _env("ASG_SHIM_MODEL_ALIAS")
    model_id = _env("ASG_SHIM_MODEL_ID", model_alias or route_id)
    return ShimConfig(
        bind=_env("ASG_SHIM_BIND", "127.0.0.1"),
        port=port,
        asg_base_url=asg_base_url,
        asg_path=asg_path,
        asg_token=_read_token(),
        route_id=route_id,
        capability=capability,
        taint=_parse_taint(_env("ASG_SHIM_TAINT", "trusted_instruction")),
        model_id=model_id,
        model_alias=model_alias,
        result_message_type=result_message_type,
        timeout_seconds=float(timeout_seconds),
        max_body_bytes=max_body_bytes,
        strip_tooling=_parse_bool("ASG_SHIM_STRIP_TOOLING", True),
        allowed_message_roles=_parse_roles(_env("ASG_SHIM_ALLOWED_MESSAGE_ROLES", "user,assistant")),
        results_max_per_minute=results_max_per_minute,
        rate_limit_max_retries=rate_limit_max_retries,
        rate_limit_backoff_seconds=rate_limit_backoff_seconds,
        rate_limit_backoff_max_seconds=rate_limit_backoff_max_seconds,
    )


def json_error(code: str, message: str, request_id: str) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "request_id": request_id}}


def model_list(config: ShimConfig) -> dict[str, Any]:
    return {
        "object": "list",
        "data": [
            {
                "id": config.model_id,
                "object": "model",
                "created": int(time.time()),
                "owned_by": APP_NAME,
            }
        ],
    }


def build_asg_payload(payload: dict[str, Any], config: ShimConfig) -> dict[str, Any]:
    outbound = dict(payload)
    if config.strip_tooling:
        outbound = strip_tooling_fields(outbound, config.allowed_message_roles)
    metadata = outbound.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    else:
        metadata = dict(metadata)
    metadata["route_id"] = config.route_id
    metadata["capability"] = config.capability
    metadata["taint"] = list(config.taint)
    outbound["metadata"] = metadata
    if config.model_alias:
        outbound["model"] = config.model_alias
    return outbound


def build_asg_result_payload(payload: dict[str, Any], config: ShimConfig) -> dict[str, Any]:
    outbound = strip_tooling_fields(payload, config.allowed_message_roles) if config.strip_tooling else dict(payload)
    metadata = outbound.get("metadata")
    metadata = dict(metadata) if isinstance(metadata, dict) else {}
    if isinstance(payload.get("model"), str) and payload.get("model"):
        metadata["source_model"] = payload["model"]
    metadata["route_id"] = config.route_id
    metadata["capability"] = config.capability
    metadata["taint"] = list(config.taint)

    result: dict[str, Any] = {
        "route_id": config.route_id,
        "capability": config.capability,
        "taint": list(config.taint),
        "message_type": config.result_message_type,
        "metadata": metadata,
    }
    messages = outbound.get("messages")
    if isinstance(messages, list):
        result["messages"] = messages
    for field in ("run_id", "task_id", "user"):
        value = outbound.get(field)
        if isinstance(value, str) and value.strip():
            result[field] = value.strip()
            continue
        meta_value = metadata.get(field)
        if isinstance(meta_value, str) and meta_value.strip():
            result[field] = meta_value.strip()
    if "input" in outbound and "messages" not in result:
        result["input"] = outbound["input"]
    return result


def wait_for_result_send_slot(config: ShimConfig) -> None:
    """Keep /v1/results submissions at or below the configured per-minute cap."""
    if config.asg_path != "/v1/results":
        return
    while True:
        now = time.monotonic()
        with _RESULT_RATE_LOCK:
            while _RESULT_SEND_TIMES and now - _RESULT_SEND_TIMES[0] >= 60.0:
                _RESULT_SEND_TIMES.popleft()
            if len(_RESULT_SEND_TIMES) < config.results_max_per_minute:
                _RESULT_SEND_TIMES.append(now)
                return
            sleep_for = max(0.1, 60.0 - (now - _RESULT_SEND_TIMES[0]))
        time.sleep(sleep_for)


def retry_after_seconds(headers: Any) -> float | None:
    raw = headers.get("Retry-After") if hasattr(headers, "get") else None
    if raw is None:
        return None
    try:
        value = float(str(raw).strip())
    except ValueError:
        return None
    return value if value >= 0 else None


def rate_limit_sleep_seconds(config: ShimConfig, attempt: int, retry_after: float | None) -> float:
    if retry_after is not None:
        return min(config.rate_limit_backoff_max_seconds, retry_after)
    exponential = config.rate_limit_backoff_seconds * (2 ** max(0, attempt - 1))
    return min(config.rate_limit_backoff_max_seconds, max(config.rate_limit_backoff_seconds, exponential))


def openai_result_response(body: dict[str, Any], config: ShimConfig, request_id: str) -> dict[str, Any]:
    response_id = str(body.get("request_id") or request_id).removeprefix("req_")
    return {
        "id": "chatcmpl-asg-" + response_id[:24],
        "object": "chat.completion",
        "created": int(time.time()),
        "model": config.model_id,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": json.dumps(body, ensure_ascii=False, sort_keys=True),
                },
                "finish_reason": "stop",
            }
        ],
    }


def strip_tooling_fields(payload: dict[str, Any], allowed_roles: set[str]) -> dict[str, Any]:
    blocked_request_fields = {
        "tools",
        "tool_choice",
        "functions",
        "function_call",
        "parallel_tool_calls",
    }
    blocked_message_fields = {
        "tool_calls",
        "function_call",
        "tool_call_id",
        "name",
    }
    sanitized = {key: value for key, value in payload.items() if key not in blocked_request_fields}
    messages = payload.get("messages")
    if isinstance(messages, list):
        clean_messages: list[dict[str, Any]] = []
        for message in messages:
            if not isinstance(message, dict):
                continue
            role = str(message.get("role", "")).lower()
            if role not in allowed_roles:
                continue
            clean_message = {key: value for key, value in message.items() if key not in blocked_message_fields}
            clean_messages.append(clean_message)
        sanitized["messages"] = clean_messages
    return sanitized


def forward_chat(payload: dict[str, Any], config: ShimConfig, request_id: str) -> tuple[int, dict[str, Any]]:
    outbound = build_asg_result_payload(payload, config) if config.asg_path == "/v1/results" else build_asg_payload(payload, config)
    body = json.dumps(outbound, ensure_ascii=False, sort_keys=True).encode("utf-8")
    headers = {
        "Authorization": "Bearer " + config.asg_token,
        "Content-Type": "application/json",
        "X-ASG-Route": config.route_id,
        "X-Agent-Capability": config.capability,
        "X-Request-ID": request_id,
    }
    attempt = 0
    while True:
        wait_for_result_send_slot(config)
        request = urllib.request.Request(
            config.asg_base_url + config.asg_path,
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, timeout=config.timeout_seconds) as response:
                raw = response.read().decode("utf-8", errors="replace")
                parsed = json.loads(raw) if raw.strip() else {}
                if not isinstance(parsed, dict):
                    parsed = {"value": parsed}
                if config.asg_path == "/v1/results":
                    parsed = openai_result_response(parsed, config, request_id)
                return response.status, parsed
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read().decode("utf-8", errors="replace") if exc.fp else ""
                parsed = json.loads(raw) if raw.strip() else {}
                if not isinstance(parsed, dict):
                    parsed = {"value": parsed}
                if exc.code == 429 and config.asg_path == "/v1/results" and attempt < config.rate_limit_max_retries:
                    attempt += 1
                    time.sleep(rate_limit_sleep_seconds(config, attempt, retry_after_seconds(exc.headers)))
                    continue
                return exc.code, parsed
            finally:
                exc.close()
        except (socket.timeout, TimeoutError) as exc:
            raise ShimError(504, "asg_timeout", "ASG request timed out") from exc
        except urllib.error.URLError as exc:
            raise ShimError(502, "asg_error", f"ASG request failed: {type(exc).__name__}") from exc
        except json.JSONDecodeError as exc:
            raise ShimError(502, "asg_error", "ASG response was not valid JSON") from exc


class ShimHandler(http.server.BaseHTTPRequestHandler):
    server_version = "OpenAIASGShim/" + VERSION

    def do_GET(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-ID") or "shim_" + uuid.uuid4().hex
        config = self.server.config  # type: ignore[attr-defined]
        if self.path in {"/healthz", "/readyz"}:
            self.write_json(200, {"ok": True, "app": APP_NAME, "version": VERSION})
            return
        if self.path == "/v1/models":
            self.write_json(200, model_list(config))
            return
        self.write_json(404, json_error("not_found", "not found", request_id))

    def do_POST(self) -> None:  # noqa: N802
        request_id = self.headers.get("X-Request-ID") or "shim_" + uuid.uuid4().hex
        config = self.server.config  # type: ignore[attr-defined]
        try:
            if self.path != "/v1/chat/completions":
                raise ShimError(404, "not_found", "not found")
            payload = self.read_json_body(config)
            status, body = forward_chat(payload, config, request_id)
            if status == 200 and payload.get("stream") is True:
                self.write_openai_stream(body)
                return
            self.write_json(status, body)
        except ShimError as exc:
            self.write_json(exc.status, json_error(exc.code, exc.message, request_id))
        except Exception:  # noqa: BLE001
            self.write_json(500, json_error("internal_error", "internal error", request_id))

    def read_json_body(self, config: ShimConfig) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ShimError(400, "invalid_json", "invalid Content-Length") from exc
        if length < 0 or length > config.max_body_bytes:
            raise ShimError(413, "request_too_large", "request body is too large")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ShimError(400, "invalid_json", "request body must be valid JSON") from exc
        if not isinstance(payload, dict):
            raise ShimError(400, "invalid_json", "request body must be a JSON object")
        return payload

    def write_json(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(encoded)

    def write_openai_stream(self, body: dict[str, Any]) -> None:
        chunks = openai_stream_chunks(body)
        encoded = b"".join(("data: " + json.dumps(chunk, ensure_ascii=False, sort_keys=True) + "\n\n").encode("utf-8") for chunk in chunks)
        encoded += b"data: [DONE]\n\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("[%s] %s\n" % (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), fmt % args))


class ThreadingHTTPServer(http.server.ThreadingHTTPServer):
    config: ShimConfig


def openai_stream_chunks(body: dict[str, Any]) -> list[dict[str, Any]]:
    response_id = str(body.get("id") or "chatcmpl-" + uuid.uuid4().hex[:24])
    created = int(body.get("created") or time.time())
    model = str(body.get("model") or "")
    chunks: list[dict[str, Any]] = []
    choices = body.get("choices")
    if not isinstance(choices, list) or not choices:
        return [
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
            }
        ]
    for choice in choices:
        if not isinstance(choice, dict):
            continue
        index = int(choice.get("index", 0))
        message = choice.get("message") if isinstance(choice.get("message"), dict) else {}
        content = message.get("content") if isinstance(message, dict) else ""
        role = message.get("role") if isinstance(message, dict) else "assistant"
        if content:
            chunks.append(
                {
                    "id": response_id,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": index, "delta": {"role": role or "assistant", "content": str(content)}, "finish_reason": None}],
                }
            )
        chunks.append(
            {
                "id": response_id,
                "object": "chat.completion.chunk",
                "created": created,
                "model": model,
                "choices": [{"index": index, "delta": {}, "finish_reason": choice.get("finish_reason") or "stop"}],
            }
        )
    return chunks


def serve(config: ShimConfig) -> None:
    server = ThreadingHTTPServer((config.bind, config.port), ShimHandler)
    server.config = config
    print(f"{APP_NAME} listening on http://{config.bind}:{config.port}", flush=True)
    server.serve_forever()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="OpenAI-compatible ASG forwarding shim")
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
                    "asg_base_url": config.asg_base_url,
                    "asg_path": config.asg_path,
                    "route_id": config.route_id,
                    "capability": config.capability,
                    "model_id": config.model_id,
                    "result_message_type": config.result_message_type,
                    "bind": config.bind,
                    "port": config.port,
                    "strip_tooling": config.strip_tooling,
                    "allowed_message_roles": sorted(config.allowed_message_roles),
                    "results_max_per_minute": config.results_max_per_minute,
                    "rate_limit_max_retries": config.rate_limit_max_retries,
                    "rate_limit_backoff_seconds": config.rate_limit_backoff_seconds,
                    "rate_limit_backoff_max_seconds": config.rate_limit_backoff_max_seconds,
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
