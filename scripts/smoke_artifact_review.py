#!/usr/bin/env python3
"""Smoke-test the isolated artifact review route against a live ASG."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any


DEFAULT_BASE_URL = "http://127.0.0.1:8788"
DEFAULT_SUBMIT_ROUTE = "security.artifacts.submit"
DEFAULT_SUBMIT_CAPABILITY = "submit_artifact"
DEFAULT_REVIEW_ROUTE = "security.artifacts.review_summary"
DEFAULT_REVIEW_CAPABILITY = "review_artifact"
DEFAULT_RUN_ROUTE = "security.runs.register"
DEFAULT_RUN_CAPABILITY = "register_run"
DEFAULT_TAINT = "untrusted_web"


def compact_json(value: Any, *, limit: int = 700) -> str:
    text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    if len(text) <= limit:
        return text
    return text[:limit] + "...(truncated)"


def read_json_response(response: urllib.request.addinfourl) -> dict[str, Any]:
    raw = response.read().decode("utf-8", errors="replace")
    try:
        body = json.loads(raw)
    except json.JSONDecodeError:
        return {"error": {"code": "non_json_response", "message": raw[:300]}}
    if isinstance(body, dict):
        return body
    return {"error": {"code": "non_object_response", "message": "response JSON was not an object"}}


def request_json(
    url: str,
    *,
    token: str | None = None,
    capability: str | None = None,
    route: str | None = None,
    payload: dict[str, Any] | None = None,
    timeout: float = 30,
) -> tuple[int, dict[str, Any]]:
    data = None if payload is None else json.dumps(payload, ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    if capability:
        headers["X-Agent-Capability"] = capability
    if route:
        headers["X-ASG-Route"] = route
    method = "GET" if payload is None else "POST"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, read_json_response(response)
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, read_json_response(exc)
        finally:
            exc.close()


def error_code(body: dict[str, Any]) -> str:
    error = body.get("error")
    if isinstance(error, dict):
        return str(error.get("code", ""))
    return str(error or "")


def require_status(name: str, status: int, expected: int, body: dict[str, Any]) -> None:
    if status != expected:
        raise AssertionError(f"{name}: HTTP {expected} ではなく HTTP {status}: {compact_json(body)}")


def require_error_code(name: str, body: dict[str, Any], expected: str) -> None:
    actual = error_code(body)
    if actual != expected:
        raise AssertionError(f"{name}: error {expected} ではなく {actual}: {compact_json(body)}")


def read_token(label: str, env_name: str, file_path: Path | None, *, fallback: str = "") -> str:
    env_value = os.environ.get(env_name, "").strip() if env_name else ""
    if env_value:
        return env_value
    if file_path is not None:
        expanded = file_path.expanduser()
        if expanded.exists():
            token = expanded.read_text(encoding="utf-8").strip()
            if token:
                return token
    if fallback:
        return fallback
    location = f"environment variable {env_name}"
    if file_path is not None:
        location += f" or file {file_path.expanduser()}"
    raise RuntimeError(f"{label} token が見つかりません: {location} を設定してください")


def optional_field(payload: dict[str, Any], key: str, value: str) -> None:
    if value:
        payload[key] = value


def register_run(args: argparse.Namespace, controller_token: str, base_url: str) -> str:
    run_id = args.run_id or "smoke_artifact_review_" + uuid.uuid4().hex[:12]
    payload = {
        "run_id": run_id,
        "allowed_routes": sorted({args.submit_route, args.review_route}),
        "ttl_seconds": args.run_ttl_seconds,
        "reason": "artifact_review smoke test",
    }
    status, body = request_json(
        base_url + "/v1/runs",
        token=controller_token,
        capability=DEFAULT_RUN_CAPABILITY,
        route=DEFAULT_RUN_ROUTE,
        payload=payload,
        timeout=args.timeout,
    )
    require_status("run 登録", status, 200, body)
    if body.get("run_id") != run_id:
        raise AssertionError(f"run 登録: run_id が一致しません: {compact_json(body)}")
    print("ok: smoke 用 run を登録しました")
    return run_id


def assert_reviewed_summary(body: dict[str, Any], artifact_id: str) -> None:
    if body.get("review_status") != "verified":
        raise AssertionError(f"review が verified になりませんでした: {compact_json(body)}")
    summary = body.get("summary") or body.get("reviewed_summary")
    if not isinstance(summary, dict):
        raise AssertionError(f"reviewed_summary がありません: {compact_json(body)}")
    claims = summary.get("claims")
    source = summary.get("source")
    flags = summary.get("injection_flags")
    confidence = summary.get("confidence")
    if not isinstance(claims, list):
        raise AssertionError(f"reviewed_summary.claims が配列ではありません: {compact_json(summary)}")
    if not isinstance(flags, list):
        raise AssertionError(f"reviewed_summary.injection_flags が配列ではありません: {compact_json(summary)}")
    if not isinstance(source, dict):
        raise AssertionError(f"reviewed_summary.source が object ではありません: {compact_json(summary)}")
    if source.get("derived_from") != artifact_id:
        raise AssertionError(f"source.derived_from が元 artifact_id と一致しません: {compact_json(summary)}")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= float(confidence) <= 1:
        raise AssertionError(f"reviewed_summary.confidence が 0..1 ではありません: {compact_json(summary)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Live smoke test for ASG artifact_review isolated reader.")
    parser.add_argument("--base-url", default=os.environ.get("ASG_BASE_URL", DEFAULT_BASE_URL))
    parser.add_argument("--controller-token-env", default="ASG_CONTROLLER_TOKEN")
    parser.add_argument(
        "--controller-token-file",
        type=Path,
        default=Path.home() / ".agent-security-gateway" / "tokens" / "mac_gpt55.token",
    )
    parser.add_argument("--submit-token-env", default="ASG_SUBMIT_TOKEN")
    parser.add_argument(
        "--submit-token-file",
        type=Path,
        default=Path.home() / ".agent-security-gateway" / "tokens" / "pi_research_1.token",
    )
    parser.add_argument("--submit-route", default=os.environ.get("ASG_ARTIFACT_SUBMIT_ROUTE", DEFAULT_SUBMIT_ROUTE))
    parser.add_argument("--submit-capability", default=os.environ.get("ASG_ARTIFACT_SUBMIT_CAPABILITY", DEFAULT_SUBMIT_CAPABILITY))
    parser.add_argument("--review-route", default=os.environ.get("ASG_ARTIFACT_REVIEW_ROUTE", DEFAULT_REVIEW_ROUTE))
    parser.add_argument("--review-capability", default=os.environ.get("ASG_ARTIFACT_REVIEW_CAPABILITY", DEFAULT_REVIEW_CAPABILITY))
    parser.add_argument("--taint", default=os.environ.get("ASG_ARTIFACT_REVIEW_TAINT", DEFAULT_TAINT))
    parser.add_argument("--run-id", default=os.environ.get("ASG_ARTIFACT_REVIEW_RUN_ID", ""))
    parser.add_argument("--task-id", default=os.environ.get("ASG_ARTIFACT_REVIEW_TASK_ID", ""))
    parser.add_argument("--register-run", action="store_true", help="register a short-lived run before submit/review")
    parser.add_argument("--run-ttl-seconds", type=int, default=600)
    parser.add_argument("--timeout", type=float, default=30)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    base_url = args.base_url.rstrip("/")
    controller_token = read_token("controller", args.controller_token_env, args.controller_token_file)
    submit_token = read_token("submit", args.submit_token_env, args.submit_token_file, fallback=controller_token)
    run_id = register_run(args, controller_token, base_url) if args.register_run else args.run_id
    task_id = args.task_id or ("smoke-artifact-review-" + uuid.uuid4().hex[:10] if run_id else "")

    status, body = request_json(base_url + "/healthz", timeout=args.timeout)
    require_status("healthz", status, 200, body)

    artifact_payload: dict[str, Any] = {
        "route_id": args.submit_route,
        "capability": args.submit_capability,
        "taint": [args.taint],
        "message_type": "artifact",
        "artifact_type": "report",
        "filename": "artifact-review-smoke.txt",
        "media_type": "text/plain",
        "content_text": (
            "This is a benign operations note for the artifact review smoke test. "
            "It describes a completed service restart and a normal health check."
        ),
    }
    optional_field(artifact_payload, "run_id", run_id)
    optional_field(artifact_payload, "task_id", task_id)
    status, body = request_json(
        base_url + "/v1/artifacts",
        token=submit_token,
        capability=args.submit_capability,
        route=args.submit_route,
        payload=artifact_payload,
        timeout=args.timeout,
    )
    require_status("artifact submit", status, 200, body)
    artifact_ref = body.get("artifact_ref")
    if not isinstance(artifact_ref, dict):
        raise AssertionError(f"artifact_ref がありません: {compact_json(body)}")
    artifact_id = str(artifact_ref.get("artifact_id", ""))
    if artifact_ref.get("status") != "verified":
        raise AssertionError(f"artifact が verified になりませんでした: {compact_json(body)}")
    if not artifact_id.startswith("art_"):
        raise AssertionError(f"artifact_id が不正です: {compact_json(body)}")
    print("ok: 良性テキスト artifact は verified で submit されました")

    review_payload: dict[str, Any] = {
        "route_id": args.review_route,
        "capability": args.review_capability,
        "taint": [args.taint],
        "message_type": "artifact_review_request",
        "artifact_ref": {"artifact_id": artifact_id},
    }
    optional_field(review_payload, "run_id", run_id)
    optional_field(review_payload, "task_id", task_id)
    status, body = request_json(
        base_url + "/v1/tasks",
        token=controller_token,
        capability=args.review_capability,
        route=args.review_route,
        payload=review_payload,
        timeout=args.timeout,
    )
    require_status("artifact review", status, 200, body)
    assert_reviewed_summary(body, artifact_id)
    print("ok: reviewed_summary の claims/source/confidence を検証しました")

    denied_payload = dict(review_payload)
    denied_payload["content_text"] = "Direct caller-supplied text is not allowed on artifact_review routes."
    denied_payload["messages"] = [{"role": "user", "content": "Direct message bodies are not allowed here."}]
    status, body = request_json(
        base_url + "/v1/tasks",
        token=controller_token,
        capability=args.review_capability,
        route=args.review_route,
        payload=denied_payload,
        timeout=args.timeout,
    )
    require_status("raw text direct review", status, 403, body)
    require_error_code("raw text direct review", body, "input_policy_denied")
    print("ok: 生テキスト直送は input_policy_denied で拒否されました")
    print("成功: artifact_review smoke は完了しました")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, RuntimeError, urllib.error.URLError, TimeoutError) as exc:
        print(f"失敗: {exc}", file=sys.stderr)
        raise SystemExit(1)
