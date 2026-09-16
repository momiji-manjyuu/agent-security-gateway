"""ASG wire adapter, checked against upstream e9a251de9b8ac26112376e78f542d8110f14b7db."""
import datetime as dt
import hashlib
import hmac
import http.client
import os
import re
import ssl
from urllib.parse import urlsplit

from contract import (encode, exact_keys, limited_text, load_json, require,
                      validate_task)

TASK_ROUTE = "docker90.web_research.task"
ARTIFACT_ROUTE = "docker90.artifacts.submit"


def secret(name):
    value = os.environ.get(name, "")
    require(len(value) >= 32 and value.isascii() and not any(c.isspace() for c in value))
    return value


def identifier(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}", value))
    return value


def verify_backend(headers, raw, token, hmac_key, allowed_callers, now=None):
    auth = headers.get("Authorization", "")
    require(hmac.compare_digest(auth.encode(), ("Bearer " + token).encode()))
    body_hash = hashlib.sha256(raw).hexdigest()
    require(hmac.compare_digest(headers.get("X-ASG-Request-SHA256", ""), body_hash))
    agent = identifier(headers.get("X-ASG-Agent-Id", ""))
    require(agent in allowed_callers)
    require(headers.get("X-ASG-Route-Id") == TASK_ROUTE)
    run_id = identifier(headers.get("X-ASG-Run-Id", ""))
    task_id = identifier(headers.get("X-ASG-Task-Id", ""))
    timestamp = headers.get("X-ASG-Timestamp", "")
    require(type(timestamp) is str and len(timestamp) <= 40)
    date = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    require(date.tzinfo is not None)
    now = now or dt.datetime.now(dt.timezone.utc)
    require(abs((now - date).total_seconds()) <= 120)
    canonical = "\n".join(["POST", "/v1/tasks", body_hash, agent, TASK_ROUTE,
                            run_id, task_id, timestamp])
    expected = "sha256=" + hmac.new(hmac_key.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    require(hmac.compare_digest(headers.get("X-ASG-Signature", ""), expected))
    return run_id, task_id


def task_from_packet(packet, run_id, task_id):
    exact_keys(packet, {"route_id", "capability", "run_id", "task_id", "taint", "task"},
               {"message_type"})
    require(packet["route_id"] == TASK_ROUTE)
    require(packet["capability"] == "delegate_web_research")
    require(packet["run_id"] == run_id and packet["task_id"] == task_id)
    require(packet["taint"] == ["trusted_instruction"])
    require(packet.get("message_type", "task_instruction") == "task_instruction")
    task = packet["task"]
    exact_keys(task, {"objective", "inputs", "constraints", "output_contract"})
    limited_text(task["objective"], 1000, True)
    require(task["output_contract"] == {"format": "artifact_ref"})
    inputs = task["inputs"]
    require(type(inputs) is list and len(inputs) <= 5)
    for item in inputs:
        exact_keys(item, {"url"})
    constraints = task["constraints"]
    exact_keys(constraints, set(), {"search", "allowed_hosts", "max_sources"})
    request = {"question": task["objective"], "urls": [i["url"] for i in inputs],
               **constraints}
    return validate_task(request)


def artifact_packet(report, run_id, task_id):
    # No arbitrary route, callback, filename, taint or IDs supplied by the worker.
    return {"route_id": ARTIFACT_ROUTE, "capability": "submit_artifact",
            "run_id": identifier(run_id), "task_id": identifier(task_id),
            "taint": ["untrusted_web", "sandbox_output"], "message_type": "artifact",
            "artifact_type": "report", "filename": "research-report.json",
            "media_type": "application/json", "content_text": encode(report).decode()}


def artifact_receipt(response, run_id, task_id, expected_hash):
    require(type(response) is dict and type(response.get("artifact_ref")) is dict)
    ref = response["artifact_ref"]
    artifact_id = ref.get("artifact_id", "")
    require(type(artifact_id) is str and re.fullmatch(r"art_[0-9a-f]{32}", artifact_id))
    require(ref.get("status") in ("verified", "needs_review", "blocked"))
    require(ref.get("run_id") == run_id and ref.get("task_id") == task_id)
    require(ref.get("content_sha256") == expected_hash)
    require(set(ref.get("taint", [])) == {"untrusted_web", "sandbox_output"})
    # Discard manifest, reason, summary, filenames and every free-text field.
    return {"artifact_id": artifact_id, "artifact_status": ref["status"]}


def submit_artifact(packet, token, base_url):
    url = urlsplit(base_url)
    require(url.scheme in {"http", "https"} and url.hostname)
    require(not url.username and not url.password and not url.query and not url.fragment)
    require(url.path in ("", "/"))
    # LAN transport uses the documented SSH tunnel, or operator-configured TLS.
    require(url.scheme == "https" or url.hostname in {"127.0.0.1", "::1"})
    if url.scheme == "https":
        conn = http.client.HTTPSConnection(url.hostname, url.port or 443, timeout=20,
                                           context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(url.hostname, url.port or 80, timeout=20)
    try:
        conn.request("POST", "/v1/artifacts", body=encode(packet), headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json",
            "X-ASG-Route": ARTIFACT_ROUTE, "X-Agent-Capability": "submit_artifact"})
        response = conn.getresponse()
        require(response.status == 200)  # No redirects, automatic retries or bypass.
        value = load_json(response.read(131073), 131072)
        digest = hashlib.sha256(packet["content_text"].encode()).hexdigest()
        return artifact_receipt(value, packet["run_id"], packet["task_id"], digest)
    finally:
        conn.close()
