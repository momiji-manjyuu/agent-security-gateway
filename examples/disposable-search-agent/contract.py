"""Strict shape validation, NOT a semantic prompt-injection detector."""
import json
import re

MAX_WIRE_BYTES = 2_000_000
MAX_RESULT_BYTES = 32_768
MAX_SOURCES = 5
MAX_DOCUMENT_CHARS = 70_000


class BoundaryError(ValueError):
    pass


def require(condition):
    if not condition:
        raise BoundaryError("invalid_contract")


def exact_keys(value, required, optional=()):
    require(type(value) is dict)
    require(set(required) <= set(value) <= set(required) | set(optional))


def limited_text(value, limit, nonempty=False):
    require(type(value) is str and len(value) <= limit)
    require(not nonempty or bool(value.strip()))
    return value


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        require(key not in obj)
        obj[key] = value
    return obj


def load_json(raw, limit=MAX_WIRE_BYTES):
    require(type(raw) is bytes and len(raw) <= limit)
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates,
                          parse_constant=lambda _: require(False))
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise BoundaryError("invalid_json") from exc


def encode(value):
    # ASCII escaping also prevents literal control characters in saved JSON.
    return (json.dumps(value, ensure_ascii=True, allow_nan=False) + "\n").encode()


def validate_task(task):
    exact_keys(task, {"question"}, {"urls", "search", "allowed_hosts", "max_sources"})
    limited_text(task["question"], 1000, True)
    urls = task.get("urls", [])
    require(type(urls) is list and len(urls) <= MAX_SOURCES)
    for url in urls:
        limited_text(url, 2048, True)
    require(type(task.get("search", False)) is bool)
    n = task.get("max_sources", MAX_SOURCES)
    require(type(n) is int and 1 <= n <= MAX_SOURCES)
    hosts = task.get("allowed_hosts", [])
    require(type(hosts) is list and len(hosts) <= 20)
    for host in hosts:
        limited_text(host, 253, True)
        require(re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9-]+)+", host) is not None)
    require(bool(urls) or task.get("search", False))
    return task


def validate_bundle(bundle, question):
    exact_keys(bundle, {"version", "question", "documents", "fetch_failures"})
    require(type(bundle["version"]) is int and bundle["version"] == 1)
    require(bundle["question"] == question)
    require(type(bundle["fetch_failures"]) is int and 0 <= bundle["fetch_failures"] <= 10)
    docs = bundle["documents"]
    require(type(docs) is list and len(docs) <= MAX_SOURCES)
    for index, doc in enumerate(docs, 1):
        exact_keys(doc, {"source_id", "url", "content_type", "content"})
        require(doc["source_id"] == f"s{index}")
        limited_text(doc["url"], 2048, True)
        require(doc["content_type"] in ("text/html", "text/plain", "text/markdown"))
        limited_text(doc["content"], MAX_DOCUMENT_CHARS)
    return bundle


def validate_result(value, source_ids):
    exact_keys(value, {"version", "findings"})
    require(type(value["version"]) is int and value["version"] == 1)
    findings = value["findings"]
    require(type(findings) is list and len(findings) <= MAX_SOURCES)
    seen = set()
    for finding in findings:
        exact_keys(finding, {"source_id", "excerpt"})
        sid = finding["source_id"]
        require(type(sid) is str and sid in source_ids and sid not in seen)
        seen.add(sid)
        limited_text(finding["excerpt"], 1200, True)
    return value


def make_receipt(run_id, bundle, result):
    """Only controller-generated IDs/counts cross into the parent context."""
    require(re.fullmatch(r"[0-9a-f]{32}", run_id) is not None)
    validate_result(result, {doc["source_id"] for doc in bundle["documents"]})
    return {
        "version": 1,
        "status": "completed",
        "artifact_id": run_id,
        "source_count": len(bundle["documents"]),
        "fetch_failures": bundle["fetch_failures"],
        "finding_count": len(result["findings"]),
        "selected_source_ids": [f["source_id"] for f in result["findings"]],
        "external_text_returned": False,
    }
