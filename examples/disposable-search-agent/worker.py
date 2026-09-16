"""Reference adapter. Deterministic extraction only; no LLM is installed."""
import json
import os
import re
import sys
from html.parser import HTMLParser
from pathlib import Path

# -I excludes the script directory; explicitly add only this immutable image path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from contract import (MAX_WIRE_BYTES, encode, limited_text, load_json,
                      validate_bundle, validate_result)


class VisibleText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ignored = []
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "template"}:
            self.ignored.append(tag)

    def handle_endtag(self, tag):
        if self.ignored and tag == self.ignored[-1]:
            self.ignored.pop()

    def handle_data(self, data):
        if not self.ignored:
            self.parts.append(data)


def extract(doc):
    if doc["content_type"] == "text/html":
        parser = VisibleText()
        parser.feed(doc["content"])
        text = " ".join(parser.parts)
    else:
        text = doc["content"]
    # Formatting cleanup only. This does NOT remove prompt injection.
    return re.sub(r"\s+", " ", text).strip()


def run_adapter(bundle):
    """Replace this function with a chosen LLM adapter after reviewing its boundary.

    Input is one task and untrusted documents, never parent history/credentials.
    Output remains untrusted even if an LLM says it is safe.
    """
    findings = []
    for doc in bundle["documents"]:
        text = extract(doc)
        if text:
            findings.append({"source_id": doc["source_id"], "excerpt": text[:1200]})
    return {"version": 1, "findings": findings}


def main():
    try:
        bundle = load_json(sys.stdin.buffer.readline(MAX_WIRE_BYTES + 1))
        question = limited_text(bundle["question"], 1000, True)
        validate_bundle(bundle, question)
        if os.environ.get('WORKER_MODEL_MODE') == 'broker':
            request = {'version': 1, 'type': 'inference_request', 'question': question,
                       'documents': [{'source_id': d['source_id'], 'text': extract(d)[:4000]}
                                     for d in bundle['documents']]}
            sys.stdout.buffer.write(encode(request))
            sys.stdout.buffer.flush()
            response = load_json(sys.stdin.buffer.readline(131073), 131072)
            from contract import exact_keys, require
            exact_keys(response, {'version', 'content'})
            require(response['version'] == 1)
            result = load_json(limited_text(response['content'], 24000, True).encode('utf-8'), 32768)
        else:
            result = run_adapter(bundle)
        validate_result(result, {d["source_id"] for d in bundle["documents"]})
        sys.stdout.buffer.write(encode(result))
        return 0
    except Exception:
        # Never echo exception text, a URL, model logs, or a document to stderr.
        sys.stderr.write("worker_failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
