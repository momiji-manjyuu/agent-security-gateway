"""Trusted host service. Bind to loopback and connect ONLY through ASG.

The child has no network, host filesystem, API keys, or Docker API access.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import sqlite3
import sys
import uuid

from contract import encode, load_json, make_receipt, require
from gateway_link import (artifact_packet, secret, submit_artifact, task_from_packet,
                          verify_backend)
from runtime import collect_job, demo_bundle, docker_job


@contextmanager
def database(path):
    db = sqlite3.connect(path)
    try:
        with db:
            yield db
    finally:
        db.close()


def perform(task, run_id, task_id):
    bundle = collect_job(task)
    require(bool(bundle["documents"]))
    result = docker_job(bundle)
    # Full page bodies remain in memory. Only bounded excerpts go to ASG quarantine.
    report = {"format": "disposable-search-report.v1", "adapter": os.environ.get('WORKER_ADAPTER', 'reference'),
              "sources": [{"source_id": d["source_id"], "url": d["url"]}
                          for d in bundle["documents"]],
              "findings": result["findings"]}
    ref = submit_artifact(artifact_packet(report, run_id, task_id),
                          secret("ASG_WORKER_TOKEN"),
                          os.environ.get("ASG_BASE_URL", "http://127.0.0.1:18788"))
    return {"version": 1, "status": "stored", **ref,
            "source_count": len(bundle["documents"]),
            "fetch_failures": bundle["fetch_failures"], "external_text_returned": False}


class RunnerServer(HTTPServer):
    # Deliberately one active job at a time. Bind only to the SSH tunnel endpoint.
    request_queue_size = 4

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(15)
        return connection, address


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # Default HTTP logs may contain attacker-controlled request text.

    def reply(self, status, value):
        raw = encode(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        self.reply(200 if self.path == "/healthz" else 404,
                   {"service": "disposable-search-runner", "version": 1})

    def do_POST(self):
        try:
            require(self.path == "/v1/tasks")
            require(self.headers.get("Transfer-Encoding") is None)
            for header in ("Authorization", "Content-Length", "Content-Type", "X-ASG-Agent-Id",
                           "X-ASG-Route-Id", "X-ASG-Run-Id", "X-ASG-Task-Id", "X-ASG-Timestamp",
                           "X-ASG-Request-SHA256", "X-ASG-Signature"):
                require(len(self.headers.get_all(header, [])) == 1)
            require(self.headers.get("Content-Type", "").split(";")[0] == "application/json")
            size = int(self.headers.get("Content-Length", "0"))
            require(0 < size <= 32768)
            raw = self.rfile.read(size)
            require(len(raw) == size)
            run_id, task_id = verify_backend(self.headers, raw, self.server.backend_token,
                                             self.server.hmac_key, self.server.allowed_callers)
            packet = load_json(raw, 32768)
            task = task_from_packet(packet, run_id, task_id)
        except Exception:
            self.reply(403, {"status": "rejected", "error_code": "request_rejected"})
            return

        job_key = hashlib.sha256((run_id + "\n" + task_id).encode()).hexdigest()
        body_hash = hashlib.sha256(raw).hexdigest()
        with database(self.server.db_path) as db:
            prior = db.execute("SELECT body_hash, response FROM jobs WHERE job_key=?",
                               (job_key,)).fetchone()
            if prior:
                if prior[0] == body_hash and prior[1]:
                    self.reply(200, load_json(prior[1]))
                else:
                    self.reply(409, {"status": "rejected", "error_code": "duplicate_task"})
                return
            db.execute("INSERT INTO jobs VALUES (?, ?, NULL)", (job_key, body_hash))
            db.commit()  # Persist before any collection, container or artifact operation.
        try:
            receipt = perform(task, run_id, task_id)
        except Exception:
            # Retain the claim. A crash/uncertain upload must not auto-repeat side effects.
            self.reply(502, {"status": "failed", "error_code": "job_failed"})
            return
        with database(self.server.db_path) as db:
            db.execute("UPDATE jobs SET response=? WHERE job_key=?", (encode(receipt), job_key))
        self.reply(200, receipt)


def serve(args):
    token = secret("SEARCH_BACKEND_TOKEN")
    hmac_key = secret("ASG_BACKEND_HMAC_KEY")
    secret("ASG_WORKER_TOKEN")
    callers = os.environ.get("ASG_ALLOWED_CALLERS", "controller").split(",")
    state = Path(args.state).resolve()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    db_path = state / "jobs.sqlite3"
    with database(db_path) as db:
        db.execute("CREATE TABLE IF NOT EXISTS jobs "
                   "(job_key TEXT PRIMARY KEY, body_hash TEXT NOT NULL, response BLOB)")
    server = RunnerServer(("127.0.0.1", args.port), Handler)
    server.backend_token, server.hmac_key = token, hmac_key
    server.allowed_callers, server.db_path = callers, db_path
    print("runner_ready", file=sys.stderr)
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers(dest="command", required=True)
    subs.add_parser("demo", help="Offline Docker smoke run; does not contact ASG")
    server = subs.add_parser("serve", help="Authenticated ASG backend")
    server.add_argument("--port", type=int, default=8790)
    server.add_argument("--state", default="runs/runner-state")
    args = parser.parse_args()
    try:
        if args.command == "demo":
            bundle = demo_bundle()
            result = docker_job(bundle)
            sys.stdout.buffer.write(encode(make_receipt(uuid.uuid4().hex, bundle, result)))
        else:
            serve(args)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        sys.stdout.buffer.write(encode({"status": "failed", "error_code": "runtime_or_config_error"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
