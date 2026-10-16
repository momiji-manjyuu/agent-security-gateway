"""Real ASG routing, HMAC, quarantine and output guard, entirely on loopback.

Usage: python tests/check_asg_compatibility.py /path/to/agent-security-gateway
Only collection/Docker are mocked. Credentials and storage are temporary.
"""
import copy
import datetime as dt
import hashlib
import http.client
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import contract
import gateway_link as link
import runner
import runtime
import worker


def main():
    sys.path.insert(0, str(Path(sys.argv[1]).resolve()))
    import gateway
    controller_token, worker_token = "test-controller-" + "a" * 32, "test-worker-" + "b" * 32
    backend_token, signature_key = "test-backend-" + "c" * 32, "test-signature-" + "d" * 32
    env = {"ASG_WORKER_TOKEN": worker_token, "ASG_SEARCH_BACKEND_KEY": backend_token,
           "SEARCH_BACKEND_TOKEN": backend_token, "ASG_BACKEND_HMAC_KEY": signature_key}
    with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, env):
        root = Path(temp)
        backend = runner.RunnerServer(("127.0.0.1", 0), runner.Handler)
        backend.backend_token, backend.hmac_key = backend_token, signature_key
        backend.allowed_callers = ["controller"]
        backend.db_path = root / "jobs.sqlite3"
        with runner.database(backend.db_path) as db:
            db.execute("CREATE TABLE jobs (job_key TEXT PRIMARY KEY, body_hash TEXT NOT NULL, response BLOB)")
        cfg = copy.deepcopy(gateway.DEFAULT_CONFIG)
        cfg.update(json.loads((runtime.ROOT / "asg/config.fragment.json").read_text()))
        cfg["bind"], cfg["port"] = "127.0.0.1", 8788
        cfg["audit_log"], cfg["kill_switch_file"] = str(root / "audit.jsonl"), str(root / "KILL_SWITCH")
        cfg["approval_store"] = str(root / "approvals.jsonl")
        cfg["run_store"] = {"path": str(root / "runs.jsonl")}
        cfg["artifact_store"]["path"] = str(root / "artifacts")
        cfg["rate_limit"]["enabled"] = False
        cfg["agents"]["controller"]["token_sha256"] = hashlib.sha256(controller_token.encode()).hexdigest()
        cfg["agents"]["lab_worker"]["token_sha256"] = hashlib.sha256(worker_token.encode()).hexdigest()
        cfg["routes"][link.TASK_ROUTE]["backend"]["base_url"] = f"http://127.0.0.1:{backend.server_port}"
        cfg["runs"] = {"run-test": {
            "allowed_routes": [link.TASK_ROUTE, link.ARTIFACT_ROUTE],
            "allowed_callers": ["controller", "lab_worker"],
            "expires_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=15)).isoformat()}}
        gateway.validate_config(cfg)
        asg = gateway.ThreadingHTTPServer(("127.0.0.1", 0), gateway.GatewayHandler)
        asg.config = cfg
        threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (backend, asg)]
        for thread in threads:
            thread.start()
        os.environ["ASG_BASE_URL"] = f"http://127.0.0.1:{asg.server_port}"
        try:
            data = json.loads((runtime.ROOT / "asg/task.example.json").read_text(encoding="utf-8"))
            data["run_id"] = "run-test"
            responses = []
            for case in ("clean", "injected"):
                data["task_id"] = case
                bundle = runtime.demo_bundle()
                if case == "clean":
                    bundle["documents"][0]["content"] = "Container networking can be disabled."
                with patch("runner.collect_job", return_value=bundle), \
                        patch("runner.docker_job", side_effect=worker.run_adapter):
                    conn = http.client.HTTPConnection("127.0.0.1", asg.server_port, timeout=15)
                    try:
                        conn.request("POST", "/v1/tasks", contract.encode(data), headers={
                            "Authorization": "Bearer " + controller_token, "X-ASG-Route": link.TASK_ROUTE,
                            "X-Agent-Capability": "delegate_web_research", "Content-Type": "application/json"})
                        response = conn.getresponse()
                        raw = response.read()
                        assert response.status == 200, (response.status, raw[:1000])
                        assert b"Ignore previous" not in raw and b"example.com" not in raw
                        assert b"external_text_returned" in raw and b"art_" in raw
                        receipt = contract.load_json(raw)
                        if case == "clean":
                            assert receipt["artifact_status"] == "verified"
                        else:
                            assert receipt["artifact_status"] in {"blocked", "needs_review"}
                        responses.append({"case": case, "artifact_status": receipt["artifact_status"],
                                          "parent_received_external_text": False})
                    finally:
                        conn.close()
            print(json.dumps({"compatibility": "passed", "cases": responses}))
        finally:
            for server in (backend, asg):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()


if __name__ == "__main__":
    main()
