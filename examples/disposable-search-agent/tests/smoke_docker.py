"""Real runtime checks; requires the built image and a running Linux engine."""
import json
from pathlib import Path
import subprocess
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runtime
import contract

PROBE = r'''
import json, os
from pathlib import Path
checks = {}
checks["non_root"] = os.getuid() == 65532
checks["no_docker_socket"] = not Path("/var/run/docker.sock").exists()
checks["no_host_mount"] = not Path("/host").exists()
status = Path("/proc/self/status").read_text()
checks["no_capabilities"] = "CapEff:\t0000000000000000" in status
checks["no_new_privileges"] = "NoNewPrivs:\t1" in status
checks["seccomp_enabled"] = "Seccomp:\t2" in status
checks["loopback_only"] = set(os.listdir("/sys/class/net")) == {"lo"}
# The official Python image includes GPG_KEY, a public release-verification key.
checks["no_credentials"] = not any(("TOKEN" in k or "KEY" in k) and k != "GPG_KEY"
                                   for k in os.environ)
checks["fresh_tmp"] = not Path("/tmp/previous-job-marker").exists()
Path("/tmp/previous-job-marker").write_text("temporary")
try:
    Path("/app/forbidden").write_text("x")
    checks["read_only"] = False
except OSError:
    checks["read_only"] = True
print(json.dumps(checks))
'''


def main():
    for _ in range(2):
        name = "disposable-search-" + uuid.uuid4().hex
        try:
            raw = runtime.bounded_process(runtime.docker_command(name, ["-I", "-c", PROBE]), b"", 25, 4096)
            checks = contract.load_json(raw, 4096)
            assert checks and all(checks.values()), checks
        finally:
            subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10)
        inspect = subprocess.run(["docker", "inspect", name], stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=10)
        assert inspect.returncode != 0, "Container remains after completion"
    bundle = runtime.demo_bundle()
    result = runtime.docker_job(bundle)
    receipt = contract.make_receipt(uuid.uuid4().hex, bundle, result)
    assert b"Ignore previous" not in contract.encode(receipt)
    print(json.dumps({"docker_isolation": "passed", "fresh_containers": 2, "receipt_boundary": "passed"}))


if __name__ == "__main__":
    main()
