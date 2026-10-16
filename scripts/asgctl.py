#!/usr/bin/env python3
"""asgctl - read-only environment checks for Agent Security Gateway deployments (phase 1).

Commands:
  doctor  --role R   static checks of THIS host (versions, listeners, firewall, Hyper-V, secrets presence)
  plan    --role R   doctor plus which setup steps are still open; changes nothing
  secrets init / fragment merge / runs register   see asgctl_ops.py (phase 2; changes are dry-run by default)
  verify  --role R   behaviour checks (health endpoints, guest self-check, egress probes)
                     --deep also lifts the guest firewall for the duration of a test (restored afterwards)

Rules: no changes to the host, no secret values are read or printed (environment variables are reported by
name only, files by existence/permission only), output is JSON unless --human is given. Exit code 1 if any
check failed. Standard library only.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import locale
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ROLE_DIR = ROOT / "setup" / "roles"
TIME_SYNC_GUID = "2497F4DE-E9FA-4204-80E4-4B75C46419C0"
IS_WINDOWS = os.name == "nt"
LOOPBACK = {"127.0.0.1", "::1", "localhost"}
ANY_BIND = {"0.0.0.0", "::", "*"}


def result(check_id: str, status: str, detail: str = "", hint: str = "") -> dict:
    out = {"id": check_id, "status": status, "detail": detail}
    if hint and status in ("fail", "warn"):
        out["hint"] = hint
    return out


def run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 124, f"{type(exc).__name__}"
    enc = locale.getpreferredencoding(False) or "utf-8"
    out = proc.stdout.decode("utf-8", errors="replace") if b"\xef\xbb\xbf" in proc.stdout[:3] else proc.stdout.decode(enc, errors="replace")
    return proc.returncode, out


def powershell(script: str, timeout: int = 60) -> tuple[int, str]:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return 127, "powershell not found"
    prefix = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ErrorActionPreference='Stop';"
    return run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script], timeout)


def ps_json(script: str, timeout: int = 60):
    rc, out = powershell("& { " + script + " } | ConvertTo-Json -Compress -Depth 5", timeout)
    if rc != 0:
        return None, out.strip()[:200]
    try:
        return json.loads(out.strip() or "null"), ""
    except json.JSONDecodeError:
        return None, "unparsable output"


def listeners(port: int) -> list[str]:
    """Local addresses a TCP port is listening on."""
    binds: list[str] = []
    if IS_WINDOWS:
        data, _ = ps_json(f"@(Get-NetTCPConnection -State Listen -LocalPort {int(port)} -ErrorAction SilentlyContinue | "
                          "Select-Object -ExpandProperty LocalAddress)")
        if data:
            binds = [data] if isinstance(data, str) else list(data)
    else:
        rc, out = run(["ss", "-ltnH"]) if shutil.which("ss") else run(["netstat", "-an"])
        for line in out.splitlines():
            m = re.search(r"(\[[0-9a-fA-F:]+\]|[0-9.*:]+?)[:.](\d+)\s", line)
            if m and int(m.group(2)) == port and ("LISTEN" in line or line.startswith("LISTEN")):
                binds.append(m.group(1).strip("[]"))
    return sorted(set(binds))


# ----- individual checks -------------------------------------------------------------------------------

def check_python_version(c: dict) -> dict:
    need = tuple(int(x) for x in c["min"].split("."))
    have = sys.version_info[:3]
    ok = have >= need
    return result(c["id"], "ok" if ok else "fail", f"python {'.'.join(map(str, have))} (need >= {c['min']})",
                  "Install Python 3.10 or newer.")


def check_os_info(c: dict) -> dict:
    return result(c["id"], "ok", f"{platform.system()} {platform.release()} {platform.machine()}")


def check_command(c: dict) -> dict:
    path = shutil.which(c["name"])
    return result(c["id"], "ok" if path else "fail", c["name"] + (" found" if path else " not found"),
                  c.get("hint", f"Install {c['name']}."))


def check_listen(c: dict) -> dict:
    binds = listeners(int(c["port"]))
    if not binds:
        return result(c["id"], "warn", f"nothing listening on {c['port']}", c.get("hint", ""))
    exposed = [b for b in binds if b not in LOOPBACK]
    if c.get("expect") == "loopback" and exposed:
        return result(c["id"], "fail", f"port {c['port']} is reachable beyond loopback: {', '.join(binds)}", c.get("hint", ""))
    return result(c["id"], "ok", f"port {c['port']} listening on {', '.join(binds)}")


def check_env_vars(c: dict) -> dict:
    present = {n: (n in os.environ and bool(os.environ[n])) for n in c["names"]}  # names only, never values
    missing = [n for n, ok in present.items() if not ok]
    status = "ok" if not missing else ("fail" if c.get("required") else "warn")
    return result(c["id"], status, "set: " + (", ".join(n for n, ok in present.items() if ok) or "-") +
                  "; unset: " + (", ".join(missing) or "-"), c.get("hint", ""))


def check_hyperv_enabled(c: dict) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "not a Windows host")
    data, err = ps_json("[bool](Get-Command Get-VM -ErrorAction SilentlyContinue)")
    return result(c["id"], "ok" if data is True else "fail", "Hyper-V module available" if data is True else (err or "Hyper-V module missing"),
                  "Enable the Hyper-V feature and run from an elevated session.")


def normalize_cidr(value: str) -> str:
    try:
        return str(ipaddress.ip_network(value, strict=False))  # accepts both /29 and /255.255.255.248
    except ValueError:
        return value


def check_firewall_rule(c: dict) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "not a Windows host")
    name = c["name"].replace("'", "''")
    data, err = ps_json(f"$r=Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue; if($r){{ $a=$r|Get-NetFirewallAddressFilter; "
                        "[pscustomobject]@{enabled=[string]$r.Enabled;direction=[string]$r.Direction;action=[string]$r.Action;"
                        "remote=@($a.RemoteAddress)} }")
    if not data:
        return result(c["id"], "fail", f"rule '{c['name']}' not found", c.get("hint", ""))
    want = normalize_cidr(c["remote_address"])
    remotes = [normalize_cidr(r) for r in (data["remote"] if isinstance(data["remote"], list) else [data["remote"]])]
    problems = []
    if str(data["enabled"]).lower() not in ("true", "1"):
        problems.append("disabled")
    if str(data["direction"]).lower() not in ("inbound", "1"):
        problems.append("not inbound")
    if str(data["action"]).lower() not in ("block", "4"):
        problems.append("not a block rule")
    if want not in remotes:
        problems.append(f"remote address {remotes} != {want}")
    return result(c["id"], "fail" if problems else "ok", ("; ".join(problems)) or f"inbound block from {want}", c.get("hint", ""))


def check_hyperv_vm(c: dict) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "not a Windows host")
    name = c["name"].replace("'", "''")
    data, err = ps_json(
        f"$v=Get-VM -Name '{name}' -ErrorAction SilentlyContinue; if($v){{ $nic=Get-VMNetworkAdapter -VM $v; "
        "$sw=@($nic|ForEach-Object{ if($_.SwitchName){(Get-VMSwitch -Name $_.SwitchName).SwitchType.ToString()} else {'Disconnected'} }); "
        "[pscustomobject]@{state=[string]$v.State;auto_cp=[bool]$v.AutomaticCheckpointsEnabled;switch_types=$sw;"
        "svc=@(Get-VMIntegrationService -VM $v|Where-Object Enabled|ForEach-Object{$_.Id});"
        "checkpoints=@(Get-VMSnapshot -VM $v|ForEach-Object{$_.Name})} }")
    if not data:
        return result(c["id"], "fail", f"VM '{c['name']}' not found" + (f" ({err})" if err else ""), c.get("hint", ""))
    problems = []
    switches = data["switch_types"] if isinstance(data["switch_types"], list) else [data["switch_types"]]
    for st in switches:
        if st not in (c.get("switch_type", "Internal"), "Disconnected"):
            problems.append(f"switch type {st}")
    services = data["svc"] if isinstance(data["svc"], list) else ([data["svc"]] if data["svc"] else [])
    extra = [s for s in services if TIME_SYNC_GUID.lower() not in str(s).lower()]
    if extra:
        problems.append(f"{len(extra)} integration service(s) enabled besides time sync")
    if data["auto_cp"]:
        problems.append("automatic checkpoints enabled")
    cps = data["checkpoints"] if isinstance(data["checkpoints"], list) else ([data["checkpoints"]] if data["checkpoints"] else [])
    if c.get("checkpoint") and c["checkpoint"] not in cps:
        problems.append(f"checkpoint '{c['checkpoint']}' missing")
    return result(c["id"], "fail" if problems else "ok",
                  f"state={data['state']}; " + ("; ".join(problems) if problems else "isolation settings as designed"))


def loopback_only(url: str) -> bool:
    return (urllib.parse.urlsplit(url).hostname or "") in LOOPBACK


def fetch_json(url: str):
    if not loopback_only(url):
        raise ValueError("only loopback URLs are probed in phase 1")
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=5) as resp:
        return json.loads(resp.read(65536).decode("utf-8"))


def check_http_health(c: dict) -> dict:
    try:
        body = fetch_json(c["url"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return result(c["id"], "fail", f"{c['url']}: {type(exc).__name__}", c.get("hint", "Is ASG (or the tunnel) up?"))
    ok = body.get("ok") is True and body.get("app") == c.get("app", body.get("app"))
    return result(c["id"], "ok" if ok else "fail", f"app={body.get('app')} ok={body.get('ok')} routes={body.get('routes')}")


def check_http_json_ok(c: dict) -> dict:
    try:
        body = fetch_json(c["url"])
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return result(c["id"], "fail", f"{c['url']}: {type(exc).__name__}")
    return result(c["id"], "ok" if body.get("ok") is True else "fail", f"ok={body.get('ok')}")


def lab_ssh(c: dict, command: str, timeout: int = 90) -> tuple[int, str]:
    helper = Path(os.environ.get("ASGCTL_LAB_PRESETS", ROOT / "presets" / "isolated" / "vm")) / "hyperv" / "Invoke-AsgLabSsh.ps1"
    if not helper.exists():
        return 127, "Invoke-AsgLabSsh.ps1 not found"
    exe = shutil.which("powershell") or shutil.which("pwsh")
    cmd = [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(helper), "-Command", command,
           "-GuestIp", c.get("guest_ip", "172.29.91.2"), "-TimeoutSeconds", str(timeout)]
    return run(cmd, timeout + 30)


def check_guest_selfcheck(c: dict) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "Hyper-V host checks need Windows")
    rc, out = lab_ssh(c, "sudo asg-lab-selfcheck")
    m = re.search(r"\{.*\}", out)
    if not m:
        return result(c["id"], "fail", "no self-check output (guest unreachable?)")
    data = json.loads(m.group(0))
    problems = []
    if data.get("profile") != "offline":
        problems.append(f"profile={data.get('profile')}")
    if data.get("firewall_table_present") is not True:
        problems.append("guest firewall table missing")
    if data.get("ssh_password_auth") != "no":
        problems.append("ssh password auth enabled")
    if data.get("default_routes") != 0:
        problems.append("guest has a default route")
    return result(c["id"], "fail" if problems else "ok", "; ".join(problems) or "offline profile, firewall present, key-only ssh, no default route")


def check_guest_egress(c: dict, deep: bool = False) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "Hyper-V host checks need Windows")
    if c.get("deep") and not deep:
        return result(c["id"], "skip", "needs --deep (lifts the guest firewall temporarily)")
    targets = c["targets"]
    for t in targets:  # targets come from our own role file, but still validate the shape before it reaches a shell
        host, _, port = t.rpartition(":")
        ipaddress.ip_address(host)
        if not port.isdigit():
            return result(c["id"], "fail", f"bad target {t}")
    probe = "for d in " + " ".join(targets) + '; do if timeout 3 bash -c "exec 3<>/dev/tcp/${d%%:*}/${d##*:}" 2>/dev/null; then echo "REACHABLE $d"; else echo "blocked $d"; fi; done'
    if c.get("deep"):
        script = ("set +e; trap 'sudo nft -f /etc/nftables.conf' EXIT; sudo nft flush ruleset; " + probe +
                  "; sudo nft -f /etc/nftables.conf; echo \"firewall_restored=$(sudo nft list ruleset | grep -c asg_lab)\"")
    else:
        script = probe
    rc, out = lab_ssh(c, script, timeout=120)
    reachable = re.findall(r"^REACHABLE (\S+)", out, flags=re.M)
    blocked = re.findall(r"^blocked\s+(\S+)", out, flags=re.M)
    if len(reachable) + len(blocked) != len(targets):
        return result(c["id"], "fail", "probe did not complete (guest unreachable?)")
    detail = f"blocked: {', '.join(blocked) or '-'}"
    if c.get("deep") and "firewall_restored=0" in out:
        return result(c["id"], "fail", "guest firewall was NOT restored; restore the baseline-clean checkpoint")
    if reachable:
        return result(c["id"], "fail", f"reachable from the guest: {', '.join(reachable)}; " + detail,
                      c.get("hint", "Apply the host firewall rule (Block-LabToHost.ps1)."))
    return result(c["id"], "ok", detail)


def check_scheduled_task(c: dict) -> dict:
    if not IS_WINDOWS:
        return result(c["id"], "skip", "not a Windows host")
    name = c["name"].replace("'", "''")
    data, err = ps_json(f"$t=Get-ScheduledTask -TaskName '{name}' -ErrorAction SilentlyContinue; if($t){{ [pscustomobject]@{{state=[string]$t.State}} }}")
    if not data:
        return result(c["id"], "fail", f"scheduled task '{c['name']}' not found", c.get("hint", ""))
    ok = str(data["state"]) in ("Running", "Ready", "3", "4")
    return result(c["id"], "ok" if ok else "fail", f"task {c['name']}: {data['state']}", c.get("hint", ""))


def check_docker_image(c: dict) -> dict:
    exe = shutil.which("docker")
    if not exe:
        return result(c["id"], "fail", "docker not found", c.get("hint", ""))
    rc, out = run([exe, "images", "--format", "{{.Repository}}"], 30)
    present = rc == 0 and c["repository"] in out.split()
    return result(c["id"], "ok" if present else "fail", f"image {c['repository']} " + ("present" if present else "missing"), c.get("hint", ""))


def check_http_refuses(c: dict) -> dict:
    """An unauthenticated request to a loopback service must be refused (401/403), not served and not hanging."""
    if not loopback_only(c["url"]):
        return result(c["id"], "fail", "only loopback URLs are probed")
    request = urllib.request.Request(c["url"], data=b"{}", method=c.get("method", "POST"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=8) as resp:
            return result(c["id"], "fail", f"served an unauthenticated request (http {resp.status})", "The service must reject unsigned requests.")
    except urllib.error.HTTPError as exc:
        refused = exc.code in (401, 403)
        return result(c["id"], "ok" if refused else "fail", f"http {exc.code}", "Expected 401 or 403 for an unauthenticated request.")
    except OSError as exc:
        return result(c["id"], "fail", f"{type(exc).__name__}: service not reachable")


CHECKS = {
    "python_version": check_python_version, "os_info": check_os_info, "command": check_command, "listen": check_listen,
    "env_vars": check_env_vars, "hyperv_enabled": check_hyperv_enabled, "firewall_rule": check_firewall_rule,
    "hyperv_vm": check_hyperv_vm, "http_health": check_http_health, "http_json_ok": check_http_json_ok,
    "guest_selfcheck": check_guest_selfcheck, "guest_egress": check_guest_egress,
    "scheduled_task": check_scheduled_task, "docker_image": check_docker_image, "http_refuses": check_http_refuses,
}


def load_role(role: str, role_dir: Path) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{1,30}", role):
        raise SystemExit(f"asgctl: bad role name {role!r}")
    path = role_dir / f"{role}.json"
    if not path.exists():
        known = ", ".join(sorted(p.stem for p in role_dir.glob("*.json")))
        raise SystemExit(f"asgctl: unknown role {role!r} (known: {known})")
    return json.loads(path.read_text(encoding="utf-8"))


def run_checks(items: list[dict], deep: bool = False) -> list[dict]:
    out = []
    for c in items:
        fn = CHECKS.get(c["type"])
        if fn is None:
            out.append(result(c["id"], "fail", f"unknown check type {c['type']}"))  # fail closed
        elif c["type"] == "guest_egress":
            out.append(fn(c, deep))
        else:
            out.append(fn(c))
    return out


def summarize(checks: list[dict]) -> dict:
    counts = {s: sum(1 for c in checks if c["status"] == s) for s in ("ok", "warn", "fail", "skip")}
    return {"healthy": counts["fail"] == 0, **counts}


def build_plan(role: dict, checks: list[dict]) -> list[dict]:
    status = {c["id"]: c["status"] for c in checks}
    steps = []
    for s in role.get("steps", []):
        needs = s.get("needs", [])
        if s.get("manual") and not needs:
            steps.append({"step": s["step"], "state": "manual"})
        else:
            open_ = [n for n in needs if status.get(n) not in ("ok", "skip")]
            steps.append({"step": s["step"], "state": "todo" if open_ else "done", **({"blocked_by": open_} if open_ else {})})
    return steps


def render_human(report: dict) -> str:
    marks = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL", "skip": "skip"}
    lines = [f"role={report['role']} command={report['command']} host={report['host']}"]
    for c in report["checks"]:
        lines.append(f"  [{marks[c['status']]}] {c['id']}: {c['detail']}")
        if c.get("hint"):
            lines.append(f"         hint: {c['hint']}")
    for s in report.get("plan", []):
        lines.append(f"  ({s['state']}) {s['step']}")
    s = report["summary"]
    lines.append(f"summary: healthy={s['healthy']} ok={s['ok']} warn={s['warn']} fail={s['fail']} skip={s['skip']}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] in ("secrets", "fragment", "runs", "canary"):  # phase 2 operations live in asgctl_ops
        import asgctl_ops
        return asgctl_ops.main(argv)
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["doctor", "plan", "verify"])
    ap.add_argument("--role", required=True)
    ap.add_argument("--role-dir", type=Path, default=DEFAULT_ROLE_DIR)
    ap.add_argument("--deep", action="store_true", help="verify only: run checks that temporarily lift the guest firewall")
    ap.add_argument("--human", action="store_true", help="human-readable output instead of JSON")
    args = ap.parse_args(argv)

    role = load_role(args.role, args.role_dir)
    if args.command == "verify":
        checks = run_checks(role.get("verify", []), deep=args.deep)
    else:
        checks = run_checks(role.get("doctor", []))
    report = {"role": role["role"], "command": args.command, "host": platform.node(), "checks": checks, "summary": summarize(checks)}
    if args.command == "plan":
        report["plan"] = build_plan(role, checks)
    print(render_human(report) if args.human else json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["summary"]["healthy"] else 1


if __name__ == "__main__":
    sys.exit(main())
