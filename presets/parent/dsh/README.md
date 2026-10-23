# dsh integration (parent host)

1. Put `setup/firecracker-worker/spawn_worker.py` in `<SPAWN_WORKER_DIR>`. Create `~/.asg/spawn_worker.json` from
   `setup/firecracker-worker/spawn_worker.example.json`: ASG URL, worker-host ssh target, token file path, provider
   key env name.
2. Merge `asg-worker.patch.example.yml` into your dsh profile patch (web/tui) or use it headless:
   `dsh headless --patch asg-worker.patch.yml "use spawn_worker once ..."`.
3. Restart the dsh instance after replacing `spawn_worker.py`. The MCP child loads the file at start.
4. Check the schema rejection with `python spawn_worker.py mcp`. Send a `tools/call` that has an extra `test_mode`
   argument; it must return `unknown_arguments`.
5. Verify one benign run in the ASG audit log (`scripts/asg_audit_query.py --prefix fcw-`). Expected sequence:
   registered, `fc.llm.chat` allow, artifact verified, parent metadata/download, revoke.

Do not put Tailscale names, trusted-host lists or boot tokens in shared templates.
