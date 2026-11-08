"""research_service repo_auditor part: registration, archive handling, read-only tree/read/grep, quotas."""
import io
import socket
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "setup" / "research-service"))
import research_service as rs  # noqa: E402

PUBLIC = lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("140.82.121.9", port))]  # noqa: E731


def cfg(**over):
    c = rs.load_config()
    c.update(over)
    return c


def tarball(members, fmt=tarfile.PAX_FORMAT):
    """members: list of (name, bytes|None, type) -> .tar.gz bytes. type default regular file; None data = directory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz", format=fmt) as tf:
        for item in members:
            name, data = item[0], item[1]
            kind = item[2] if len(item) > 2 else (tarfile.DIRTYPE if data is None else tarfile.REGTYPE)
            ti = tarfile.TarInfo(name)
            ti.type = kind
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                ti.linkname = "/etc/passwd"
                tf.addfile(ti)
            elif data is None:
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


GOOD = tarball([
    ("proj-main/", None),
    ("proj-main/README.md", b"# Proj\nhello\nrouter at 192.168.1.1 and 127.0.0.1\n"),
    ("proj-main/src/", None),
    ("proj-main/src/app.py", b"def main():\n    token = os.environ['API_TOKEN']\n    return 1\n"),
    ("proj-main/src/util.py", b"import html\nS = '&lt;tag&gt;'\n"),
    ("proj-main/logo.png", b"\x89PNG\r\n\x00\x00binary"),
    ("proj-main/big.txt", b"x" * 2000),
    ("proj-main/link", None, tarfile.SYMTYPE),
])


def getter_for(blob, status=200, calls=None):
    def getter(url, addrs, c, **kw):
        if calls is not None:
            calls.append((url, addrs, kw))
        return status, {}, blob
    return getter


def new_run(c=None, repos=None, **limits):
    c = c or cfg()
    reg = rs.Registry(c)
    reg.register("run-1", [], limits, repos if repos is not None else [{"owner": "Acme", "repo": "Proj", "ref": "main"}])
    return c, reg.get("run-1")


class RegistrationTests(unittest.TestCase):
    def test_valid_spec_normalised_and_defaults_to_github(self):
        spec = rs.repo_spec({"owner": "Acme", "repo": "Proj", "ref": "v1.2.3"}, cfg())
        self.assertEqual((spec["forge"], spec["name"]), ("github.com", "acme/proj"))

    def test_rejects_bad_specs(self):
        c = cfg()
        bad = [None, "x", {"owner": "a", "repo": "b"}, {"owner": "a", "repo": "b", "ref": "../x"}, {"owner": "..", "repo": "b", "ref": "m"},
               {"owner": "a/b", "repo": "c", "ref": "m"}, {"owner": "a", "repo": "b.git", "ref": "m"}, {"owner": "a", "repo": "b", "ref": "m", "x": 1},
               {"owner": "a", "repo": "b", "ref": "a//b"}, {"owner": "a", "repo": "b", "ref": "-flag"}, {"owner": "a", "repo": "b", "ref": "m", "forge": "evil.example"},
               {"owner": "a", "repo": "b", "ref": "m", "forge": "github.com/../x"}, {"owner": "a b", "repo": "c", "ref": "m"}, {"owner": 1, "repo": "c", "ref": "m"}]
        for raw in bad:
            self.assertIsNone(rs.repo_spec(raw, c), raw)

    def test_register_keeps_at_most_max_repos_and_drops_duplicates(self):
        c = cfg(repo_max_repos=2)
        reg = rs.Registry(c)
        out = reg.register("r", [], {}, [{"owner": "a", "repo": "one", "ref": "m"}, {"owner": "a", "repo": "two", "ref": "m"},
                                         {"owner": "a", "repo": "three", "ref": "m"}])
        self.assertEqual(out["repos"], 2)
        out = reg.register("r2", [], {}, [{"owner": "a", "repo": "one", "ref": "m"}, {"owner": "A", "repo": "ONE", "ref": "x"}])
        self.assertEqual(out["repos"], 1)

    def test_template_validation(self):
        for bad in ("http://x.example/{owner}", "https://u:p@x.example/{owner}", "https://x.example:8443/{owner}", "https://x.example/{other}", "https://x.example/{}"):
            with self.assertRaises(ValueError, msg=bad):
                self._load({"repo_forges": {"x.example": bad}})

    def _load(self, user):
        import json
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "c.json")
            Path(p).write_text(json.dumps(user), encoding="utf-8")
            return rs.load_config(p)

    def test_null_removes_default_forge(self):
        self.assertEqual(self._load({"repo_forges": {"github.com": None}})["repo_forges"], {})


class ArchiveTests(unittest.TestCase):
    def test_loads_tree_and_classifies_files(self):
        snap = rs.load_archive(GOOD, cfg(repo_max_file_bytes=1000))
        self.assertEqual(snap.meta["README.md"][1], "text")
        self.assertEqual(snap.meta["logo.png"][1], "binary")
        self.assertEqual(snap.meta["big.txt"][1], "large")
        self.assertNotIn("big.txt", snap.files)
        self.assertNotIn("link", snap.meta)
        self.assertEqual(snap.skipped, 1)

    def test_unsafe_member_names_reject_the_whole_archive(self):
        for name in ("proj/../../etc/passwd", "/etc/passwd", "proj/a/../../b", "proj/./x", "../x"):
            blob = tarball([("proj/", None), (name, b"x")], fmt=tarfile.GNU_FORMAT)
            with self.assertRaises(rs.Denied, msg=name) as ctx:
                rs.load_archive(blob, cfg())
            self.assertEqual(ctx.exception.code, "archive_unsafe_path", name)

    def test_backslash_and_control_chars_rejected(self):
        for name in ("proj/a\\b", "proj/a\x01b"):
            with self.assertRaises(rs.Denied):
                rs.load_archive(tarball([(name, b"x")], fmt=tarfile.GNU_FORMAT), cfg())

    def test_hard_links_devices_are_skipped_not_followed(self):
        blob = tarball([("proj/", None), ("proj/ok.txt", b"ok"), ("proj/h", None, tarfile.LNKTYPE), ("proj/fifo", None, tarfile.FIFOTYPE)])
        snap = rs.load_archive(blob, cfg())
        self.assertEqual(sorted(snap.meta), ["ok.txt"])
        self.assertEqual(snap.skipped, 2)

    def test_size_caps(self):
        blob = tarball([("p/", None), ("p/a", b"a" * 600), ("p/b", b"b" * 600)])
        with self.assertRaises(rs.Denied) as ctx:
            rs.load_archive(blob, cfg(repo_max_uncompressed_bytes=1000))
        self.assertEqual(ctx.exception.code, "archive_too_large")
        with self.assertRaises(rs.Denied) as ctx:
            rs.load_archive(blob, cfg(repo_max_files=1))
        self.assertEqual(ctx.exception.code, "archive_too_many_files")
        with self.assertRaises(rs.Denied) as ctx:
            rs.load_archive(blob, cfg(repo_max_members=2))
        self.assertEqual(ctx.exception.code, "archive_too_large")

    def test_garbage_and_empty(self):
        with self.assertRaises(rs.Denied) as ctx:
            rs.load_archive(b"not a tarball", cfg())
        self.assertEqual(ctx.exception.code, "archive_invalid")
        with self.assertRaises(rs.Denied) as ctx:
            rs.load_archive(tarball([("p/", None)]), cfg())
        self.assertEqual(ctx.exception.code, "archive_empty")

    def test_nothing_is_written_to_disk(self):
        import os
        import tempfile
        before = set(os.listdir(tempfile.gettempdir()))
        rs.load_archive(GOOD, cfg())
        self.assertEqual(set(os.listdir(tempfile.gettempdir())) - before, set())


class DoRepoTests(unittest.TestCase):
    def call(self, run, c, getter=None, **payload):
        return rs.do_repo(run, payload, c, getter or getter_for(GOOD), PUBLIC)

    def test_list_read_grep(self):
        c, run = new_run(cfg(repo_max_file_bytes=1000))
        top = self.call(run, c, repo="acme/proj", op="list_tree")
        self.assertEqual([e["name"] for e in top["entries"]], ["src", "README.md", "big.txt", "logo.png"])
        self.assertEqual(top["entries"][0]["type"], "dir")
        self.assertEqual({e["name"]: e.get("kind") for e in top["entries"]}["logo.png"], "binary")
        sub = self.call(run, c, repo="ACME/Proj", op="list_tree", path="src")
        self.assertEqual([e["name"] for e in sub["entries"]], ["app.py", "util.py"])
        page = self.call(run, c, repo="acme/proj", op="read_file", path="src/app.py")
        self.assertIn("1: def main():", page["text"])
        self.assertEqual((page["total_lines"], page["truncated"]), (4, False))
        hits = self.call(run, c, repo="acme/proj", op="grep", pattern="api_token")
        self.assertEqual([(m["path"], m["line"]) for m in hits["matches"]], [("src/app.py", 2)])
        self.assertEqual(self.call(run, c, repo="acme/proj", op="grep", pattern="API_TOKEN", ignore_case=False)["matches"][0]["line"], 2)

    def test_archive_downloaded_once_from_fixed_template_with_pinned_dns_answer(self):
        c, run = new_run()
        calls = []
        g = getter_for(GOOD, calls=calls)
        for _ in range(3):
            self.call(run, c, g, repo="acme/proj", op="list_tree")
        self.assertEqual(len(calls), 1)
        url, addrs, kw = calls[0]
        self.assertEqual(url, "https://codeload.github.com/Acme/Proj/tar.gz/main")
        self.assertEqual(addrs, ["140.82.121.9"])
        self.assertEqual(kw["max_bytes"], c["repo_max_archive_bytes"])

    def test_private_dns_answer_for_forge_is_refused(self):
        c, run = new_run()
        private = lambda host, port, type=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]  # noqa: E731
        with self.assertRaises(rs.Denied) as ctx:
            rs.do_repo(run, {"repo": "acme/proj", "op": "list_tree"}, c, getter_for(GOOD), private)
        self.assertEqual(ctx.exception.code, "non_public_address")

    def test_unregistered_repo_and_bad_op(self):
        c, run = new_run()
        for payload, code in (({"repo": "other/thing", "op": "list_tree"}, "repo_not_registered"),
                              ({"repo": None, "op": "list_tree"}, "repo_not_registered"),
                              ({"repo": "acme/proj", "op": "write_file"}, "bad_op"),
                              ({"repo": "acme/proj"}, "bad_op")):
            with self.assertRaises(rs.Denied) as ctx:
                rs.do_repo(run, payload, c, getter_for(GOOD), PUBLIC)
            self.assertEqual(ctx.exception.code, code, payload)

    def test_run_without_repos_denies_everything(self):
        c, run = new_run(repos=[])
        with self.assertRaises(rs.Denied) as ctx:
            self.call(run, c, repo="acme/proj", op="list_tree")
        self.assertEqual(ctx.exception.code, "repo_not_registered")

    def test_path_errors(self):
        c, run = new_run(cfg(repo_max_file_bytes=1000))
        cases = [({"op": "read_file", "path": "../x"}, "bad_path"), ({"op": "read_file", "path": "/etc/passwd"}, "bad_path"),
                 ({"op": "read_file", "path": "a\\b"}, "bad_path"), ({"op": "read_file"}, "bad_path"),
                 ({"op": "list_tree", "path": "a//b"}, "bad_path"), ({"op": "read_file", "path": "nope.txt"}, "path_not_found"),
                 ({"op": "read_file", "path": "src"}, "path_not_found"), ({"op": "list_tree", "path": "nope"}, "path_not_found"),
                 ({"op": "list_tree", "path": "README.md"}, "not_a_directory"), ({"op": "read_file", "path": "logo.png"}, "not_text_file"),
                 ({"op": "read_file", "path": "big.txt"}, "file_too_large"), ({"op": "read_file", "path": "README.md", "start_line": 0}, "bad_start_line"),
                 ({"op": "read_file", "path": "README.md", "start_line": True}, "bad_start_line"), ({"op": "grep", "pattern": ""}, "bad_pattern"),
                 ({"op": "grep", "pattern": "x" * 201}, "bad_pattern"), ({"op": "grep", "pattern": 5}, "bad_pattern")]
        for payload, code in cases:
            with self.assertRaises(rs.Denied, msg=payload) as ctx:
                self.call(run, c, repo="acme/proj", **payload)
            self.assertEqual(ctx.exception.code, code, payload)

    def test_quota_counts_every_call(self):
        c, run = new_run(repo_calls=2)
        self.call(run, c, repo="acme/proj", op="list_tree")
        self.call(run, c, repo="acme/proj", op="list_tree")
        with self.assertRaises(rs.Denied) as ctx:
            self.call(run, c, repo="acme/proj", op="list_tree")
        self.assertEqual((ctx.exception.status, ctx.exception.code), (429, "repo_quota_exceeded"))

    def test_registered_limit_is_capped(self):
        c = cfg()
        reg = rs.Registry(c)
        reg.register("r", [], {"repo_calls": 10 ** 6}, [])
        self.assertEqual(reg.get("r").limits["repo_calls"], c["limit_caps"]["repo_calls"])

    def test_forge_errors(self):
        c, run = new_run()
        for status, code in ((404, "repo_not_found"), (500, "archive_fetch_failed"), (302, "archive_fetch_failed")):
            with self.assertRaises(rs.Denied) as ctx:
                rs.do_repo(run, {"repo": "acme/proj", "op": "list_tree"}, c, getter_for(b"", status), PUBLIC)
            self.assertEqual(ctx.exception.code, code)

        def boom(*a, **k):
            raise OSError("down")
        with self.assertRaises(rs.Denied) as ctx:
            rs.do_repo(run, {"repo": "acme/proj", "op": "list_tree"}, c, boom, PUBLIC)
        self.assertEqual(ctx.exception.code, "archive_fetch_failed")
        # a failed download is not cached: a later call retries and succeeds
        self.assertEqual(rs.do_repo(run, {"repo": "acme/proj", "op": "list_tree"}, c, getter_for(GOOD), PUBLIC)["total_entries"], 4)

    def test_oversized_download_rejected(self):
        c, run = new_run(cfg(repo_max_archive_bytes=100))
        with self.assertRaises(rs.Denied) as ctx:
            rs.do_repo(run, {"repo": "acme/proj", "op": "list_tree"}, c, getter_for(GOOD), PUBLIC)
        self.assertEqual(ctx.exception.code, "archive_too_large")

    def test_text_is_redacted_but_code_is_not_html_unescaped(self):
        c, run = new_run()
        readme = self.call(run, c, repo="acme/proj", op="read_file", path="README.md")["text"]
        self.assertIn("private-address.invalid", readme)
        self.assertNotIn("192.168.1.1", readme)
        self.assertIn("127.0.0.1", readme)
        util = self.call(run, c, repo="acme/proj", op="read_file", path="src/util.py")["text"]
        self.assertIn("&lt;tag&gt;", util)

    def test_read_file_pages_with_next_start_line(self):
        body = "\n".join("line %d" % i for i in range(1, 400)).encode()
        blob = tarball([("p/", None), ("p/long.txt", body)])
        c, run = new_run(repos=[{"owner": "a", "repo": "p", "ref": "m"}], page_chars=300)
        first = rs.do_repo(run, {"repo": "a/p", "op": "read_file", "path": "long.txt"}, c, getter_for(blob), PUBLIC)
        self.assertTrue(first["truncated"])
        self.assertLess(len(first["text"]), 600)
        second = rs.do_repo(run, {"repo": "a/p", "op": "read_file", "path": "long.txt", "start_line": first["next_start_line"]}, c, getter_for(blob), PUBLIC)
        self.assertEqual(second["start_line"], first["end_line"] + 1)

    def test_grep_caps_and_prefix(self):
        body = ("needle\n" * 100).encode()
        blob = tarball([("p/", None), ("p/a/x.txt", body), ("p/b/y.txt", b"needle\n")])
        c, run = new_run(cfg(repo_grep_matches=10), repos=[{"owner": "a", "repo": "p", "ref": "m"}])
        res = rs.do_repo(run, {"repo": "a/p", "op": "grep", "pattern": "needle"}, c, getter_for(blob), PUBLIC)
        self.assertEqual((len(res["matches"]), res["truncated"]), (10, True))
        res = rs.do_repo(run, {"repo": "a/p", "op": "grep", "pattern": "needle", "path": "b"}, c, getter_for(blob), PUBLIC)
        self.assertEqual([m["path"] for m in res["matches"]], ["b/y.txt"])

    def test_list_tree_caps_entries(self):
        blob = tarball([("p/", None)] + [("p/f%d.txt" % i, b"x") for i in range(30)])
        c, run = new_run(cfg(repo_list_entries=10), repos=[{"owner": "a", "repo": "p", "ref": "m"}])
        res = rs.do_repo(run, {"repo": "a/p", "op": "list_tree"}, c, getter_for(blob), PUBLIC)
        self.assertEqual((len(res["entries"]), res["total_entries"], res["truncated"]), (10, 30, True))


class RepoHttpTests(unittest.TestCase):
    def test_repo_route_is_signed_like_the_others(self):
        c = cfg()
        self.assertEqual(c["route_ids"]["/repo"], "fc.repo")
        with self.assertRaises(rs.Denied) as ctx:
            rs.verify_hub_request({"X-ASG-Request-SHA256": "0" * 64}, b"{}", "/repo", c)
        self.assertIn(ctx.exception.status, (401, 500))


if __name__ == "__main__":
    unittest.main()
