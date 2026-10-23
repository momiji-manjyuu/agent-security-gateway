"""Rev11: audit records which model served an openai_chat_completions route (no content, no secrets)."""
import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway  # noqa: E402


def decision(kind, backend):
    return gateway.RouteDecision(route_id="fc.llm.chat", route={"kind": kind, "backend": backend},
                                 capability="worker_llm", run_id="r1", task_id=None, taint=["untrusted_web"], warnings=[])


class BackendModelAudit(unittest.TestCase):
    def test_openai_route_records_models_and_usage(self):
        f = gateway.backend_model_audit_fields(
            decision("openai_chat_completions", {"model_rewrite": "main", "api_key_env": "X"}),
            {"model": "GLM-5.3-Flash-EXL3", "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15, "x": "y"},
             "choices": [{"message": {"content": "secret-ish content"}}]})
        self.assertEqual(f["backend_model"], "main")
        self.assertEqual(f["upstream_model"], "GLM-5.3-Flash-EXL3")
        self.assertEqual(f["upstream_usage"], {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15})
        self.assertNotIn("content", repr(f))
        self.assertNotIn("X", f.values())

    def test_non_openai_route_adds_nothing(self):
        self.assertEqual(gateway.backend_model_audit_fields(decision("http_json", {}), {"model": "m"}), {})

    def test_hostile_model_string_is_bounded(self):
        f = gateway.backend_model_audit_fields(decision("openai_chat_completions", {"model": "m"}),
                                                {"model": "a\n\x00" + "b" * 500})
        self.assertLessEqual(len(f["upstream_model"]), 96)
        self.assertNotIn("\n", f["upstream_model"])


if __name__ == "__main__":
    unittest.main()
