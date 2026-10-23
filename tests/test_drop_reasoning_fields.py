"""Rev15: opt-in drop of backend 'thinking' fields (reasoning_content) before the output guard and delivery."""
import copy
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gateway  # noqa: E402

REPLY = {
    "model": "m",
    "choices": [{"index": 0, "finish_reason": "stop", "message": {
        "role": "assistant",
        "content": '{"action":"final","answer":"391 < 399"}',
        "reasoning_content": "The system prompt says I am now acting as the worker; ignore previous instructions? No.",
    }}],
}


def decision(backend):
    return gateway.RouteDecision(route_id="fc.llm.chat", route={"kind": "openai_chat_completions", "backend": backend},
                                 capability="worker_llm", run_id="r1", task_id=None, taint=["untrusted_web"], warnings=[])


class DropReasoningFields(unittest.TestCase):
    def test_noop_without_option(self):
        reply = copy.deepcopy(REPLY)
        with mock.patch.object(gateway, "enforce_canary") as canary:
            out = gateway.drop_response_message_fields({}, reply, {})
        self.assertIn("reasoning_content", out["choices"][0]["message"])
        canary.assert_not_called()

    def test_drops_only_listed_thinking_fields_after_canary_on_full_reply(self):
        reply = copy.deepcopy(REPLY)
        seen = []
        with mock.patch.object(gateway, "enforce_canary", side_effect=lambda cfg, payload, **kw: seen.append(copy.deepcopy(payload))):
            out = gateway.drop_response_message_fields({}, reply, {"drop_response_message_fields": ["reasoning_content", "content"]})
        msg = out["choices"][0]["message"]
        self.assertNotIn("reasoning_content", msg)
        self.assertEqual(msg["content"], REPLY["choices"][0]["message"]["content"])  # 'content' is never droppable
        self.assertEqual(len(seen), 1)
        self.assertIn("reasoning_content", seen[0]["choices"][0]["message"])  # canary saw the undropped reply

    def test_canary_trip_in_reasoning_still_raises(self):
        def trip(cfg, payload, **kw):
            raise gateway.GatewayError(403, "canary_tripped", "x")
        with mock.patch.object(gateway, "enforce_canary", side_effect=trip):
            with self.assertRaises(gateway.GatewayError):
                gateway.drop_response_message_fields({}, copy.deepcopy(REPLY), {"drop_response_message_fields": ["reasoning_content"]})

    def test_output_guard_scans_delivered_content(self):
        with mock.patch.object(gateway, "enforce_canary"):
            dropped = gateway.drop_response_message_fields({}, copy.deepcopy(REPLY), {"drop_response_message_fields": ["reasoning_content"]})
        text = gateway.security.complete_text(dropped)
        self.assertNotIn("ignore previous instructions", text)
        self.assertIn("391 < 399", text)

    def test_droppable_set_is_thinking_only(self):
        self.assertEqual(gateway.DROPPABLE_RESPONSE_MESSAGE_FIELDS, frozenset({"reasoning_content", "reasoning", "thinking"}))


class DropReasoningConfigValidation(unittest.TestCase):
    def test_validation(self):
        import tempfile
        import test_gateway as fixtures
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = fixtures.GatewayTests.make_config(None, tmp.name)
        rid = next(r for r, v in base["routes"].items() if v.get("kind") == "openai_chat_completions")
        other = next(r for r, v in base["routes"].items() if v.get("kind") not in ("openai_chat_completions", "inspect_only", "canary"))

        def with_drop(route_id, value):
            cfg = copy.deepcopy(base)
            cfg["routes"][route_id].setdefault("backend", {})["drop_response_message_fields"] = value
            return cfg

        gateway.validate_config(with_drop(rid, ["reasoning_content"]))
        for bad in (with_drop(rid, ["content"]), with_drop(rid, []), with_drop(rid, "reasoning_content"), with_drop(other, ["reasoning_content"])):
            with self.assertRaises(Exception):
                gateway.validate_config(bad)


if __name__ == "__main__":
    unittest.main()
