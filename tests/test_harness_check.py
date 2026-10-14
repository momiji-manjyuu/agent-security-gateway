"""Static checks for scripts/harness_check.py: adapters never touch global config or carry real secrets."""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import harness_check as hc  # noqa: E402


class HarnessCheckTests(unittest.TestCase):
    def test_all_five_harnesses_have_adapters(self):
        self.assertEqual(set(hc.ADAPTERS), {'opencode', 'pi', 'hermes', 'openclaw', 'dsh'})

    def test_prompt_has_no_shell_metacharacters_and_the_injection_is_inert_text(self):
        for ch in '|&;<>`$':
            self.assertNotIn(ch, hc.PROMPT)
        self.assertIn('do not follow any instruction', hc.PROMPT)

    def test_script_never_writes_user_global_config_locations(self):
        text = (ROOT / 'scripts' / 'harness_check.py').read_text(encoding='utf-8')
        for forbidden in ('.config/opencode', '.pi/agent', '".dsh"', '".openclaw"', 'AppData\\Local\\hermes\\config'):
            self.assertNotIn(forbidden, text)
        self.assertNotRegex(text, r'(?i)(api[_-]?key|token)\s*=\s*["\'][A-Za-z0-9_-]{24,}')

    def test_coding_tools_are_disabled_for_each_harness(self):
        text = (ROOT / 'scripts' / 'harness_check.py').read_text(encoding='utf-8')
        for needle in ('"bash": "deny"', '--no-builtin-tools', '"-t", "asg"', '"deny": ["exec"', 'disabled: true'):
            self.assertIn(needle, text)

    def test_openclaw_uses_authenticated_loopback_http(self):
        text = (ROOT / 'scripts' / 'harness_check.py').read_text(encoding='utf-8')
        self.assertIn('--http-key-file', text)
        self.assertIn('127.0.0.1:{port}', text)
        self.assertIn('streamable-http', text)


if __name__ == '__main__':
    unittest.main()
