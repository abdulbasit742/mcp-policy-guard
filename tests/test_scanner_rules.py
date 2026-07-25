"""Regression tests for the MCP-specific rules MPG006-MPG008."""
from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from mcp_policy_guard.scanner import RULES, scan_path


class McpRuleTests(unittest.TestCase):
    def scan_repo(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for relative_path, content in files.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    textwrap.dedent(content).strip() + "\n", encoding="utf-8"
                )
            return scan_path(root)

    def rule_ids(self, result) -> set[str]:
        return {finding.rule_id for finding in result.findings}

    def test_rule_ids_are_unique_and_sequential(self):
        ids = [rule["rule_id"] for rule in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids))
        for rule in RULES:
            self.assertIn(rule["severity"], {"low", "medium", "high", "critical"})
            self.assertTrue(rule["recommendation"].strip())

    def test_flags_unpinned_remote_server_launch(self):
        result = self.scan_repo(
            {
                "mcp.json": """
                {"command": "npx", "args": ["-y", "some-mcp-server@latest"]}
                """
            }
        )
        self.assertIn("MPG006", self.rule_ids(result))

    def test_flags_unpinned_uvx_invocation(self):
        result = self.scan_repo({"run.sh": "uvx some-mcp-server"})
        self.assertIn("MPG006", self.rule_ids(result))

    def test_pinned_version_or_digest_is_accepted(self):
        pinned = self.scan_repo({"mcp.json": '{"args": ["npx some-mcp-server@1.4.2"]}'})
        self.assertNotIn("MPG006", self.rule_ids(pinned))
        digest = self.scan_repo(
            {"run.sh": "uvx server@sha256:0123456789abcdef"}
        )
        self.assertNotIn("MPG006", self.rule_ids(digest))

    def test_flags_tool_auto_approval(self):
        result = self.scan_repo(
            {"settings.json": '{"autoApprove": ["write_file", "run_command"]}'}
        )
        self.assertIn("MPG007", self.rule_ids(result))

    def test_empty_or_false_auto_approval_is_not_flagged(self):
        empty = self.scan_repo({"settings.json": '{"autoApprove": []}'})
        self.assertNotIn("MPG007", self.rule_ids(empty))
        disabled = self.scan_repo({"settings.yaml": "always_allow: false"})
        self.assertNotIn("MPG007", self.rule_ids(disabled))

    def test_flags_bind_all_interfaces(self):
        result = self.scan_repo(
            {
                "server.py": """
                host = "0.0.0.0"
                """,
                "start.sh": "python -m server --host 0.0.0.0",
            }
        )
        self.assertIn("MPG008", self.rule_ids(result))
        self.assertEqual(
            len([f for f in result.findings if f.rule_id == "MPG008"]), 2
        )

    def test_loopback_binding_is_not_flagged(self):
        result = self.scan_repo({"server.py": 'host = "127.0.0.1"'})
        self.assertNotIn("MPG008", self.rule_ids(result))


if __name__ == "__main__":
    unittest.main()
