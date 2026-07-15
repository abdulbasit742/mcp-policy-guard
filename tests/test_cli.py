from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from mcp_policy_guard.cli import main
from mcp_policy_guard.scanner import scan_path


class CliTests(unittest.TestCase):
    def make_repo(self, files: dict[str, str]) -> Path:
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        root = Path(tmp_dir.name)
        for relative_path, content in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                textwrap.dedent(content).strip() + "\n", encoding="utf-8"
            )
        return root

    def test_json_output_contains_fingerprint(self):
        repo = self.make_repo({"server.py": "allow_origins=['*']"})
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                ["scan", str(repo), "--format", "json", "--fail-on", "critical"]
            )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["scanned_files"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "MPG002")
        self.assertRegex(
            payload["findings"][0]["fingerprint"], r"^sha256:[0-9a-f]{64}$"
        )

    def test_fail_on_threshold_uses_active_findings(self):
        repo = self.make_repo({"server.py": "subprocess.run(cmd, shell=True)"})
        stdout = StringIO()
        with redirect_stdout(stdout):
            medium_exit_code = main(["scan", str(repo), "--fail-on", "medium"])
        self.assertEqual(medium_exit_code, 1)

        stdout = StringIO()
        with redirect_stdout(stdout):
            high_exit_code = main(["scan", str(repo), "--fail-on", "high"])
        self.assertEqual(high_exit_code, 0)

    def test_sarif_output_is_version_2_1_0(self):
        repo = self.make_repo({"server.py": "allow_origins=['*']"})
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                ["scan", str(repo), "--format", "sarif", "--fail-on", "critical"]
            )
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["version"], "2.1.0")
        self.assertEqual(payload["runs"][0]["results"][0]["ruleId"], "MPG002")

    def test_policy_validation_error_returns_two(self):
        repo = self.make_repo({".mcp-policy-guard.json": "{}"})
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            exit_code = main(
                ["policy", "validate", str(repo / ".mcp-policy-guard.json")]
            )
        self.assertEqual(exit_code, 2)
        self.assertIn("Policy error", stderr.getvalue())

    def test_strict_policy_rejects_unused_suppression(self):
        repo = self.make_repo({"server.py": "allow_origins=['*']"})
        finding = scan_path(repo).findings[0]
        policy = {
            "schema_version": 1,
            "suppressions": [
                {
                    "rule_id": "MPG003",
                    "path": "server.py",
                    "fingerprint": finding.fingerprint,
                    "owner": "security-team",
                    "reason": "Reviewed test-only exception with an accountable owner",
                    "expires_on": "2099-01-01",
                }
            ],
        }
        (repo / ".mcp-policy-guard.json").write_text(
            json.dumps(policy), encoding="utf-8"
        )
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(
                ["scan", str(repo), "--strict-policy", "--fail-on", "critical"]
            )
        self.assertEqual(exit_code, 2)


if __name__ == "__main__":
    unittest.main()
