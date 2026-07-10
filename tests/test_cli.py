from __future__ import annotations

import json
import tempfile
import textwrap
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from mcp_policy_guard.cli import main


class CliTests(unittest.TestCase):
    def make_repo(self, files: dict[str, str]) -> str:
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        root = Path(tmp_dir.name)
        for relative_path, content in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
        return tmp_dir.name

    def test_json_output_contains_findings(self):
        repo = self.make_repo({"server.py": "allow_origins=['*']"})
        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["scan", repo, "--format", "json", "--fail-on", "critical"])
        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["scanned_files"], 1)
        self.assertEqual(payload["findings"][0]["rule_id"], "MPG002")

    def test_fail_on_threshold_controls_exit_code(self):
        repo = self.make_repo({"server.py": "subprocess.run(cmd, shell=True)"})
        stdout = StringIO()
        with redirect_stdout(stdout):
            medium_exit_code = main(["scan", repo, "--fail-on", "medium"])
        self.assertEqual(medium_exit_code, 1)

        stdout = StringIO()
        with redirect_stdout(stdout):
            high_exit_code = main(["scan", repo, "--fail-on", "high"])
        self.assertEqual(high_exit_code, 0)


if __name__ == "__main__":
    unittest.main()
