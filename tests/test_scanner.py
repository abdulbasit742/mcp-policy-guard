from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from mcp_policy_guard.scanner import scan_path


class ScannerTests(unittest.TestCase):
    def scan_repo(self, files: dict[str, str]):
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            for relative_path, content in files.items():
                path = root / relative_path
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(textwrap.dedent(content).strip() + "\n", encoding="utf-8")
            return scan_path(root)

    def test_detects_high_and_medium_risks(self):
        result = self.scan_repo(
            {
                "server.py": """
                API_TOKEN = \"sk_live_12345678901234567890\"
                allow_origins=[\"*\"]
                subprocess.run(user_input, shell=True)
                """,
                "config.yaml": """
                auth_required: false
                allowed_paths: [\"/\"]
                """,
            }
        )

        self.assertEqual(result.scanned_files, 2)
        rule_ids = {finding.rule_id for finding in result.findings}
        self.assertEqual(rule_ids, {"MPG001", "MPG002", "MPG003", "MPG004", "MPG005"})

    def test_ignores_placeholder_secret_values(self):
        result = self.scan_repo(
            {
                ".env": """
                API_KEY=\"YOUR_API_KEY\"
                """
            }
        )
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(result.findings, ())

    def test_skips_vendor_directories(self):
        result = self.scan_repo(
            {
                "node_modules/example.js": "allow_origins=['*']",
                "src/server.py": "auth_required = false",
            }
        )
        self.assertEqual(result.scanned_files, 1)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].rule_id, "MPG003")


if __name__ == "__main__":
    unittest.main()
