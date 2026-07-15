from __future__ import annotations

import json
import tempfile
import unittest
from datetime import date
from pathlib import Path

from mcp_policy_guard.policy import PolicyError, apply_policy, load_policy
from mcp_policy_guard.scanner import scan_path


class PolicyTests(unittest.TestCase):
    def fixture(self):
        tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(tmp_dir.cleanup)
        root = Path(tmp_dir.name)
        (root / "server.py").write_text(
            "allow_origins=['*']\n", encoding="utf-8"
        )
        finding = scan_path(root).findings[0]
        return root, finding

    def write_policy(self, root, finding, **overrides):
        entry = {
            "rule_id": finding.rule_id,
            "path": "server.py",
            "fingerprint": finding.fingerprint,
            "owner": "security-team",
            "reason": "Known local-only fixture reviewed by the security owner",
            "expires_on": "2026-08-15",
        }
        entry.update(overrides)
        path = root / ".mcp-policy-guard.json"
        path.write_text(
            json.dumps({"schema_version": 1, "suppressions": [entry]}),
            encoding="utf-8",
        )
        return path

    def test_valid_fingerprint_suppresses_finding(self):
        root, finding = self.fixture()
        policy = load_policy(
            self.write_policy(root, finding), today=date(2026, 7, 15)
        )
        result = apply_policy((finding,), policy)
        self.assertEqual(result.active, ())
        self.assertEqual(len(result.suppressed), 1)
        self.assertEqual(result.unused, ())

    def test_fingerprint_mismatch_remains_active(self):
        root, finding = self.fixture()
        policy = load_policy(
            self.write_policy(root, finding, fingerprint="sha256:" + "0" * 64),
            today=date(2026, 7, 15),
        )
        result = apply_policy((finding,), policy)
        self.assertEqual(result.active, (finding,))
        self.assertEqual(len(result.unused), 1)

    def test_expired_suppression_fails_closed(self):
        root, finding = self.fixture()
        path = self.write_policy(root, finding, expires_on="2026-07-14")
        with self.assertRaisesRegex(PolicyError, "expired"):
            load_policy(path, today=date(2026, 7, 15))

    def test_same_day_expiry_is_valid(self):
        root, finding = self.fixture()
        load_policy(
            self.write_policy(root, finding, expires_on="2026-07-15"),
            today=date(2026, 7, 15),
        )

    def test_rejects_path_traversal(self):
        root, finding = self.fixture()
        path = self.write_policy(root, finding, path="../server.py")
        with self.assertRaisesRegex(PolicyError, "traversal"):
            load_policy(path, today=date(2026, 7, 15))

    def test_rejects_unknown_fields(self):
        root, finding = self.fixture()
        path = self.write_policy(root, finding)
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw["suppressions"][0]["ticket"] = "SEC-1"
        path.write_text(json.dumps(raw), encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "exactly"):
            load_policy(path, today=date(2026, 7, 15))


if __name__ == "__main__":
    unittest.main()
