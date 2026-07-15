# MCP Policy Guard

MCP Policy Guard is a dependency-free Python scanner for risky Model Context Protocol (MCP) server and agent-repository defaults.

It detects practical trust-boundary mistakes before they ship:

- hardcoded secret-like credentials
- wildcard CORS or origin exposure
- authentication explicitly disabled
- dangerous shell execution primitives
- broad filesystem-root exposure

Version 0.2 adds auditable, expiring suppressions and SARIF 2.1.0 output without adding runtime dependencies or network access.

## Safety model

- scans are read-only and offline
- findings have stable rule IDs and SHA-256 fingerprints
- suppressions require an exact rule, repository-relative path glob, and finding fingerprint
- every suppression requires an owner, meaningful reason, and expiry date
- expired, malformed, duplicate, oversized, or traversal-bearing policies fail closed with exit code 2
- optional strict mode rejects stale/unused suppressions
- JSON retains suppressed findings for audit visibility
- SARIF publishes active findings only and records suppressed/unused counts

The scanner is a deterministic heuristic guardrail, not proof that an MCP server is safe.

## Install

```bash
python -m pip install -e .
```

Or run from the repository:

```bash
PYTHONPATH=src python -m mcp_policy_guard scan .
```

Python 3.10 or newer is supported.

## Scan

```bash
# Human-readable output; fail on active high/critical findings
python -m mcp_policy_guard scan . --fail-on high

# Machine-readable audit output
python -m mcp_policy_guard scan . --format json --fail-on medium

# SARIF 2.1.0 for code-scanning pipelines
python -m mcp_policy_guard scan . --format sarif --fail-on high > report.sarif
```

Each active finding includes a fingerprint suitable for a narrowly scoped suppression.

## Suppression policy

By default, a scan of a directory discovers `.mcp-policy-guard.json` in that directory. Use `--policy PATH` to select another file or `--no-policy` to disable discovery.

```json
{
  "schema_version": 1,
  "suppressions": [
    {
      "rule_id": "MPG002",
      "path": "tests/fixtures/local_server.py",
      "fingerprint": "sha256:<64 lowercase hex characters>",
      "owner": "security-team",
      "reason": "Reviewed local-only fixture with no network exposure",
      "expires_on": "2026-08-15"
    }
  ]
}
```

Copy `.mcp-policy-guard.example.json` as a structural starting point, then replace its example fingerprint and expiry. Never suppress only by rule ID or broad repository path.

Validate policy independently:

```bash
python -m mcp_policy_guard policy validate .mcp-policy-guard.json
```

Reject stale suppressions in CI:

```bash
python -m mcp_policy_guard scan . \
  --policy .mcp-policy-guard.json \
  --strict-policy \
  --fail-on high
```

A suppression remains valid through its `expires_on` calendar date. It is invalid the following day.

## Exit codes

- `0`: scan/policy validation completed and active findings stayed below the requested threshold
- `1`: at least one active finding met `--fail-on`
- `2`: policy validation failed or strict mode found unused suppressions

Only active findings influence exit code 1. Suppressed findings remain visible in JSON under `suppressed_findings`.

## Rules

| Rule | Severity | Detects |
|---|---:|---|
| `MPG001` | high | hardcoded secret-like credentials |
| `MPG002` | high | wildcard origins or permissive CORS |
| `MPG003` | high | authentication explicitly disabled |
| `MPG004` | medium | dangerous shell execution primitives |
| `MPG005` | medium | broad filesystem-root exposure |

## Example text output

```text
Scanned 4 files
Found 1 active issue(s)
Suppressed 1 issue(s)

[high] MPG002 wildcard network origin exposure
  file: server.py:14
  fingerprint: sha256:...
  evidence: allow_origins=["*"]
  recommendation: Replace wildcard origins with an explicit allowlist.
```

## Validation

```bash
python -m compileall -q src tests
python -m unittest discover -s tests -v
python -m mcp_policy_guard policy validate .mcp-policy-guard.example.json
python -m mcp_policy_guard scan . --fail-on critical
python -m mcp_policy_guard scan . --format sarif --fail-on critical > report.sarif
```

The current suite contains 15 regression tests covering scanner behavior, stable fingerprints, policy validation, expiry boundaries, exact-match suppression, stale entries, CLI exit codes, and SARIF serialization. CI runs on Python 3.10–3.13 with read-only repository permissions.

## Design references

The implementation reviewed Semgrep, Trivy, and Yelp detect-secrets for baseline/suppression and machine-readable reporting patterns. See [docs/reference-review.md](docs/reference-review.md).

## Security posture and limitations

- runtime dependencies: 0
- network calls during scans: 0
- shell execution during scans: 0
- maximum scanned file size: 1 MiB
- maximum policy size: 256 KiB
- maximum suppressions: 500

Heuristic rules can produce false positives and false negatives. A fingerprint proves only that the same rule/path/evidence tuple was reviewed; it does not prove the code is safe. Review owners must remove suppressions after remediation and reassess them before expiry.

See [SECURITY.md](SECURITY.md), [docs/security-audit.md](docs/security-audit.md), and [docs/SKILL_REGISTRY.md](docs/SKILL_REGISTRY.md).

## License

MIT
