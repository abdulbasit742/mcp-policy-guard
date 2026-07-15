# AGENTS.md

## Scope

These instructions apply to the entire `abdulbasit742/mcp-policy-guard` repository.

Project: **MCP Policy Guard**, a stdlib-only Python scanner with governed suppressions and SARIF output.

## Architecture

- `src/mcp_policy_guard/scanner.py`: read-only text scanning and stable rules
- `src/mcp_policy_guard/models.py`: finding model, severity ordering, fingerprints
- `src/mcp_policy_guard/policy.py`: strict suppression schema and matching
- `src/mcp_policy_guard/sarif.py`: SARIF 2.1.0 serialization
- `src/mcp_policy_guard/cli.py`: commands, output formats, and exit codes
- `tests/`: scanner, policy, CLI, and SARIF regression coverage

## Working method

1. Read `README.md`, `docs/security-audit.md`, nearby tests, and the relevant module before editing.
2. Keep runtime dependencies at zero unless a separately reviewed accuracy requirement clearly justifies one.
3. Never execute, import, or make network requests based on scanned repository content.
4. Keep rule IDs stable. Update rule metadata, tests, README, and SARIF behavior together when adding or changing a rule.
5. Treat policy parsing as an untrusted-input boundary: preserve size/count caps, exact fields, path safety, expiry, and duplicate rejection.
6. Do not weaken suppression matching from exact rule + path + fingerprint or remove owner/reason/expiry requirements.
7. Preserve exit semantics: `0` success/below threshold, `1` active finding threshold, `2` policy/governance failure.

## Verification

```bash
python -m pip install -e .
python -m compileall -q src tests
python -m unittest discover -s tests -v
python -m mcp_policy_guard policy validate .mcp-policy-guard.example.json
python -m mcp_policy_guard scan . --fail-on critical
python -m mcp_policy_guard scan . --format sarif --fail-on critical > report.sarif
```

## Security requirements

- Never commit real credentials or suppression evidence containing private data.
- Suppressions must be narrow, accountable, time-bounded, and visible in JSON audit output.
- Active findings only appear as SARIF results; suppression counts must remain visible in run metadata.
- Never add inline ignore comments or rule-wide disable switches that bypass repository policy review.
- Do not silently skip malformed policy, expired entries, stale strict-policy entries, or unknown fields.

## Completion checklist

- Relevant tests, compile, policy validation, scanner smoke test, and SARIF parsing pass.
- Documentation and skill registry reflect changed public behavior.
- No network, mutation, shell execution, or new runtime dependency was introduced.
- Residual heuristic and suppression risks remain documented.
