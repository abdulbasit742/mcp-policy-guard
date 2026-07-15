# Security audit — 2026-07-15

## Scope

Changed-area review of finding fingerprints, repository suppression policy, CLI exit behavior, SARIF output, tests, and CI.

## Improvements

- Findings now expose deterministic SHA-256 fingerprints derived from rule ID, repository-relative path, and normalized evidence.
- Suppressions require an exact rule, path glob, and fingerprint; rule-wide silent disablement is not supported.
- Policy entries require an accountable owner, meaningful reason, and ISO expiry date.
- Invalid JSON, unknown fields, missing fields, duplicates, absolute/traversal paths, oversized policies, excessive entries, malformed fingerprints, and expired suppressions fail closed with exit code 2.
- Same-day expiry remains valid through that calendar date, avoiding premature expiration during the day.
- `--strict-policy` returns exit code 2 when suppressions no longer match, making stale exceptions visible in CI.
- JSON output retains suppressed findings and their governance metadata.
- SARIF 2.1.0 contains active findings only, stable rule metadata, fingerprints, and aggregate suppression/unused counts.
- File coverage now includes JSX/TSX/MJS, shell, INI, and CFG files while preserving the 1 MiB per-file cap.
- CI validates Python 3.10–3.13, compiles sources, runs 15 tests, validates the example policy, scans the repository, and parses generated SARIF.

## Security properties

- runtime dependencies: zero
- scan network access: none
- scan shell execution: none
- policy size cap: 256 KiB
- suppression count cap: 500
- finding threshold exit: 1
- policy/governance failure exit: 2

## Residual risk

- Detection remains heuristic; risky semantic behavior can evade textual patterns and safe code can still match them.
- A matching fingerprint proves only that the same rule/path/evidence tuple was reviewed, not that the implementation is safe.
- Path globs can be broad. Reviewers should require the narrowest practical scope and reject repository-wide wildcards.
- Policy expiry uses the executing machine's local calendar date. Teams requiring one global rollover instant should run CI in a controlled timezone or define an organizational convention.
- SARIF is generated but not uploaded automatically because this repository keeps workflow permissions at `contents: read`; consumers may upload it in a separately authorized code-scanning workflow.
- Native GitHub secret scanning and branch protection remain repository/platform controls outside this codebase.

## Next highest-value work

Expand transport/auth rules with structured JSON/YAML parsing, then add test fixtures for HTTP/SSE authentication, webhook verification, and reverse-proxy trust boundaries without executing scanned content.
