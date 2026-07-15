# Reference review

Reviewed on 2026-07-15 before shipping suppression governance and SARIF output.

## Semgrep

Adopted:

- stable rule identifiers and fingerprints for triage
- machine-readable findings suitable for CI and code review
- suppressions that remain visible to security reviewers instead of deleting evidence

Not adopted:

- Semgrep rule syntax, cloud services, language parsers, or inline ignore comments. Repository-local comments are too easy to copy broadly and do not require an accountable owner or expiry.

## Aqua Security Trivy

Adopted:

- explicit ignore-policy files rather than silently mutating scanner output
- expiry-aware exceptions
- SARIF output for security tooling interoperability
- severity thresholds independent from the output format

Not adopted:

- vulnerability databases, network updates, package scanning, Rego policies, or external runtime dependencies.

## Yelp detect-secrets

Adopted:

- baseline-style review of exact findings rather than rule-wide disablement
- stable fingerprints so harmless line movement does not invalidate an reviewed exception
- human audit metadata retained alongside suppressed findings

Not adopted:

- plugin architecture, entropy detectors, baseline migration machinery, or interactive audit commands.

## Resulting decision

MCP Policy Guard uses a small versioned JSON policy with mandatory rule, path, fingerprint, owner, reason, and expiry fields. Invalid or expired policy fails closed. Active findings alone control severity exit code 1; policy errors and stale strict-policy entries use exit code 2. JSON preserves suppressed findings for audit, while SARIF publishes active findings and aggregate suppression metadata.
