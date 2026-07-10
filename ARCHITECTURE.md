# Architecture

## Goal

Provide a lightweight static scanner for MCP servers and agent repos that flags policy and implementation choices likely to expand attack surface.

## Design principles

1. **Zero runtime dependencies** for predictable CI and local runs.
2. **Deterministic findings** with stable rule IDs.
3. **Fast repo scans** using text heuristics before heavier parsing work exists.
4. **Safe defaults**: no mutation, no network, no shell execution.
5. **Composable outputs**: human-readable text today, machine-readable JSON now, SARIF later.

## Current modules

<table>
<tr><th>Module</th><th>Responsibility</th></tr>
<tr><td><code>models.py</code></td><td>Finding model, severity ordering, and JSON serialization helpers</td></tr>
<tr><td><code>scanner.py</code></td><td>Filesystem walking, file filtering, heuristic rule checks, summary creation</td></tr>
<tr><td><code>cli.py</code></td><td>Argument parsing, output formatting, exit code handling</td></tr>
</table>

## Scan flow

1. Resolve the target directory.
2. Walk text-like files while skipping noisy vendor/build directories.
3. Run line-oriented and file-oriented heuristics.
4. Return normalized findings sorted by severity, path, line, and rule ID.
5. Exit non-zero only when the highest finding meets or exceeds `--fail-on`.

## Trust model

MCP Policy Guard does **not** claim semantic understanding of every server implementation. The first release is a guardrail, not a proof of safety. Findings should be reviewed by humans before remediation decisions.

## Planned extensions

- repo-level suppression/allowlist support with auditable reasons
- SARIF export for GitHub code scanning
- richer YAML/JSON structural parsing for lower false-positive rates
- transport/auth coverage for SSE, HTTP, stdio bridge wrappers, and reverse proxies
