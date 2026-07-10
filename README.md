# MCP Policy Guard

MCP Policy Guard scans Model Context Protocol (MCP) servers and adjacent agent repositories for risky policy defaults before they ship.

It focuses on practical repo-level risks that repeatedly show up in agent tooling:

- hardcoded secrets and tokens in code or config
- wildcard CORS / origin exposure
- explicit authentication disablement
- dangerous shell execution primitives in tool handlers
- broad filesystem root exposure

The first release is intentionally small, fast, and dependency-light so it can run in local development, CI, and pre-merge review without network access.

## Why this exists

Teams are moving quickly on MCP servers, local agents, and tool-enabled automation. In that rush, security-sensitive defaults often land before review:

- `allow_origins=["*"]`
- `auth_required: false`
- `shell=True` in a tool execution path
- `allowed_paths: ["/"]`
- copied tokens in local examples that stop being examples

MCP Policy Guard turns those patterns into actionable findings with stable rule IDs and CI-friendly exit codes.

## Features in this vertical slice

- stdlib-only Python scanner
- text and JSON output
- severity-aware exit codes via `--fail-on`
- deterministic rule IDs for triage and future suppression support
- unit tests for scanner and CLI behavior
- least-privilege GitHub Actions for test and security runs

## Install

```bash
python -m pip install -e .
```

Or run directly from the repository:

```bash
python -m mcp_policy_guard scan .
```

## Quickstart

Scan the current repository and fail CI only on high/critical findings:

```bash
python -m mcp_policy_guard scan . --fail-on high
```

Emit JSON for downstream tooling:

```bash
python -m mcp_policy_guard scan . --format json --fail-on medium
```

Scan a specific project folder:

```bash
python -m mcp_policy_guard scan ../my-mcp-server
```

## Example output

```text
Scanned 4 files
Found 2 issue(s)

[high] MPG002 wildcard network origin exposure
  file: server.py:14
  evidence: allow_origins=["*"]
  recommendation: replace wildcard origins with an explicit allowlist

[medium] MPG004 dangerous shell execution primitive
  file: tools.py:22
  evidence: subprocess.run(user_input, shell=True)
  recommendation: remove shell invocation and route through an explicit command allowlist
```

## Rules in this release

<table>
<tr><th>Rule</th><th>Severity</th><th>What it catches</th></tr>
<tr><td>MPG001</td><td>high</td><td>Hardcoded secret-like credentials in source or config</td></tr>
<tr><td>MPG002</td><td>high</td><td>Wildcard origins / permissive CORS settings</td></tr>
<tr><td>MPG003</td><td>high</td><td>Authentication explicitly disabled in config</td></tr>
<tr><td>MPG004</td><td>medium</td><td>Dangerous shell execution primitives</td></tr>
<tr><td>MPG005</td><td>medium</td><td>Broad filesystem root exposure</td></tr>
</table>

## Repository layout

```text
src/mcp_policy_guard/   Scanner and CLI
tests/                  Unit tests
.docs/                  Not used
.github/workflows/      CI and security automation
docs/                   Audit and roadmap material
```

## Validation

```bash
python -m unittest discover -s tests -v
python -m mcp_policy_guard scan . --fail-on critical
```

## Security posture

- runtime dependencies: 0
- network calls during scan: 0
- default exit threshold: `high`
- native GitHub secret scanning may still require repository-level enablement outside this codebase

See [SECURITY.md](SECURITY.md) and [docs/security-audit.md](docs/security-audit.md).

## Roadmap

See [docs/SKILL_REGISTRY.md](docs/SKILL_REGISTRY.md) for prioritized skills.

## License

MIT
