# Skill Registry

<table>
<tr><th>ID</th><th>Priority</th><th>Status</th><th>Skill</th><th>Acceptance criteria</th></tr>
<tr><td>SKILL-001</td><td>High</td><td>Ready</td><td>Suppression / allowlist support</td><td>Users can suppress known-safe findings with explicit reason, rule ID, and path scope while audit mode still surfaces suppressed items.</td></tr>
<tr><td>SKILL-002</td><td>High</td><td>Ready</td><td>SARIF export</td><td>CLI emits valid SARIF 2.1.0 with stable rule metadata and GitHub code scanning ingestion docs.</td></tr>
<tr><td>SKILL-003</td><td>Medium</td><td>Ready</td><td>Transport/auth coverage expansion</td><td>Scanner detects more MCP transport patterns such as unauthenticated HTTP/SSE bridges and missing webhook verification hints with regression tests.</td></tr>
<tr><td>SKILL-004</td><td>Medium</td><td>Backlog</td><td>Rule tuning for structured config</td><td>YAML/JSON structural parsing reduces false positives without adding unsafe execution.</td></tr>
</table>

## Shipped in this run

- initial vertical slice with 5 stable rule IDs
- CLI text and JSON output
- severity-aware fail thresholds
- baseline docs, CI, and security audit trail
