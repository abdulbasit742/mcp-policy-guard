# Skill Registry

<table>
<tr><th>ID</th><th>Priority</th><th>Status</th><th>Skill</th><th>Acceptance criteria</th></tr>
<tr><td>SKILL-001</td><td>High</td><td>Shipped</td><td>Suppression / allowlist support</td><td>Known-safe findings require exact fingerprint, rule, and path matching plus owner, reason, and expiry; JSON audit mode retains suppressed findings.</td></tr>
<tr><td>SKILL-002</td><td>High</td><td>Shipped</td><td>SARIF export</td><td>CLI emits valid SARIF 2.1.0 with stable rule metadata, locations, fingerprints, and active findings.</td></tr>
<tr><td>SKILL-003</td><td>Medium</td><td>Ready</td><td>Transport/auth coverage expansion</td><td>Scanner detects more MCP transport patterns such as unauthenticated HTTP/SSE bridges and missing webhook verification hints with regression tests.</td></tr>
<tr><td>SKILL-004</td><td>Medium</td><td>Backlog</td><td>Rule tuning for structured config</td><td>JSON/YAML structural parsing reduces false positives without executing scanned content or adding unsafe dependencies.</td></tr>
</table>

## Shipped capabilities

- five stable policy rule IDs
- text, JSON, and SARIF 2.1.0 output
- severity-aware fail thresholds
- stable finding fingerprints
- versioned repository policy with owner/reason/expiry governance
- fail-closed expired and malformed policy behavior
- strict stale-suppression enforcement
- 15-test regression suite and Python 3.10–3.13 CI
