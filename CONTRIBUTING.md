# Contributing

Thanks for improving MCP Policy Guard.

## Local setup

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Validation before opening a PR

```bash
python -m unittest discover -s tests -v
python -m mcp_policy_guard scan . --fail-on critical
```

## Contribution rules

- keep runtime dependencies at zero unless a change materially improves accuracy
- add or update tests for every new rule and regression fix
- prefer deterministic, auditable heuristics over opaque scoring
- do not commit credentials, tokens, or real customer data
- keep GitHub workflows least-privilege by default

## Pull request checklist

1. Describe the security or product problem clearly.
2. Link the rule IDs or skill IDs affected.
3. Include validation evidence.
4. Update `docs/security-audit.md` if the change affects risk posture.
5. Update `docs/SKILL_REGISTRY.md` when shipping or adding a skill.
