from __future__ import annotations

from .models import Finding

SARIF_LEVEL = {
    "info": "note",
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}


def build_sarif(
    findings: tuple[Finding, ...],
    rules: tuple[dict[str, object], ...],
    *,
    suppressed_count: int = 0,
    unused_count: int = 0,
) -> dict[str, object]:
    rule_index = {str(rule["rule_id"]): index for index, rule in enumerate(rules)}
    driver_rules = [
        {
            "id": rule["rule_id"],
            "name": str(rule["title"]).replace(" ", "-"),
            "shortDescription": {"text": rule["title"]},
            "fullDescription": {"text": rule["message"]},
            "help": {"text": rule["recommendation"]},
            "defaultConfiguration": {
                "level": SARIF_LEVEL[str(rule["severity"])]
            },
            "properties": {
                "security-severity": str(
                    {
                        "medium": 5.0,
                        "high": 8.0,
                        "critical": 9.5,
                    }.get(str(rule["severity"]), 2.0)
                )
            },
        }
        for rule in rules
    ]
    results = [
        {
            "ruleId": finding.rule_id,
            "ruleIndex": rule_index[finding.rule_id],
            "level": SARIF_LEVEL[finding.severity],
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": finding.line},
                    }
                }
            ],
            "partialFingerprints": {
                "primaryLocationLineHash": finding.fingerprint
            },
            "properties": {
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
            },
        }
        for finding in findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Policy Guard",
                        "informationUri": "https://github.com/abdulbasit742/mcp-policy-guard",
                        "rules": driver_rules,
                    }
                },
                "originalUriBaseIds": {"%SRCROOT%": {"uri": "file:///"}},
                "results": results,
                "properties": {
                    "suppressedFindings": suppressed_count,
                    "unusedSuppressions": unused_count,
                },
            }
        ],
    }
