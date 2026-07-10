from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

SEVERITY_ORDER = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    file_path: str
    line: int
    message: str
    evidence: str
    recommendation: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ScanResult:
    scanned_files: int
    findings: tuple[Finding, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "scanned_files": self.scanned_files,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def severity_rank(severity: str) -> int:
    normalized = severity.lower()
    if normalized not in SEVERITY_ORDER:
        raise ValueError(f"Unknown severity: {severity}")
    return SEVERITY_ORDER[normalized]


def sort_findings(findings: Iterable[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            -severity_rank(finding.severity),
            finding.file_path,
            finding.line,
            finding.rule_id,
        ),
    )
