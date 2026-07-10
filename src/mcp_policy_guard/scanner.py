from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable

from .models import Finding, ScanResult, sort_findings

TEXT_SUFFIXES = {
    ".env",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
    ".js",
    ".ts",
}
SKIP_DIR_NAMES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
MAX_FILE_BYTES = 1024 * 1024

SECRET_ASSIGNMENT = re.compile(
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"][^'\"]{12,}['\"]"
)
WILDCARD_ORIGIN = re.compile(
    r"(?i)(allow_origins|cors|access-control-allow-origin|allowed_origins).{0,40}(\*|\[\s*['\"]\*['\"]\s*\])"
)
AUTH_DISABLED = re.compile(
    r"(?i)(auth_required|authentication|required_auth|auth_enabled).{0,20}(false|none|off|disabled)"
)
DANGEROUS_SHELL = re.compile(
    r"(?i)(shell\s*=\s*true|os\.system\(|subprocess\.(run|popen|call)\(|execSync\(|child_process\.exec\(|spawn\(.{0,80}shell\s*:\s*true)"
)
FILESYSTEM_ROOT = re.compile(
    r"(?i)(allowed_paths|filesystem_roots|mounts|roots|sandbox_root).{0,60}['\"]/(?:['\"]|\s*[\],}])"
)
PLACEHOLDER_HINTS = (
    "your_api_key",
    "example",
    "changeme",
    "placeholder",
    "replace_me",
    "dummy",
    "sample",
)


RULES = (
    {
        "rule_id": "MPG001",
        "title": "hardcoded secret-like credential",
        "severity": "high",
        "pattern": SECRET_ASSIGNMENT,
        "message": "Potential hardcoded credential found in tracked content.",
        "recommendation": "Move secrets to environment or secret managers and commit only placeholders.",
    },
    {
        "rule_id": "MPG002",
        "title": "wildcard network origin exposure",
        "severity": "high",
        "pattern": WILDCARD_ORIGIN,
        "message": "Wildcard origin or permissive CORS rule expands remote attack surface.",
        "recommendation": "Replace wildcard origins with an explicit allowlist.",
    },
    {
        "rule_id": "MPG003",
        "title": "authentication explicitly disabled",
        "severity": "high",
        "pattern": AUTH_DISABLED,
        "message": "Authentication appears disabled in a configuration or code path.",
        "recommendation": "Require an authenticated transport or document an explicit safe local-only boundary.",
    },
    {
        "rule_id": "MPG004",
        "title": "dangerous shell execution primitive",
        "severity": "medium",
        "pattern": DANGEROUS_SHELL,
        "message": "Shell execution in tool paths increases command-injection risk.",
        "recommendation": "Replace shell invocation with explicit command allowlists and argument arrays.",
    },
    {
        "rule_id": "MPG005",
        "title": "broad filesystem root exposure",
        "severity": "medium",
        "pattern": FILESYSTEM_ROOT,
        "message": "Filesystem exposure includes the host root directory.",
        "recommendation": "Restrict filesystem access to explicit project-scoped paths.",
    },
)


def scan_path(target: str | Path) -> ScanResult:
    root = Path(target).expanduser().resolve()
    findings: list[Finding] = []
    scanned_files = 0

    for file_path in iter_text_files(root):
        scanned_files += 1
        findings.extend(scan_file(file_path, root))

    return ScanResult(scanned_files=scanned_files, findings=tuple(sort_findings(findings)))


def iter_text_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if should_scan(root):
            yield root
        return

    for file_path in root.rglob("*"):
        if file_path.is_dir():
            continue
        if any(part in SKIP_DIR_NAMES for part in file_path.parts):
            continue
        if should_scan(file_path):
            yield file_path


def should_scan(file_path: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in file_path.parts):
        return False
    if file_path.suffix.lower() not in TEXT_SUFFIXES and file_path.name != ".env":
        return False
    try:
        if file_path.stat().st_size > MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return True


def scan_file(file_path: Path, root: Path) -> list[Finding]:
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    findings: list[Finding] = []
    relative_path = str(file_path.relative_to(root)) if root.is_dir() else file_path.name

    for line_number, line in enumerate(content.splitlines(), start=1):
        lowered = line.lower()
        for rule in RULES:
            if not rule["pattern"].search(line):
                continue
            if rule["rule_id"] == "MPG001" and looks_like_placeholder(lowered):
                continue
            findings.append(
                Finding(
                    rule_id=rule["rule_id"],
                    title=rule["title"],
                    severity=rule["severity"],
                    file_path=relative_path,
                    line=line_number,
                    message=rule["message"],
                    evidence=line.strip(),
                    recommendation=rule["recommendation"],
                )
            )

    return deduplicate_findings(findings)


def looks_like_placeholder(lowered_line: str) -> bool:
    return any(hint in lowered_line for hint in PLACEHOLDER_HINTS)


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
