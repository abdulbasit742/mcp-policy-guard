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
    ".jsx",
    ".mjs",
    ".ts",
    ".tsx",
    ".sh",
    ".ini",
    ".cfg",
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
UNPINNED_REMOTE_EXEC = re.compile(
    r"(?i)(?:^|[\s'\"\[(,=])(npx|uvx|bunx|pnpm\s+dlx|pipx\s+run)\s+[-@a-z0-9]"
)
TOOL_AUTO_APPROVAL = re.compile(
    r"(?i)(auto[_-]?approve|always[_-]?allow|auto[_-]?execute|auto[_-]?run[_-]?tools|approve[_-]?all[_-]?tools|dangerously[_-]?skip[_-]?permissions|yolo[_-]?mode)"
)
BIND_ALL_INTERFACES = re.compile(
    r"(?i)((host|hostname|bind|bind_host|address|listen)\s*[:=]\s*['\"]?(0\.0\.0\.0|::)['\"]?"
    r"|--(host|bind)[= ]\s*['\"]?0\.0\.0\.0)"
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
# A pinned invocation names an exact version, digest, or locked revision.
PINNED_VERSION = re.compile(
    r"(?i)(@\d[\w.\-]*|@sha256:[0-9a-f]{7,}|==\s*\d[\w.\-]*|--rev[= ]\s*[0-9a-f]{7,})"
)
UNPINNED_TAGS = ("@latest", "@next", "@canary", "@beta", "@dev")
DISABLED_AUTO_APPROVAL = re.compile(
    r"(?i)(auto[_-]?approve|always[_-]?allow|auto[_-]?execute|auto[_-]?run[_-]?tools)"
    r"\s*[:=]\s*(\[\s*\]|false|off|no|0|none|null)\b"
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
    {
        "rule_id": "MPG006",
        "title": "unpinned remote package execution",
        "severity": "high",
        "pattern": UNPINNED_REMOTE_EXEC,
        "message": "MCP server is launched from an unpinned remote package, so a compromised or"
        " republished release executes with the agent's privileges.",
        "recommendation": "Pin the exact version or digest (for example package@1.4.2) or vendor the server locally.",
    },
    {
        "rule_id": "MPG007",
        "title": "tool calls auto-approved",
        "severity": "high",
        "pattern": TOOL_AUTO_APPROVAL,
        "message": "Tool invocations are approved without a human in the loop, so prompt injection"
        " reaches side-effecting tools directly.",
        "recommendation": "Remove blanket auto-approval; allow only read-only tools and require confirmation for writes.",
    },
    {
        "rule_id": "MPG008",
        "title": "server bound to all network interfaces",
        "severity": "medium",
        "pattern": BIND_ALL_INTERFACES,
        "message": "Binding to 0.0.0.0 exposes a local-trust MCP server to the whole network.",
        "recommendation": "Bind to 127.0.0.1 for local use, or add authentication and TLS before exposing it.",
    },
)


def scan_path(target: str | Path) -> ScanResult:
    root = Path(target).expanduser().resolve()
    findings: list[Finding] = []
    scanned_files = 0
    for file_path in iter_text_files(root):
        scanned_files += 1
        findings.extend(scan_file(file_path, root))
    return ScanResult(
        scanned_files=scanned_files,
        findings=tuple(sort_findings(findings)),
    )


def iter_text_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        if should_scan(root):
            yield root
        return
    for file_path in root.rglob("*"):
        if file_path.is_dir() or any(
            part in SKIP_DIR_NAMES for part in file_path.parts
        ):
            continue
        if should_scan(file_path):
            yield file_path


def should_scan(file_path: Path) -> bool:
    if any(part in SKIP_DIR_NAMES for part in file_path.parts):
        return False
    if file_path.suffix.lower() not in TEXT_SUFFIXES and file_path.name != ".env":
        return False
    try:
        return file_path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
        return False


def scan_file(file_path: Path, root: Path) -> list[Finding]:
    try:
        content = file_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    relative_path = str(file_path.relative_to(root)) if root.is_dir() else file_path.name
    findings: list[Finding] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        lowered = line.lower()
        for rule in RULES:
            if not rule["pattern"].search(line):
                continue
            if rule["rule_id"] == "MPG001" and looks_like_placeholder(lowered):
                continue
            if rule["rule_id"] == "MPG006" and looks_pinned(lowered):
                continue
            if rule["rule_id"] == "MPG007" and auto_approval_is_disabled(line):
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


def looks_pinned(lowered_line: str) -> bool:
    """True when a remote execution names an exact version, digest, or revision."""
    if any(tag in lowered_line for tag in UNPINNED_TAGS):
        return False
    return bool(PINNED_VERSION.search(lowered_line))


def auto_approval_is_disabled(line: str) -> bool:
    """True when the auto-approval switch is explicitly empty, false, or none."""
    return bool(DISABLED_AUTO_APPROVAL.search(line))


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, int]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique
