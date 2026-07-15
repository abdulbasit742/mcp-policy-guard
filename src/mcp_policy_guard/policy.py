from __future__ import annotations

import fnmatch
import json
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path, PurePosixPath
from typing import Iterable

from .models import Finding

POLICY_FILE_NAME = ".mcp-policy-guard.json"
MAX_POLICY_BYTES = 256 * 1024
MAX_SUPPRESSIONS = 500
FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RULE_ID_RE = re.compile(r"^MPG\d{3}$")
ENTRY_KEYS = {"rule_id", "path", "fingerprint", "owner", "reason", "expires_on"}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Suppression:
    rule_id: str
    path: str
    fingerprint: str
    owner: str
    reason: str
    expires_on: date

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "path": self.path,
            "fingerprint": self.fingerprint,
            "owner": self.owner,
            "reason": self.reason,
            "expires_on": self.expires_on.isoformat(),
        }


@dataclass(frozen=True)
class Policy:
    path: Path
    suppressions: tuple[Suppression, ...]


@dataclass(frozen=True)
class SuppressedFinding:
    finding: Finding
    suppression: Suppression

    def to_dict(self) -> dict[str, object]:
        return {**self.finding.to_dict(), "suppression": self.suppression.to_dict()}


@dataclass(frozen=True)
class PolicyResult:
    active: tuple[Finding, ...]
    suppressed: tuple[SuppressedFinding, ...]
    unused: tuple[Suppression, ...]


def discover_policy(target: Path) -> Path | None:
    resolved = target.expanduser().resolve()
    base = resolved if resolved.is_dir() else resolved.parent
    candidate = base / POLICY_FILE_NAME
    return candidate if candidate.is_file() else None


def _text(value: object, field: str, minimum: int, maximum: int) -> str:
    if not isinstance(value, str):
        raise PolicyError(f"{field} must be a string")
    normalized = " ".join(value.split())
    if not minimum <= len(normalized) <= maximum:
        raise PolicyError(f"{field} must be {minimum}-{maximum} characters")
    return normalized


def _path_pattern(value: object) -> str:
    pattern = _text(value, "path", 1, 240).replace("\\", "/")
    pure = PurePosixPath(pattern)
    if pure.is_absolute() or ".." in pure.parts or pattern.startswith("~"):
        raise PolicyError("path must be a repository-relative glob without traversal")
    return pattern


def load_policy(path: str | Path, *, today: date | None = None) -> Policy:
    policy_path = Path(path).expanduser().resolve()
    try:
        size = policy_path.stat().st_size
    except OSError as error:
        raise PolicyError(f"unable to read policy: {error}") from error
    if size > MAX_POLICY_BYTES:
        raise PolicyError(f"policy exceeds {MAX_POLICY_BYTES} bytes")
    try:
        raw = json.loads(policy_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError(f"invalid policy JSON: {error}") from error
    if not isinstance(raw, dict) or set(raw) - {"schema_version", "suppressions"}:
        raise PolicyError("policy must contain only schema_version and suppressions")
    if raw.get("schema_version") != 1:
        raise PolicyError("schema_version must be 1")
    entries = raw.get("suppressions")
    if not isinstance(entries, list):
        raise PolicyError("suppressions must be an array")
    if len(entries) > MAX_SUPPRESSIONS:
        raise PolicyError(f"policy contains more than {MAX_SUPPRESSIONS} suppressions")

    current = today or date.today()
    suppressions: list[Suppression] = []
    seen: set[tuple[str, str, str]] = set()
    for index, entry in enumerate(entries):
        prefix = f"suppressions[{index}]"
        if not isinstance(entry, dict) or set(entry) != ENTRY_KEYS:
            raise PolicyError(f"{prefix} must contain exactly {sorted(ENTRY_KEYS)}")
        rule_id = _text(entry["rule_id"], f"{prefix}.rule_id", 6, 6).upper()
        if not RULE_ID_RE.fullmatch(rule_id):
            raise PolicyError(f"{prefix}.rule_id is invalid")
        path_pattern = _path_pattern(entry["path"])
        fingerprint = _text(
            entry["fingerprint"], f"{prefix}.fingerprint", 71, 71
        ).lower()
        if not FINGERPRINT_RE.fullmatch(fingerprint):
            raise PolicyError(
                f"{prefix}.fingerprint must be sha256:<64 lowercase hex>"
            )
        owner = _text(entry["owner"], f"{prefix}.owner", 2, 120)
        reason = _text(entry["reason"], f"{prefix}.reason", 12, 500)
        try:
            expires_on = date.fromisoformat(
                _text(entry["expires_on"], f"{prefix}.expires_on", 10, 10)
            )
        except ValueError as error:
            raise PolicyError(f"{prefix}.expires_on must be YYYY-MM-DD") from error
        if expires_on < current:
            raise PolicyError(f"{prefix} expired on {expires_on.isoformat()}")
        key = (rule_id, path_pattern, fingerprint)
        if key in seen:
            raise PolicyError(f"{prefix} duplicates an earlier suppression")
        seen.add(key)
        suppressions.append(
            Suppression(rule_id, path_pattern, fingerprint, owner, reason, expires_on)
        )
    return Policy(path=policy_path, suppressions=tuple(suppressions))


def _matches(finding: Finding, suppression: Suppression) -> bool:
    return (
        finding.rule_id == suppression.rule_id
        and fnmatch.fnmatchcase(
            finding.file_path.replace("\\", "/"), suppression.path
        )
        and finding.fingerprint == suppression.fingerprint
    )


def apply_policy(findings: Iterable[Finding], policy: Policy) -> PolicyResult:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    used: set[Suppression] = set()
    for finding in findings:
        match = next(
            (item for item in policy.suppressions if _matches(finding, item)), None
        )
        if match is None:
            active.append(finding)
        else:
            suppressed.append(SuppressedFinding(finding=finding, suppression=match))
            used.add(match)
    unused = tuple(item for item in policy.suppressions if item not in used)
    return PolicyResult(
        active=tuple(active), suppressed=tuple(suppressed), unused=unused
    )
