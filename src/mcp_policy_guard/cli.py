from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import Finding, severity_rank
from .policy import PolicyError, apply_policy, discover_policy, load_policy
from .sarif import build_sarif
from .scanner import RULES, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-policy-guard",
        description="Scan MCP repositories for risky auth, CORS, shell, filesystem, and secret exposure patterns.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a repository or file path")
    scan_parser.add_argument("path", nargs="?", default=".", help="Directory or file to scan")
    scan_parser.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        default="text",
        help="Output format",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="Minimum active severity that should produce exit code 1",
    )
    scan_parser.add_argument(
        "--policy",
        help="Suppression policy path; defaults to .mcp-policy-guard.json in the scan root",
    )
    scan_parser.add_argument(
        "--no-policy",
        action="store_true",
        help="Do not discover or apply a suppression policy",
    )
    scan_parser.add_argument(
        "--strict-policy",
        action="store_true",
        help="Exit 2 when configured suppressions are unused",
    )

    policy_parser = subparsers.add_parser("policy", help="Validate suppression policy")
    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command", required=True
    )
    validate_parser = policy_subparsers.add_parser(
        "validate", help="Validate a policy file"
    )
    validate_parser.add_argument(
        "path", nargs="?", default=".mcp-policy-guard.json"
    )
    return parser


def render_text(
    scanned_files: int,
    findings: list[dict[str, object]],
    suppressed: list[dict[str, object]],
    unused: list[dict[str, object]],
) -> str:
    lines = [
        f"Scanned {scanned_files} files",
        f"Found {len(findings)} active issue(s)",
        f"Suppressed {len(suppressed)} issue(s)",
    ]
    if unused:
        lines.append(f"Unused suppressions: {len(unused)}")
    if findings:
        lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"[{finding['severity']}] {finding['rule_id']} {finding['title']}",
                f"  file: {finding['file_path']}:{finding['line']}",
                f"  fingerprint: {finding['fingerprint']}",
                f"  evidence: {finding['evidence']}",
                f"  recommendation: {finding['recommendation']}",
                "",
            ]
        )
    return "\n".join(lines).rstrip()


def should_fail(findings: list[dict[str, object]], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    threshold = severity_rank(fail_on)
    return any(
        severity_rank(str(finding["severity"])) >= threshold
        for finding in findings
    )


def _policy_path(args: argparse.Namespace, target: Path) -> Path | None:
    if args.no_policy:
        return None
    return Path(args.policy).expanduser() if args.policy else discover_policy(target)


def _scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    result = scan_path(target)
    active: tuple[Finding, ...] = result.findings
    suppressed_payload: list[dict[str, object]] = []
    unused_payload: list[dict[str, object]] = []
    policy_path = _policy_path(args, target)
    if policy_path is not None:
        policy = load_policy(policy_path)
        policy_result = apply_policy(result.findings, policy)
        active = policy_result.active
        suppressed_payload = [
            item.to_dict() for item in policy_result.suppressed
        ]
        unused_payload = [item.to_dict() for item in policy_result.unused]

    findings = [finding.to_dict() for finding in active]
    payload = {
        "scanned_files": result.scanned_files,
        "findings": findings,
        "suppressed_findings": suppressed_payload,
        "policy": {
            "path": str(policy_path) if policy_path else None,
            "unused_suppressions": unused_payload,
        },
    }
    if args.format == "json":
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    elif args.format == "sarif":
        sys.stdout.write(
            json.dumps(
                build_sarif(
                    active,
                    RULES,
                    suppressed_count=len(suppressed_payload),
                    unused_count=len(unused_payload),
                ),
                indent=2,
            )
            + "\n"
        )
    else:
        sys.stdout.write(
            render_text(
                result.scanned_files,
                findings,
                suppressed_payload,
                unused_payload,
            )
            + "\n"
        )

    if args.strict_policy and unused_payload:
        return 2
    return 1 if should_fail(findings, args.fail_on) else 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "policy" and args.policy_command == "validate":
            policy = load_policy(args.path)
            sys.stdout.write(
                f"Policy valid: {policy.path} ({len(policy.suppressions)} suppression(s))\n"
            )
            return 0
        if args.command == "scan":
            return _scan(args)
        parser.error("Unsupported command")
    except PolicyError as error:
        sys.stderr.write(f"Policy error: {error}\n")
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
