from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .models import severity_rank
from .scanner import scan_path


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
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    scan_parser.add_argument(
        "--fail-on",
        choices=("none", "low", "medium", "high", "critical"),
        default="high",
        help="Minimum severity that should produce a non-zero exit code",
    )
    return parser


def render_text(scanned_files: int, findings: list[dict[str, object]]) -> str:
    lines = [f"Scanned {scanned_files} files", f"Found {len(findings)} issue(s)"]
    if findings:
        lines.append("")
    for finding in findings:
        lines.extend(
            [
                f"[{finding['severity']}] {finding['rule_id']} {finding['title']}",
                f"  file: {finding['file_path']}:{finding['line']}",
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
    return any(severity_rank(str(finding["severity"])) >= threshold for finding in findings)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.error("Unsupported command")

    target = Path(args.path)
    result = scan_path(target)
    payload = result.to_dict()
    findings = payload["findings"]

    if args.format == "json":
        sys.stdout.write(json.dumps(payload, indent=2))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_text(result.scanned_files, findings))
        sys.stdout.write("\n")

    return 1 if should_fail(findings, args.fail_on) else 0


if __name__ == "__main__":
    raise SystemExit(main())
