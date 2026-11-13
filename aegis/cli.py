"""Command-line interface for AEGIS untrusted document (.txt, .docx, .pdf) scanning & sanitization."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import ScanReport, sanitize_file, scan_file


def _collect_targets(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    return sorted(
        p for p in target.rglob("*")
        if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts
    )


def _print_human(reports: list[ScanReport]) -> None:
    for r in reports:
        badge = {
            "CLEAN": "[OK]",
            "FLAGGED": "[WARN]",
            "QUARANTINE": "[BLOCK]",
        }[r.verdict]
        print(f"{badge} {r.source}  (risk={r.risk_score:.2f}, sha256={r.sha256[:12]}...)")
        for f in r.findings:
            print(
                f"    -> {f.rule_id} [{f.severity.value}] line {f.line}: "
                f"{f.description} ({f.snippet})"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS — Untrusted Document (.docx, .pdf, .txt) & Prompt-Injection Scanner",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan a file or directory for prompt-injection & stealth text vectors")
    scan_p.add_argument("path", type=Path, help="Target file or directory path (.txt, .md, .docx, .pdf)")
    scan_p.add_argument("--json", action="store_true", help="Emit structured JSON report")
    scan_p.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code on any finding (including FLAGGED)",
    )

    san_p = sub.add_parser("sanitize", help="Extract text from file (.txt, .docx, .pdf) and strip stealth Unicode")
    san_p.add_argument("path", type=Path, help="Target file path")
    san_p.add_argument("-o", "--output", type=Path, default=None, help="Optional output file path")

    args = parser.parse_args(argv)

    if args.cmd == "sanitize":
        cleaned = sanitize_file(args.path)
        if args.output:
            args.output.write_text(cleaned, encoding="utf-8")
        else:
            sys.stdout.write(cleaned)
            if not cleaned.endswith("\n"):
                sys.stdout.write("\n")
        return 0

    targets = _collect_targets(args.path)
    reports = [scan_file(t) for t in targets]

    if args.json:
        print(json.dumps([r.to_dict() for r in reports], indent=2))
    else:
        _print_human(reports)

    if any(r.verdict == "QUARANTINE" for r in reports):
        return 2
    if args.strict and any(r.verdict != "CLEAN" for r in reports):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
