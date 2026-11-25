"""warden command line: scan Terraform, print findings, fail CI on a severity."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, report
from .findings import SEVERITIES, at_least
from .scanner import all_rules, scan

FORMATS = {"text": None, "json": report.as_json, "sarif": report.sarif,
           "markdown": report.markdown, "mermaid": report.mermaid}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="warden", description="Terraform misconfiguration and IAM privilege-escalation scanner")
    ap.add_argument("--version", action="version", version=f"warden {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a Terraform directory or file")
    s.add_argument("path", help="Terraform directory, .tf file, or `terraform show -json` output")
    s.add_argument("-f", "--format", choices=FORMATS, default="text")
    s.add_argument("-o", "--output", help="write to this file instead of stdout")
    s.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit 1 if any finding is at or above this severity (default: high)")
    s.add_argument("--min-severity", choices=SEVERITIES, default="low", help="hide findings below this")
    s.add_argument("--no-color", action="store_true")

    sub.add_parser("rules", help="list every rule")
    args = ap.parse_args(argv)

    if args.cmd == "rules":
        for r in all_rules():
            print(f"{r.id:<16} {r.severity:<9} {r.title}")
        return 0

    if not Path(args.path).exists():
        print(f"warden: {args.path} not found", file=sys.stderr)
        return 2
    res = scan(args.path)
    res.findings = [f for f in res.findings if at_least(f.severity, args.min_severity)]
    if args.format == "text":
        color = not args.no_color and not args.output and sys.stdout.isatty()
        out = report.text(res, color=color)
    else:
        out = FORMATS[args.format](res)
    if args.output:
        Path(args.output).write_text(out + "\n", encoding="utf-8")
    else:
        sys.stdout.reconfigure(encoding="utf-8")
        print(out)
    if args.fail_on != "none" and any(at_least(f.severity, args.fail_on) for f in res.findings):
        return 1
    return 0
