from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="envguard",
        description="Find missing environment variables and likely secrets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan_parser = sub.add_parser("scan", help="scan a project")
    scan_parser.add_argument("path", nargs="?", default=".", help="project directory")
    scan_parser.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text"
    )
    scan_parser.add_argument("--output", help="write the report to a file")
    scan_parser.add_argument(
        "--config", help="path to envguard.toml (default: auto-discover)"
    )
    scan_parser.add_argument("--quiet", action="store_true", help="suppress text output")
    scan_parser.add_argument("--verbose", action="store_true", help="show scan details")
    return parser


def as_json(findings):
    return [
        {"kind": f.kind, "path": f.path, "line": f.line, "message": f.message}
        for f in findings
    ]


def as_sarif(findings):
    results = []
    for f in findings:
        results.append(
            {
                "ruleId": f.kind,
                "level": "warning",
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path},
                            "region": {"startLine": f.line},
                        }
                    }
                ],
            }
        )
    return {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "envguard"}}, "results": results}],
    }


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()

    if not root.exists():
        print(f"error: path does not exist: {root}", file=sys.stderr)
        return 2
    if not root.is_dir():
        print(f"error: path is not a directory: {root}", file=sys.stderr)
        return 2

    if args.config:
        config = Path(args.config)
        if not config.is_absolute():
            config = root / config
        if not config.exists():
            print(f"error: config file does not exist: {config}", file=sys.stderr)
            return 2

    findings = scan(root)

    if args.verbose and not args.quiet and args.format == "text":
        print(f"Scanning {root}...", file=sys.stderr)

    if args.format == "json":
        output = json.dumps(as_json(findings), indent=2)
    elif args.format == "sarif":
        output = json.dumps(as_sarif(findings), indent=2)
    else:
        if findings:
            groups = {"missing-env": [], "stale-env": [], "secret": []}
            for finding in findings:
                groups.setdefault(finding.kind, []).append(finding)
            sections = []
            labels = {
                "missing-env": "Environment variables",
                "stale-env": "Stale environment entries",
                "secret": "Possible secrets",
            }
            for kind, items in groups.items():
                if not items:
                    continue
                lines = [labels.get(kind, kind)]
                lines.extend(
                    f"  {item.path}:{item.line}  {item.message}" for item in items
                )
                sections.append("\n".join(lines))
            output = "\n\n".join(sections)
        else:
            output = "No findings."
        output += f"\n\nSummary: {len(findings)} finding(s)."

    if args.output:
        try:
            Path(args.output).write_text(output + "\n")
        except OSError as exc:
            print(f"error: cannot write output: {exc}", file=sys.stderr)
            return 2
    elif not args.quiet:
        print(output)

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
