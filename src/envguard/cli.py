from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .scanner import scan

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="envguard")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="scan a project")
    scan_parser.add_argument("path", nargs="?", default=".")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_parser.add_argument("--output")
    return parser

def as_json(findings):
    return [
        {"kind": f.kind, "path": f.path, "line": f.line, "message": f.message}
        for f in findings
    ]

def as_sarif(findings):
    results = []
    for f in findings:
        results.append({
            "ruleId": f.kind,
            "level": "warning",
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path},
                    "region": {"startLine": f.line},
                }
            }],
        })
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "envguard"}}, "results": results}]}

def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.path).resolve()
    findings = scan(root)

    if args.format == "json":
        output = json.dumps(as_json(findings), indent=2)
    elif args.format == "sarif":
        output = json.dumps(as_sarif(findings), indent=2)
    else:
        if findings:
            output = "\n".join(f"{f.kind:12} {f.path}:{f.line}  {f.message}" for f in findings)
        else:
            output = "No findings."
        output += f"\n\n{len(findings)} finding(s)."

    if args.output:
        Path(args.output).write_text(output + "\n")
    else:
        print(output)

    return 1 if findings else 0

if __name__ == "__main__":
    raise SystemExit(main())
