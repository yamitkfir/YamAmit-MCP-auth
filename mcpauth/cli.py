"""Command-line entry point: `mcpauth scan <url>`."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from .detectors import WRITE_DETECTORS
from .runner import scan

_VERDICT_MARK = {
    "HAS_GAP": "✗ HAS GAP",
    "NO_GAP": "✓ no gap",
    "NOT_APPLICABLE": "– n/a",
    "INCONCLUSIVE": "? inconclusive",
    "ERROR": "! error",
}


def _print_human(report: dict) -> None:
    print(f"\nTarget: {report['target']}")
    print(f"Protocol version: {report.get('protocol_version') or 'unspecified'}")
    if report.get("server_info"):
        si = report["server_info"]
        print(f"Server: {si.get('name', '?')} {si.get('version', '')}".rstrip())
    print("Discovery:")
    for note in report["discovery"]:
        print(f"  - {note}")
    print("\nFindings (one per auth gap):")
    for f in report["findings"]:
        mark = _VERDICT_MARK.get(f["verdict"], f["verdict"])
        print(f"  [{mark:>16}] {f['gap_id']:<38} ({f['severity']})")
        if f["notes"]:
            print(f"      {f['notes']}")
    print("\nSummary:", json.dumps(report["summary"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcpauth", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan an MCP server for auth gaps")
    scan_p.add_argument("url", help="MCP server URL, e.g. http://localhost:9100/mcp")
    scan_p.add_argument(
        "--tier", type=int, action="append", dest="tiers",
        help="Only run detectors in this tier (repeatable). Default: all.",
    )
    scan_p.add_argument(
        "--exclude", action="append", dest="exclude", metavar="GAP_ID",
        help="Skip a detector by gap id (repeatable).",
    )
    scan_p.add_argument(
        "--safe", action="store_true",
        help="Skip detectors with side effects (currently open-dcr, which performs a "
             "registration write). Read-only scans only.",
    )
    scan_p.add_argument("--json", action="store_true", help="Emit raw JSON report")

    args = parser.parse_args(argv)
    if args.command == "scan":
        tiers = set(args.tiers) if args.tiers else None
        exclude = set(args.exclude) if args.exclude else set()
        if args.safe:
            exclude |= WRITE_DETECTORS
        report = asyncio.run(scan(args.url, tiers, exclude or None))
        if args.json:
            print(json.dumps(report, indent=2))
        else:
            _print_human(report)
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
