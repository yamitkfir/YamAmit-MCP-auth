"""Command-line entry point: `mcpauth scan <url>`."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import NoReturn
from urllib.parse import urlsplit

from .detectors import ALL_DETECTORS, WRITE_DETECTORS, known_gap_ids, known_tiers
from .runner import scan

# Exit codes, so a bulk-scan script can branch on the outcome. The CLI used to return 0
# unconditionally, which meant `run_scans.sh`'s `$?` check could never distinguish a clean
# server from a wide-open one or from a scan that never reached the target.
EXIT_CLEAN = 0
EXIT_GAP_FOUND = 1
EXIT_SCAN_FAILED = 2
EXIT_USAGE = 3


class _Parser(argparse.ArgumentParser):
    """An ArgumentParser whose usage errors exit EXIT_USAGE instead of argparse's own 2.

    argparse hardcodes status 2 for a bad command line, which is the same code this CLI uses
    for "the target never answered". `run_scans.sh` *retries* on 2 — so one mistyped flag was
    reported as every endpoint in the list failing twice, rather than as a single bad command.
    """

    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


_VERDICT_MARK = {
    "HAS_GAP": "✗ HAS GAP",
    "NO_GAP": "✓ no gap",
    "NOT_APPLICABLE": "– n/a",
    "INCONCLUSIVE": "? inconclusive",
    "ERROR": "! error",
}


def _print_human(report: dict) -> None:
    print(f"\nTarget: {report['target']}")
    if not report.get("reachable"):
        print("Reachable: NO — the target never answered, so verdicts below are not "
              "observations about the server.")
    print(f"Protocol version: {report.get('protocol_version') or 'unspecified'}")
    if report.get("server_info"):
        si = report["server_info"]
        print(f"Server: {si.get('name', '?')} {si.get('version', '')}".rstrip())
    if report.get("excluded"):
        print(f"Detectors skipped: {', '.join(report['excluded'])}")
    print("Discovery:")
    for note in report["discovery"]:
        print(f"  - {note}")
    oauth = report.get("oauth") or {}
    if oauth.get("blocked_urls"):
        print("Refused destinations (target-supplied, outside the allowed scope):")
        for u in oauth["blocked_urls"]:
            print(f"  - {u}")
    if oauth.get("external_hosts_contacted"):
        print(f"Other hosts contacted: {', '.join(oauth['external_hosts_contacted'])}")
    print("\nFindings (one per auth gap):")
    for f in report["findings"]:
        mark = _VERDICT_MARK.get(f["verdict"], f["verdict"])
        print(f"  [{mark:>16}] {f['gap_id']:<38} ({f['severity']})")
        if f["notes"]:
            print(f"      {f['notes']}")
    print("\nSummary:", json.dumps(report["summary"]))


def _exit_code(report: dict) -> int:
    """Map a report onto the process exit code a bulk runner branches on.

    `reachable` is only meaningful for HTTP targets. A stdio target is never "reached" over
    the network, yet every detector answers NOT_APPLICABLE correctly — reporting that as
    EXIT_SCAN_FAILED made a completely successful scan look like a failed one (and
    `run_scans.sh` then retried it).
    """
    summary = report.get("summary", {})
    if summary.get("HAS_GAP"):
        return EXIT_GAP_FOUND
    if summary.get("ERROR"):
        return EXIT_SCAN_FAILED
    verdicts = {k for k, v in summary.items() if v}
    if verdicts == {"NOT_APPLICABLE"}:
        # Nothing was applicable, so nothing failed — there was simply nothing to test.
        return EXIT_CLEAN
    if not report.get("reachable"):
        return EXIT_SCAN_FAILED
    return EXIT_CLEAN


def _validate_url(parser: argparse.ArgumentParser, url: str) -> None:
    """Reject a target that is not a URL, instead of silently reporting it as clean.

    `mcpauth scan example.com/mcp` used to produce twelve confident NOT_APPLICABLE verdicts
    and exit 0, with a note blaming stdio transport — a wrong answer that looks like a
    right one.
    """
    parts = urlsplit(url)
    if not parts.scheme:
        parser.error(
            f"target {url!r} has no scheme — did you mean https://{url}? "
            "(stdio targets are written stdio:///path/to/server)"
        )
    if parts.scheme in ("http", "https") and not parts.netloc:
        parser.error(f"target {url!r} has no host")
    if parts.scheme not in ("http", "https", "stdio"):
        parser.error(
            f"target {url!r} uses unsupported scheme {parts.scheme!r}; "
            "expected http, https, or stdio"
        )


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(prog="mcpauth", description=__doc__)
    # add_subparsers defaults parser_class to type(self), so `scan` inherits the exit code.
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan an MCP server for auth gaps")
    # Optional so `--list-detectors` works on its own, as its help text and the
    # unknown-gap-id error message both promise. A missing url is still rejected below.
    scan_p.add_argument(
        "url", nargs="?", help="MCP server URL, e.g. http://localhost:9100/mcp"
    )
    scan_p.add_argument(
        "--tier", type=int, action="append", dest="tiers",
        help="Only run detectors in this tier (repeatable). Default: all.",
    )
    scan_p.add_argument(
        "--exclude", action="append", dest="exclude", metavar="GAP_ID",
        help="Skip a detector by gap id (repeatable).",
    )
    scan_p.add_argument(
        "--unsafe-writes", action="store_true",
        help="Enable detectors that MODIFY the target (currently open-dcr, which performs a "
             "real OAuth client registration). Off by default: only pass this for servers "
             "you own or have written permission to test.",
    )
    scan_p.add_argument(
        "--insecure-tls", action="store_true",
        help="Do not verify TLS certificates. Only for local sandboxes with self-signed "
             "certs; it makes the TLS verdicts meaningless and allows interception.",
    )
    scan_p.add_argument("--json", action="store_true", help="Emit raw JSON report")
    scan_p.add_argument(
        "--list-detectors", action="store_true",
        help="Print the detector registry and exit.",
    )

    args = parser.parse_args(argv)
    if args.command != "scan":
        return EXIT_USAGE

    if args.list_detectors:
        for cls in ALL_DETECTORS:
            flag = " [WRITES]" if cls.has_side_effects else ""
            print(f"tier {cls.tier}  {cls.gap_id:<38} {cls.severity.value}{flag}")
        return EXIT_CLEAN

    if args.url is None:
        scan_p.error("the following arguments are required: url")
    _validate_url(scan_p, args.url)

    # A mistyped tier used to select zero detectors and print an empty, clean-looking
    # report; a mistyped gap id used to exclude nothing at all — so `--exclude opendcr`
    # (one missing hyphen) still performed the write it was meant to suppress.
    tiers = set(args.tiers) if args.tiers else None
    if tiers:
        unknown = sorted(tiers - known_tiers())
        if unknown:
            scan_p.error(
                f"unknown tier(s) {unknown}; implemented tiers are "
                f"{sorted(known_tiers())}"
            )

    exclude = set(args.exclude) if args.exclude else set()
    unknown_ids = sorted(exclude - known_gap_ids())
    if unknown_ids:
        scan_p.error(
            f"unknown gap id(s) {unknown_ids}; run `mcpauth scan --list-detectors` "
            "to see valid ids"
        )

    if not args.unsafe_writes:
        exclude |= WRITE_DETECTORS
    else:
        print(
            f"WARNING: write-performing detector(s) enabled: {', '.join(sorted(WRITE_DETECTORS))}. "
            f"These send real requests that create state on {args.url}.",
            file=sys.stderr,
        )

    report = asyncio.run(
        scan(args.url, tiers, exclude or None, insecure_tls=args.insecure_tls)
    )
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        _print_human(report)
    return _exit_code(report)


if __name__ == "__main__":
    sys.exit(main())
