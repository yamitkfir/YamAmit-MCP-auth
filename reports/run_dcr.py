"""Polite runner for the one *write* detector, open-dcr (#12).

open-dcr is the only detector that mutates a target: it performs a real RFC 7591 client
registration, then deletes it again via RFC 7592. Because that write hits servers we do not
own, this runner is deliberately careful:

  * --dry-run (DEFAULT) is fully READ-ONLY. It runs OAuth discovery on each endpoint and
    reports which ones advertise a registration_endpoint — i.e. the candidate shortlist —
    without ever registering anything. Use this to decide where a live run is warranted.

  * --live runs ONLY open-dcr, one server at a time, with a delay between servers, a single
    attempt (no retry), and a per-server timeout. open-dcr self-cleans (RFC 7592 DELETE), and
    this runner surfaces — loudly, at the end — any client it could NOT delete, so nothing is
    silently left behind on someone else's server.

Usage:
    uv run python reports/run_dcr.py --dry-run                  # read-only shortlist
    uv run python reports/run_dcr.py --dry-run --json
    uv run python reports/run_dcr.py --live                     # WRITES (with cleanup)
    uv run python reports/run_dcr.py --live --only dock,switch  # restrict to named servers
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from urllib.parse import urlsplit

from mcpauth.detectors.tier2 import OpenDcr, _CLEANUP_FAIL_MARKER
from mcpauth.models import ProbeContext, TargetSpec, Verdict
from mcpauth.oauth import discover_oauth
from mcpauth.probe import Probe

ROOT = Path(__file__).resolve().parent
ENDPOINTS = ROOT / "endpoints.txt"
RAW_DIR = ROOT / "raw_dcr"

# Two modes, two files. They used to share one path, so the default (read-only!) --dry-run
# silently truncated the ONLY record of clients this tool had left behind on third-party
# servers. A live run now also refuses to clobber an existing report.
DRY_REPORT = ROOT / "dcr_shortlist.md"
LIVE_REPORT = ROOT / "dcr_scan.md"

PER_SERVER_TIMEOUT = 25.0   # seconds for the whole per-server probe
DELAY_BETWEEN = 2.0         # politeness gap between servers in a live run


def load_endpoints(only: set[str] | None) -> list[tuple[str, str]]:
    out = []
    for line in ENDPOINTS.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, url = (p.strip() for p in line.split("|", 1))
        if only is None or name in only:
            out.append((name, url))
    return out


async def discover_one(name: str, url: str) -> dict:
    """READ-ONLY: does this endpoint advertise a registration_endpoint?"""
    try:
        async with Probe(timeout=15) as probe:
            disc = await asyncio.wait_for(discover_oauth(probe, url), timeout=PER_SERVER_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {"name": name, "url": url, "reachable": False, "error": f"{type(e).__name__}: {e}"}
    md = disc.as_metadata or {}
    endpoint = md.get("registration_endpoint")
    return {
        "name": name, "url": url, "reachable": True,
        "registration_endpoint": endpoint if isinstance(endpoint, str) else None,
        "as_metadata_url": disc.as_metadata_url or None,
    }


async def dcr_one(name: str, url: str) -> dict:
    """WRITE: run only open-dcr (registers + self-deletes) against one server."""
    det = OpenDcr()
    registration_endpoint = None
    try:
        async with Probe(timeout=15) as probe:
            ctx = ProbeContext(target=TargetSpec(url=url), probe=probe)
            ctx.oauth = await asyncio.wait_for(discover_oauth(probe, url), timeout=PER_SERVER_TIMEOUT)
            registration_endpoint = (ctx.oauth.as_metadata or {}).get("registration_endpoint")
            finding = await asyncio.wait_for(det.detect(ctx), timeout=PER_SERVER_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        # A timeout can fire *during* RFC 7592 cleanup, after the client was created. The
        # old code returned no `cleanup_failed` flag here, so a run that created a client
        # and then aborted its own cleanup reported "no manual cleanup needed" and lost the
        # client id entirely. Assume the worst instead.
        return {
            "name": name, "url": url, "verdict": "ERROR",
            "registration_endpoint": registration_endpoint,
            "notes": (
                f"{type(e).__name__}: {e} — this aborted mid-probe, so a client MAY have "
                f"been created at {registration_endpoint!r} and not cleaned up. "
                f"{_CLEANUP_FAIL_MARKER}: verify manually."
            ),
            "cleanup_failed": True,
            "cleanup_uncertain": True,
        }
    d = finding.to_dict()
    d["name"], d["url"] = name, url
    # Record the host actually written to, not just the endpoint we scanned. Scanning
    # api.serff.ai registered a client on api.llow.io, and the report labelled it
    # "ca-rate-filings" — naming only the scan target hides who was really touched.
    d["registration_endpoint"] = registration_endpoint
    d["written_host"] = (
        urlsplit(registration_endpoint).hostname if isinstance(registration_endpoint, str) else None
    )
    d["cleanup_failed"] = _CLEANUP_FAIL_MARKER in (finding.notes or "")
    d["cleanup_uncertain"] = False
    return d


async def run_dry(endpoints: list[tuple[str, str]]) -> list[dict]:
    # Read-only: safe to run concurrently (politely capped).
    sem = asyncio.Semaphore(8)

    async def guarded(n, u):
        async with sem:
            return await discover_one(n, u)

    return list(await asyncio.gather(*(guarded(n, u) for n, u in endpoints)))


async def run_live(endpoints: list[tuple[str, str]]) -> list[dict]:
    # Writes: strictly sequential with a politeness delay, no concurrency, no retry.
    results = []
    for i, (name, url) in enumerate(endpoints):
        print(f"  [{i+1}/{len(endpoints)}] {name} ...", flush=True)
        results.append(await dcr_one(name, url))
        if i < len(endpoints) - 1:
            await asyncio.sleep(DELAY_BETWEEN)
    return results


def write_dry_report(rows: list[dict]) -> list[dict]:
    candidates = [r for r in rows if r.get("registration_endpoint")]
    lines = [
        "# open-dcr candidate shortlist (DRY RUN — read-only, no writes performed)\n",
        f"Scanned {len(rows)} endpoints. **{len(candidates)} advertise a registration_endpoint** "
        "(only these would be touched by a live run).\n",
        "| server | registration_endpoint |",
        "|---|---|",
    ]
    for r in sorted(candidates, key=lambda x: x["name"]):
        lines.append(f"| {r['name']} | {r['registration_endpoint']} |")
    for r in sorted(candidates, key=lambda x: x["name"]):
        host = urlsplit(r["registration_endpoint"]).hostname or "?"
        target_host = urlsplit(r["url"]).hostname or "?"
        if host != target_host:
            lines.append(
                f"\n> ⚠️ `{r['name']}` advertises registration on **{host}**, which is not "
                f"the host scanned (`{target_host}`). A live run would write to a different "
                "party; the scanner now refuses that unless it is a sibling domain."
            )
    unreachable = [r["name"] for r in rows if not r.get("reachable")]
    if unreachable:
        lines.append(f"\n_Unreachable during discovery: {', '.join(sorted(unreachable))}._")
    DRY_REPORT.write_text("\n".join(lines) + "\n")
    return candidates


def write_live_report(rows: list[dict]) -> list[dict]:
    RAW_DIR.mkdir(exist_ok=True)
    (RAW_DIR / "_summary.json").write_text(json.dumps(rows, indent=2))
    has = [r for r in rows if r.get("verdict") == Verdict.HAS_GAP.value]
    uncleaned = [r for r in rows if r.get("cleanup_failed")]
    lines = [
        "# open-dcr LIVE run (writes performed, with RFC 7592 cleanup)\n",
        f"Ran open-dcr against {len(rows)} server(s). **{len(has)} have open registration.**\n",
    ]
    if uncleaned:
        lines += [
            f"## ⚠️ {len(uncleaned)} client(s) could NOT be auto-deleted — MANUAL CLEANUP NEEDED\n",
            "| server | host written to | note |", "|---|---|---|",
            *[
                f"| {r['name']} | {r.get('written_host') or '?'} | {r['notes']} |"
                for r in uncleaned
            ],
            "",
        ]
    else:
        lines.append("✅ Every client created was deleted again (no manual cleanup needed).\n")
    lines += [
        "## All results\n",
        "| server | scanned | host written to | verdict | notes |",
        "|---|---|---|---|---|",
    ]
    for r in sorted(rows, key=lambda x: x["name"]):
        lines.append(
            f"| {r['name']} | {r.get('url','?')} | {r.get('written_host') or '—'} | "
            f"{r.get('verdict','?')} | {r.get('notes','')} |"
        )
    _write_without_clobbering(LIVE_REPORT, "\n".join(lines) + "\n")
    return uncleaned


def _write_without_clobbering(path: Path, content: str) -> None:
    """Write `path`, preserving any existing file as `<name>.prev-<n>.md`.

    The live report is the only durable record of clients left on servers we do not own, so
    it must never be silently replaced.
    """
    if path.exists():
        n = 1
        while (backup := path.with_suffix(f".prev-{n}.md")).exists():
            n += 1
        backup.write_text(path.read_text())
        print(f"  (previous report preserved as {backup.name})")
    path.write_text(content)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True,
                      help="READ-ONLY: list servers offering registration (default).")
    mode.add_argument("--live", action="store_true",
                      help="WRITES: actually run open-dcr (registers + self-deletes).")
    ap.add_argument("--only", help="Comma-separated server names to restrict to.")
    ap.add_argument("--json", action="store_true", help="Also print raw JSON to stdout.")
    ap.add_argument(
        "--yes", action="store_true",
        help="Skip the confirmation prompt for a --live run (for non-interactive use).",
    )
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",")} if args.only else None
    if only:
        names = {n for n, _ in load_endpoints(None)}
        missing = sorted(only - names)
        if missing:
            print(f"unknown server name(s) in --only: {missing}", flush=True)
            return 2
    endpoints = load_endpoints(only)
    if not endpoints:
        print("no endpoints selected — nothing to do.", flush=True)
        return 2

    if args.live:
        # A live run writes to servers we do not own. Requiring an explicit acknowledgement
        # of *how many* and *which* is the last chance to catch a mistaken `--live`.
        if not args.only and not args.yes:
            print(
                f"About to perform a REAL OAuth client registration against ALL "
                f"{len(endpoints)} endpoint(s) in {ENDPOINTS.name}.\n"
                "These are third-party servers. Pass --only <names> to narrow, or --yes to "
                "confirm you intend to write to all of them."
            )
            return 2
        print(f"LIVE open-dcr run over {len(endpoints)} server(s) "
              f"(sequential, {DELAY_BETWEEN}s apart, self-cleaning):")
        rows = asyncio.run(run_live(endpoints))
        uncleaned = write_live_report(rows)
        print(f"\nDone. Report: {LIVE_REPORT}")
        if uncleaned:
            print(f"⚠️  {len(uncleaned)} client(s) need MANUAL CLEANUP — see report.")
    else:
        rows = asyncio.run(run_dry(endpoints))
        candidates = write_dry_report(rows)
        print(f"DRY RUN (read-only): {len(candidates)}/{len(rows)} endpoints advertise a "
              f"registration_endpoint.\nShortlist: {DRY_REPORT}")
        for c in sorted(candidates, key=lambda x: x["name"]):
            print(f"  - {c['name']}: {c['registration_endpoint']}")

    if args.json:
        print(json.dumps(rows, indent=2))
    # 1 signals "open registration found" so a caller can branch, matching the CLI.
    return 1 if any(r.get("verdict") == Verdict.HAS_GAP.value for r in rows) else 0


if __name__ == "__main__":
    raise SystemExit(main())
