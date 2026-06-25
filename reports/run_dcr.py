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

from mcpauth.detectors.tier2 import OpenDcr, _CLEANUP_FAIL_MARKER
from mcpauth.models import ProbeContext, TargetSpec, Verdict
from mcpauth.oauth import discover_oauth
from mcpauth.probe import Probe

ROOT = Path(__file__).resolve().parent
ENDPOINTS = ROOT / "endpoints.txt"
RAW_DIR = ROOT / "raw_dcr"
REPORT = ROOT / "dcr_scan.md"

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
    try:
        async with Probe(timeout=15) as probe:
            ctx = ProbeContext(target=TargetSpec(url=url), probe=probe)
            ctx.oauth = await asyncio.wait_for(discover_oauth(probe, url), timeout=PER_SERVER_TIMEOUT)
            finding = await asyncio.wait_for(det.detect(ctx), timeout=PER_SERVER_TIMEOUT)
    except Exception as e:  # noqa: BLE001
        return {"name": name, "url": url, "verdict": "ERROR", "notes": f"{type(e).__name__}: {e}"}
    d = finding.to_dict()
    d["name"], d["url"] = name, url
    d["cleanup_failed"] = _CLEANUP_FAIL_MARKER in (finding.notes or "")
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
    unreachable = [r["name"] for r in rows if not r.get("reachable")]
    if unreachable:
        lines.append(f"\n_Unreachable during discovery: {', '.join(sorted(unreachable))}._")
    REPORT.write_text("\n".join(lines) + "\n")
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
            "| server | note |", "|---|---|",
            *[f"| {r['name']} | {r['notes']} |" for r in uncleaned],
            "",
        ]
    else:
        lines.append("✅ Every client created was deleted again (no manual cleanup needed).\n")
    lines += ["## All results\n", "| server | verdict | notes |", "|---|---|---|"]
    for r in sorted(rows, key=lambda x: x["name"]):
        lines.append(f"| {r['name']} | {r.get('verdict','?')} | {r.get('notes','')} |")
    REPORT.write_text("\n".join(lines) + "\n")
    return uncleaned


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", default=True,
                      help="READ-ONLY: list servers offering registration (default).")
    mode.add_argument("--live", action="store_true",
                      help="WRITES: actually run open-dcr (registers + self-deletes).")
    ap.add_argument("--only", help="Comma-separated server names to restrict to.")
    ap.add_argument("--json", action="store_true", help="Also print raw JSON to stdout.")
    args = ap.parse_args()

    only = {s.strip() for s in args.only.split(",")} if args.only else None
    endpoints = load_endpoints(only)

    if args.live:
        print(f"LIVE open-dcr run over {len(endpoints)} server(s) "
              f"(sequential, {DELAY_BETWEEN}s apart, self-cleaning):")
        rows = asyncio.run(run_live(endpoints))
        uncleaned = write_live_report(rows)
        print(f"\nDone. Report: {REPORT}")
        if uncleaned:
            print(f"⚠️  {len(uncleaned)} client(s) need MANUAL CLEANUP — see report.")
    else:
        rows = asyncio.run(run_dry(endpoints))
        candidates = write_dry_report(rows)
        print(f"DRY RUN (read-only): {len(candidates)}/{len(rows)} endpoints advertise a "
              f"registration_endpoint.\nShortlist: {REPORT}")
        for c in sorted(candidates, key=lambda x: x["name"]):
            print(f"  - {c['name']}: {c['registration_endpoint']}")

    if args.json:
        print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
