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
import os
import time
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

# Append-only, flushed and fsynced per line, written DURING the run. The reports below are
# only produced after every server has been probed, so an interruption — Ctrl-C, SIGTERM,
# OOM, a closed laptop — used to discard every client_id created so far. On a run that
# creates dozens of registrations nobody can delete, that record is the only way to tell an
# operator which clients we left on their server. This file is never truncated.
JOURNAL = RAW_DIR / "write_journal.jsonl"

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
        async with Probe(timeout=15, target_url=url) as probe:
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


def journal_write(record: dict) -> None:
    """Append one record about something we created, and make it durable immediately.

    Opened, flushed, fsynced and closed per call. That is deliberately wasteful: the whole
    point is that the line survives whatever kills the process on the very next statement,
    so buffering it would defeat the purpose.
    """
    RAW_DIR.mkdir(exist_ok=True)
    with JOURNAL.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": time.time(), **record}, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def _could_have_written(registration_endpoint) -> bool:
    """True if a registration POST was even possible when the probe died.

    With no `registration_endpoint`, `OpenDcr` had nowhere to POST and returns
    NOT_APPLICABLE before sending anything, so flagging cleanup would invent an obligation
    that can never be discharged. `reports/dcr_scan.md` over-reports by exactly one row for
    this reason.
    """
    return isinstance(registration_endpoint, str) and bool(registration_endpoint)


def _journal_abort(url: str, registration_endpoint, exc: BaseException) -> None:
    """Record an aborted probe, if a write could have happened, before unwinding."""
    if not _could_have_written(registration_endpoint):
        return
    journal_write({
        "gap_id": "open-dcr", "target": url,
        "registration_endpoint": registration_endpoint, "client_id": None,
        "stage": "aborted-outcome-unknown",
        "detail": f"{type(exc).__name__}: {exc}",
    })


async def dcr_one(name: str, url: str) -> dict:
    """WRITE: run only open-dcr (registers + self-deletes) against one server."""
    det = OpenDcr()
    registration_endpoint = None
    try:
        async with Probe(timeout=15, target_url=url) as probe:
            ctx = ProbeContext(
                target=TargetSpec(url=url), probe=probe, write_journal=journal_write
            )
            ctx.oauth = await asyncio.wait_for(discover_oauth(probe, url), timeout=PER_SERVER_TIMEOUT)
            registration_endpoint = (ctx.oauth.as_metadata or {}).get("registration_endpoint")
            finding = await asyncio.wait_for(det.detect(ctx), timeout=PER_SERVER_TIMEOUT)
    except asyncio.CancelledError as e:
        # Ctrl-C must STOP the run. On Python 3.11+ the first SIGINT arrives here as one
        # `CancelledError`, so catching it alongside `Exception` and returning a row
        # consumed the cancellation outright: `run_live` carried on and registered clients
        # on every remaining third-party server, and the operator saw a run that looked
        # like it completed. Record what we owe, then re-raise so the loop actually ends.
        _journal_abort(url, registration_endpoint, e)
        raise
    except Exception as e:  # noqa: BLE001
        # A timeout can fire *during* RFC 7592 cleanup, after the client was created, so a
        # run that created a client and then aborted its own cleanup must not report "no
        # manual cleanup needed". But only claim an obligation when a write was actually
        # possible: with no `registration_endpoint`, `OpenDcr` had nowhere to POST and
        # returns NOT_APPLICABLE before sending anything, so flagging cleanup here invents
        # an obligation that can never be discharged. The committed
        # `reports/dcr_scan.md` over-reports by exactly one row for this reason.
        could_have_written = _could_have_written(registration_endpoint)
        if could_have_written:
            _journal_abort(url, registration_endpoint, e)
            notes = (
                f"{type(e).__name__}: {e} — this aborted mid-probe, so a client MAY have "
                f"been created at {registration_endpoint!r} and not cleaned up. "
                f"{_CLEANUP_FAIL_MARKER}: verify manually."
            )
        else:
            notes = (
                f"{type(e).__name__}: {e} — this aborted before any registration endpoint "
                "was known, so no registration request can have been sent and no cleanup "
                "is owed."
            )
        return {
            "name": name, "url": url, "verdict": "ERROR",
            "registration_endpoint": registration_endpoint,
            "written_host": (
                urlsplit(registration_endpoint).hostname if could_have_written else None
            ),
            "notes": notes,
            "cleanup_failed": could_have_written,
            "cleanup_uncertain": could_have_written,
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
    #
    # Every row is appended to the journal as it completes, not collected and written at the
    # end. A run over the full list takes many minutes, and the reports are produced only
    # after the last server — so an interruption anywhere in between used to discard every
    # result gathered so far, including the registrations that could not be deleted.
    results = []
    for i, (name, url) in enumerate(endpoints):
        print(f"  [{i+1}/{len(endpoints)}] {name} ...", flush=True)
        row = await dcr_one(name, url)
        results.append(row)
        journal_write({
            "gap_id": "open-dcr", "target": url, "stage": "server-complete",
            "name": name, "verdict": row.get("verdict"),
            "registration_endpoint": row.get("registration_endpoint"),
            "written_host": row.get("written_host"),
            "cleanup_failed": row.get("cleanup_failed"),
            "client_id": None,
            "detail": (row.get("notes") or "")[:400],
        })
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
    # Also clobber-protected. It holds no client ids, but `--only <one-server>` otherwise
    # silently replaced the full 88-endpoint shortlist with a one-row file — losing the
    # survey a live run is meant to be chosen from.
    _write_without_clobbering(DRY_REPORT, "\n".join(lines) + "\n")
    return candidates


def write_live_report(rows: list[dict]) -> list[dict]:
    RAW_DIR.mkdir(exist_ok=True)
    _write_without_clobbering(
        RAW_DIR / "_summary.json", json.dumps(rows, indent=2) + "\n"
    )
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
    """Write `path`, preserving any existing file as `<stem>.prev-<n><suffix>`.

    Every durable record of clients left on servers we do not own goes through here, so none
    of them is ever silently replaced.

    The backup keeps the original file's own extension. Hardcoding `.md` — which this did —
    meant it could only be used for the Markdown report; pointing it at `_summary.json`
    would have produced `_summary.prev-1.md`, giving JSON content a Markdown name. That is
    why the JSON was being overwritten in place instead, and why the first live run's four
    `client_id`s survive only in `dcr_scan.prev-1.md`.
    """
    if path.exists():
        n = 1
        while (backup := path.with_name(f"{path.stem}.prev-{n}{path.suffix}")).exists():
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
