"""The command line.

Design rule throughout: never let a scan look clean when it was not complete.
A skipped file, a stale feed, an unparseable version — each of those is printed,
and the exit code distinguishes "found something" from "could not finish".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .feed import FeedIndex, FeedUnavailable, load
from .findings import ScanReport
from .nearmiss import NearMissChecker
from .sarif import build as build_sarif
from .scanners import hooks, lockfiles, mcp, skills

# Exit codes are part of the interface: CI needs to tell "clean" from "broken".
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

COLOURS = {"critical": "\033[91m", "high": "\033[93m", "medium": "\033[96m",
           "low": "\033[90m", "info": "\033[90m"}
RESET = "\033[0m"

FAIL_LEVELS = ("critical", "high", "medium", "low", "info", "never")


def _tty() -> bool:
    return sys.stdout.isatty()


def _paint(text: str, severity: str) -> str:
    return f"{COLOURS.get(severity, '')}{text}{RESET}" if _tty() else text


def run_scan(project: Path, index: FeedIndex, home: Path | None,
             skip: set[str], exclude: tuple[str, ...] = ()) -> ScanReport:
    report = ScanReport()
    checker = NearMissChecker(index)
    if "deps" not in skip:
        lockfiles.scan(project, index, report, near_miss=checker, exclude=exclude)
    if "mcp" not in skip:
        mcp.scan(project, index, report, home=home)
    if "skills" not in skip:
        skills.scan(project, index, report, home=home, exclude=exclude)
    if "hooks" not in skip:
        hooks.scan(project, report, home=home)
    return report


def print_report(report: ScanReport, project: Path, quiet: bool) -> None:
    findings = report.sorted()

    if not quiet:
        scanned = ", ".join(f"{v} {k}" for k, v in sorted(report.scanned.items())) or "nothing"
        print(f"radar-check {__version__} — scanned {scanned}")
        print(f"feed: {report.entry_count} entries, updated {report.feed_last_updated} "
              f"({report.feed_origin})")
        if report.feed_origin == "stale-cache":
            print("  warning: the network was unreachable, so this used a cached "
                  "feed that may be out of date")
        print()

    for finding in findings:
        label = _paint(f"{finding.severity.upper():>8}", finding.severity)
        print(f"{label}  {finding.title}")
        print(f"          {finding.location}")
        if finding.detail:
            print(f"          {finding.detail}")
        if finding.uncertainty:
            print(f"          uncertain: {finding.uncertainty}")
        if finding.remediation:
            print(f"          → {finding.remediation}")
        if finding.source:
            print(f"          source: {finding.source}")
        print()

    if report.skipped:
        print(f"{len(report.skipped)} file(s) could not be read — these were NOT scanned:")
        for note in report.skipped[:10]:
            print(f"  {note}")
        if len(report.skipped) > 10:
            print(f"  ... and {len(report.skipped) - 10} more")
        print()

    if findings:
        counts = report.counts()
        summary = ", ".join(f"{counts[s]} {s}" for s in
                            ("critical", "high", "medium", "low", "info") if s in counts)
        print(f"{len(findings)} finding(s): {summary}")
    elif not quiet:
        print("No findings.")
        if report.skipped:
            print("Note: some files could not be read, so this is not a clean bill of health.")


def _should_fail(report: ScanReport, threshold: str) -> bool:
    if threshold == "never" or not report.findings:
        return False
    order = ["critical", "high", "medium", "low", "info"]
    allowed = order[: order.index(threshold) + 1]
    return any(f.severity in allowed for f in report.findings)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="radar-check",
        description="Scan a project and machine against the RADAR threat feed.")
    parser.add_argument("path", nargs="?", default=".", help="project to scan")
    parser.add_argument("--feed", help="path to a feed.json instead of downloading")
    parser.add_argument("--offline", action="store_true",
                        help="never hit the network; use the cache or fail")
    parser.add_argument("--refresh", action="store_true", help="ignore a fresh cache")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", help="write the report here instead of stdout")
    parser.add_argument("--skip", action="append", default=[],
                        choices=("deps", "mcp", "skills", "hooks"),
                        help="skip a scanner (repeatable)")
    parser.add_argument("--exclude", action="append", default=[], metavar="NAME",
                        help="skip a directory name or glob (repeatable); "
                             "for test fixtures and vendored code")
    parser.add_argument("--no-home", action="store_true",
                        help="scan only the project, not the user's home directory")
    parser.add_argument("--fail-on", choices=FAIL_LEVELS, default="medium",
                        help="exit non-zero at this severity or worse (default: medium)")
    parser.add_argument("--quiet", "-q", action="store_true")
    parser.add_argument("--version", action="version", version=f"radar-check {__version__}")
    args = parser.parse_args(argv)

    project = Path(args.path).expanduser().resolve()
    if not project.is_dir():
        print(f"radar-check: {project} is not a directory", file=sys.stderr)
        return EXIT_ERROR

    try:
        feed, origin = load(args.feed, offline=args.offline, refresh=args.refresh)
    except FeedUnavailable as error:
        # Never scan without a feed: a run with no data finds nothing and looks
        # exactly like a clean project.
        print(f"radar-check: {error}", file=sys.stderr)
        return EXIT_ERROR

    index = FeedIndex(feed)
    home = None if args.no_home else Path.home()
    report = run_scan(project, index, home, set(args.skip), tuple(args.exclude))
    report.feed_origin = origin
    report.feed_last_updated = feed.get("last_updated", "unknown")
    report.entry_count = feed.get("entry_count", len(feed.get("entries", [])))

    if args.format == "text":
        stream = open(args.output, "w") if args.output else sys.stdout
        try:
            original, sys.stdout = sys.stdout, stream
            print_report(report, project, args.quiet)
        finally:
            sys.stdout = original
            if args.output:
                stream.close()
    else:
        payload = (build_sarif(report, project, __version__) if args.format == "sarif"
                   else {
                       "tool": "radar-check", "version": __version__,
                       "feed": {"origin": origin,
                                "last_updated": report.feed_last_updated,
                                "entry_count": report.entry_count},
                       "scanned": report.scanned,
                       "skipped": report.skipped,
                       "findings": [f.to_dict() for f in report.sorted()],
                   })
        text = json.dumps(payload, indent=2) + "\n"
        if args.output:
            Path(args.output).write_text(text)
        else:
            sys.stdout.write(text)

    return EXIT_FINDINGS if _should_fail(report, args.fail_on) else EXIT_CLEAN


if __name__ == "__main__":
    raise SystemExit(main())
