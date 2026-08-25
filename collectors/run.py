"""Run every collector and report what each one did.

The report is the point. A collector that could not reach its source and a
collector that looked and found nothing produce the same silence otherwise,
and those two mean opposite things — one is a quiet week, the other is a
broken pipeline nobody noticed for a month.

Exit status is deliberately forgiving: a collector erroring or skipping does
not fail the run, because the other collectors' findings are still worth
committing. `--strict` makes any non-ok result fail, which is what a human
debugging a single collector wants.
"""
from __future__ import annotations

import argparse
import sys

from .base import QUEUE_DIR, load_dismissed, run_collector
from . import mcp_registry, slopsquat

COLLECTORS = {
    slopsquat.NAME: slopsquat.collect,
    mcp_registry.NAME: mcp_registry.collect,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", action="append", metavar="NAME",
                        choices=sorted(COLLECTORS),
                        help="run just this collector (repeatable)")
    parser.add_argument("--strict", action="store_true",
                        help="fail the run if any collector skipped or errored")
    args = parser.parse_args(argv)

    selected = args.only or sorted(COLLECTORS)
    dismissed = load_dismissed()
    results = [run_collector(name, COLLECTORS[name], QUEUE_DIR, dismissed)
               for name in selected]

    print(f"RADAR collectors — {len(selected)} run")
    for result in results:
        print(result.line())

    new = sum(r.new for r in results)
    queued = len(list(QUEUE_DIR.glob("*.json"))) if QUEUE_DIR.exists() else 0
    skipped = [r.name for r in results if r.status == "skipped"]
    errored = [r.name for r in results if r.status == "error"]

    print(f"\n{new} new candidate(s); {queued} awaiting triage in triage/queue/")
    if skipped:
        print(f"could not look: {', '.join(skipped)}")
    if errored:
        print(f"errored: {', '.join(errored)}")
    if new:
        print("\nNothing here is an entry. Each candidate needs a primary source "
              "read by a human before it can reach data/entries/.")

    if errored:
        return 1
    if args.strict and skipped:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
