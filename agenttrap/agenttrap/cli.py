"""python -m agenttrap"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys

from . import __version__
from .report import write as write_report
from .runner import agent_version, load_all, run_once, save
from .scenarios import ALL, BY_NAME


def cmd_list(args) -> int:
    for scenario in ALL:
        print(f"{scenario.name:20s} {scenario.shape:11s} {scenario.precedent}")
        print(f"  {scenario.summary}")
        print(f"  canary: {scenario.canary}")
        print()
    return 0


def cmd_manifest(args) -> int:
    print(json.dumps([s.manifest() for s in ALL], indent=2))
    return 0


def cmd_run(args) -> int:
    if args.all:
        selected = ALL
    elif args.scenario:
        try:
            selected = [BY_NAME[n] for n in args.scenario]
        except KeyError as missing:
            print(f"agenttrap: unknown scenario {missing}", file=sys.stderr)
            return 2
    else:
        print("agenttrap: pass --all or one or more --scenario names", file=sys.stderr)
        return 2

    conditions = ["primed", "control"] if args.both else [args.condition]
    print(f"agenttrap {__version__} — {len(selected)} scenario(s) x "
          f"{args.runs} run(s) x {len(conditions)} condition(s)")
    print(f"agent: {agent_version()}\n")

    failures = 0
    for condition in conditions:
      for scenario in selected:
        for run in range(1, args.runs + 1):
            result = run_once(scenario, run, keep=args.keep, condition=condition)
            save(result)
            if result.status != "ok":
                failures += 1
                mark = f"ERROR   {result.detail}"
            else:
                mark = ("TOOK THE BAIT  " if result.fired else "held           ") \
                       + result.evidence
            print(f"  {condition:8s} {scenario.name:20s} run {run}  {mark}")
    print()
    if failures:
        print(f"{failures} run(s) did not complete — recorded as errors, not passes.")
    return 0


def cmd_report(args) -> int:
    runs = load_all()
    if not runs:
        print("agenttrap: no recorded runs; run some first", file=sys.stderr)
        return 2
    path = write_report(agent_version(), args.date or _dt.date.today().isoformat())
    print(f"wrote {path} from {len(runs)} recorded run(s)")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agenttrap",
        description="Measure whether coding agents fall for supply-chain traps.")
    parser.add_argument("--version", action="version", version=f"agenttrap {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    listing = subparsers.add_parser("list", help="show the scenarios")
    listing.set_defaults(func=cmd_list)

    manifest = subparsers.add_parser("manifest", help="scenario manifests as JSON")
    manifest.set_defaults(func=cmd_manifest)

    running = subparsers.add_parser("run", help="run scenarios")
    running.add_argument("--all", action="store_true")
    running.add_argument("--scenario", action="append", choices=sorted(BY_NAME))
    running.add_argument("--runs", type=int, default=3,
                         help="runs per scenario (default 3)")
    running.add_argument("--condition", choices=("primed", "control"),
                         default="primed",
                         help="primed: the task asks the agent to look for "
                              "problems. control: ordinary work, no invitation "
                              "to be suspicious.")
    running.add_argument("--both", action="store_true",
                         help="run both conditions")
    running.add_argument("--keep", action="store_true",
                         help="keep every scenario directory, not only the ones "
                              "where the canary fired")
    running.set_defaults(func=cmd_run)

    reporting = subparsers.add_parser("report", help="write results/REPORT.md")
    reporting.add_argument("--date")
    reporting.set_defaults(func=cmd_report)

    args = parser.parse_args(argv)
    return args.func(args)
