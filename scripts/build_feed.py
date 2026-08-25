#!/usr/bin/env python3
"""Validate every RADAR entry, then build the published artifacts into dist/.

    python scripts/build_feed.py

Outputs:
    dist/feed.json              every entry
    dist/feed-<category>.json   one file per category
    dist/blocklist.json         flat indicators, the minimal file a runtime guard needs

The build is deterministic: it derives its timestamps from the entries
themselves, never from the clock, so the same input always produces
byte-identical output.
"""
from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate import ENTRIES_DIR, REPO_ROOT, load_entries, validate  # noqa: E402

DIST_DIR = REPO_ROOT / "dist"
SCHEMA_VERSION = "1.0.0"
LICENSE = "CC-BY-4.0"
HOMEPAGE = "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/tree/main"
ATTRIBUTION = f"RADAR ({HOMEPAGE}), CC BY 4.0"

CATEGORIES = [
    "malicious-skill",
    "slopsquat-package",
    "malicious-mcp-server",
    "malicious-package",
    "compromised-package",
    "platform-vuln",
    "vibe-app-breach",
]


def envelope(name: str, entries: list[dict]) -> dict:
    return {
        "feed": name,
        "schema_version": SCHEMA_VERSION,
        "homepage": HOMEPAGE,
        "license": LICENSE,
        "attribution": ATTRIBUTION,
        "last_updated": max((e["last_updated"] for e in entries), default="1970-01-01"),
        "entry_count": len(entries),
        "entries": entries,
    }


def primary_source(entry: dict) -> str:
    """The one source URL a consumer should show. Prefers a primary source."""
    for src in entry["sources"]:
        if src["type"] == "primary":
            return src["url"]
    return entry["sources"][0]["url"]


def indicator_sort_key(row: dict) -> tuple:
    return (
        row["type"],
        row.get("registry", ""),
        row.get("name") or row.get("slug") or row.get("value") or row.get("url") or "",
        row.get("version", ""),
        row["id"],
    )


def build_blocklist(entries: list[dict]) -> dict:
    rows: list[dict] = []
    for entry in entries:
        source = primary_source(entry)
        for indicator in entry["indicators"]:
            row = dict(indicator)
            # category and status travel with every indicator so a guard can tell a
            # malicious artifact from a legitimate one that merely had a vulnerability.
            # Blocking a platform-vuln indicator without checking its version range
            # would take out a package the developer is entitled to use.
            row.update(
                {
                    "id": entry["id"],
                    "severity": entry["severity"],
                    "category": entry["category"],
                    "status": entry["status"],
                    "source": source,
                }
            )
            rows.append(row)
    rows.sort(key=indicator_sort_key)
    return {
        "feed": "radar-blocklist",
        "schema_version": SCHEMA_VERSION,
        "homepage": HOMEPAGE,
        "license": LICENSE,
        "attribution": ATTRIBUTION,
        "last_updated": max((e["last_updated"] for e in entries), default="1970-01-01"),
        "indicator_count": len(rows),
        "indicators": rows,
    }


def dump(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def build(entries_dir: Path = ENTRIES_DIR, dist_dir: Path = DIST_DIR) -> dict[str, Path]:
    failures = validate(entries_dir, quiet=True)
    if failures:
        print(f"FAIL: refusing to build, {len(failures)} validation problem(s):", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        raise SystemExit(1)

    entries = [entry for _, entry in load_entries(entries_dir)]
    entries.sort(key=lambda e: e["id"])

    written: dict[str, Path] = {}

    full = dist_dir / "feed.json"
    dump(full, envelope("radar", entries))
    written["feed"] = full

    for category in CATEGORIES:
        subset = [e for e in entries if e["category"] == category]
        path = dist_dir / f"feed-{category}.json"
        dump(path, envelope(f"radar-{category}", subset))
        written[f"feed-{category}"] = path

    blocklist = dist_dir / "blocklist.json"
    dump(blocklist, build_blocklist(entries))
    written["blocklist"] = blocklist

    return written


def _allow_piping_to_head() -> None:
    """Exit quietly when stdout is closed early, e.g. `build.py | head`."""
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def main() -> int:
    _allow_piping_to_head()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--entries", type=Path, default=ENTRIES_DIR)
    parser.add_argument("--dist", type=Path, default=DIST_DIR)
    args = parser.parse_args()

    written = build(args.entries, args.dist)
    feed = json.loads(written["feed"].read_text())
    blocklist = json.loads(written["blocklist"].read_text())
    print(f"OK: {feed['entry_count']} entries, {blocklist['indicator_count']} indicators")
    for label, path in written.items():
        print(f"  {label:28s} {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
