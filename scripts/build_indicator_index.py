#!/usr/bin/env python3
"""Rebuild the `indicator_index` block in backend/data/feed.json.

The indicator index maps each indicator string (a package name, malicious
version specifier, domain, etc.) to the list of entry IDs that reference it.
The Exposure Checker (frontend) uses this map to look up known threats from a
pasted dependency list or config.

This is derived programmatically from the `indicators` field of every entry so
it never has to be hand-maintained. Run it any time entries change:

    python scripts/build_indicator_index.py

By default it rewrites feed.json in place (preserving key order, with
`indicator_index` sorted for stable diffs). Use --check to verify the file is
up to date without writing (useful in CI) — it exits non-zero if stale.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import OrderedDict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FEED_PATH = REPO_ROOT / "backend" / "data" / "feed.json"


def build_indicator_index(entries: list[dict]) -> "OrderedDict[str, list[str]]":
    """Map indicator -> sorted, de-duplicated list of entry IDs referencing it."""
    index: dict[str, set[str]] = {}
    for entry in entries:
        entry_id = entry.get("id")
        if not entry_id:
            continue
        for indicator in entry.get("indicators", []) or []:
            if not isinstance(indicator, str) or not indicator.strip():
                continue
            index.setdefault(indicator, set()).add(entry_id)

    # Deterministic ordering: indicators alphabetically, IDs sorted within each.
    return OrderedDict(
        (indicator, sorted(index[indicator])) for indicator in sorted(index)
    )


def load_feed() -> "OrderedDict[str, object]":
    with FEED_PATH.open("r", encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=OrderedDict)


def render_feed(feed: "OrderedDict[str, object]") -> str:
    return json.dumps(feed, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify feed.json is up to date without writing; exit 1 if stale.",
    )
    args = parser.parse_args()

    feed = load_feed()
    entries = feed.get("entries", [])
    new_index = build_indicator_index(entries)

    updated = OrderedDict(feed)
    updated["indicator_index"] = new_index

    new_text = render_feed(updated)
    current_text = FEED_PATH.read_text(encoding="utf-8")

    if args.check:
        if new_text != current_text:
            print(
                "feed.json indicator_index is stale. "
                "Run: python scripts/build_indicator_index.py",
                file=sys.stderr,
            )
            return 1
        print("feed.json indicator_index is up to date.")
        return 0

    FEED_PATH.write_text(new_text, encoding="utf-8")
    print(
        f"Wrote indicator_index with {len(new_index)} indicator(s) "
        f"from {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
