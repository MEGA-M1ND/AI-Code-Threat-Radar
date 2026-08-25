#!/usr/bin/env python3
"""Validate every Rapsheet entry against the schema and the house rules.

Run standalone before opening a pull request:

    python scripts/validate.py

Exits non-zero and names the file and field on the first failure it finds,
after reporting every problem it found.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema" / "entry.schema.json"
ENTRIES_DIR = REPO_ROOT / "data" / "entries"

ID_RE = re.compile(r"^RS-\d{4}-\d{4}$")
# A sentence ends at . ! or ? followed by whitespace-then-capital, or end of string.
SENTENCE_END_RE = re.compile(r"[.!?](?:\s+(?=[A-Z0-9\"'(])|$)")
BANNED_SUMMARY_WORDS = (
    "sophisticated",
    "cutting-edge",
    "comprehensive",
    "devastating",
    "unprecedented",
    "alarming",
    "shocking",
)


class Problem(Exception):
    pass


def load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text())


def load_entries(entries_dir: Path = ENTRIES_DIR) -> list[tuple[Path, dict]]:
    out = []
    for path in sorted(entries_dir.glob("*.json")):
        try:
            out.append((path, json.loads(path.read_text())))
        except json.JSONDecodeError as exc:
            raise Problem(f"{path.name}: not valid JSON: {exc}") from exc
    return out


def count_sentences(text: str) -> int:
    return len([m for m in SENTENCE_END_RE.finditer(text.strip())])


def check_house_rules(path: Path, entry: dict) -> list[str]:
    """Rules the schema cannot express. Returns a list of failures."""
    fails = []
    name = path.name
    entry_id = entry.get("id", "<missing id>")

    if entry_id != path.stem:
        fails.append(f"{name}: field 'id' is {entry_id!r} but the filename says {path.stem!r}")

    summary = entry.get("summary", "")
    n = count_sentences(summary)
    if n > 2:
        fails.append(f"{name}: field 'summary' has {n} sentences, the limit is 2")
    if n == 0 and summary:
        fails.append(f"{name}: field 'summary' does not end in a full stop")
    lowered = summary.lower()
    for word in BANNED_SUMMARY_WORDS:
        if word in lowered:
            fails.append(f"{name}: field 'summary' uses the banned word {word!r}")

    rationale = entry.get("severity_rationale", "")
    if "\n" in rationale:
        fails.append(f"{name}: field 'severity_rationale' must be a single line")

    first_seen = entry.get("first_seen")
    last_updated = entry.get("last_updated")
    if first_seen and last_updated and first_seen > last_updated:
        fails.append(
            f"{name}: field 'first_seen' ({first_seen}) is after 'last_updated' ({last_updated})"
        )

    if entry_id and ID_RE.match(entry_id) and first_seen:
        if entry_id[3:7] != first_seen[:4]:
            fails.append(
                f"{name}: field 'id' year {entry_id[3:7]} does not match "
                f"'first_seen' year {first_seen[:4]}"
            )

    seen_indicators = set()
    for i, ind in enumerate(entry.get("indicators", [])):
        key = json.dumps(ind, sort_keys=True)
        if key in seen_indicators:
            fails.append(f"{name}: indicators[{i}] is a duplicate of an earlier indicator")
        seen_indicators.add(key)

    seen_urls = set()
    for i, src in enumerate(entry.get("sources", [])):
        url = src.get("url")
        if url in seen_urls:
            fails.append(f"{name}: sources[{i}] repeats url {url}")
        seen_urls.add(url)

    return fails


def validate(entries_dir: Path = ENTRIES_DIR, *, quiet: bool = False) -> list[str]:
    """Validate every entry. Returns a list of human-readable failures."""
    schema = load_schema()
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    failures: list[str] = []
    seen_ids: dict[str, str] = {}

    entries = load_entries(entries_dir)
    if not entries:
        failures.append(f"{entries_dir}: no entry files found")

    for path, entry in entries:
        for error in sorted(validator.iter_errors(entry), key=lambda e: list(e.absolute_path)):
            where = "/".join(str(p) for p in error.absolute_path) or "<root>"
            failures.append(f"{path.name}: field '{where}': {error.message}")
        failures.extend(check_house_rules(path, entry))

        entry_id = entry.get("id")
        if entry_id in seen_ids:
            failures.append(f"{path.name}: id {entry_id} already used by {seen_ids[entry_id]}")
        elif entry_id:
            seen_ids[entry_id] = path.name

    if not quiet:
        if failures:
            print(f"FAIL: {len(failures)} problem(s) across {len(entries)} entries", file=sys.stderr)
            for f in failures:
                print(f"  {f}", file=sys.stderr)
        else:
            print(f"OK: {len(entries)} entries valid")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--entries", type=Path, default=ENTRIES_DIR, help="directory of entry JSON files"
    )
    args = parser.parse_args()
    return 1 if validate(args.entries) else 0


if __name__ == "__main__":
    raise SystemExit(main())
