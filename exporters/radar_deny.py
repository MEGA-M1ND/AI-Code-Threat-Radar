"""radar-deny.json — the generic format RADAR proposes for runtime guards.

Every guard in this space carries its own hand-maintained blocklist and its own
schema for it. `blocklist.json` already ships RADAR's indicators, but it mirrors
the entry schema: nested `affected` objects, indicator types a scanner has to
branch on, and no statement of what to *do* with a match.

This is the flattened form, and the one thing it adds is the decision. Each row
says `block`, `warn` or `monitor`, and says why, so a guard can act without
re-deriving the semantics of seven categories. See exporters/common.py for how
that call is made — it is the part worth disagreeing with, so it is written
down rather than buried in a severity comparison.

Nothing here is specific to RADAR's internals: the format is offered for other
feeds to emit and other guards to read.
"""
from __future__ import annotations

from .common import decide_action, indicator_value

FORMAT_VERSION = "1.0.0"

# Which indicator types a scanner can match against what it sees.
SCAN_SURFACE = {
    "package": "dependency manifests and lockfiles",
    "application": "installed applications",
    "mcp-server": "MCP server configuration",
    "skill": "installed agent skills",
    "hash": "file contents",
    "domain": "outbound network destinations",
    "ip": "outbound network destinations",
    "url": "outbound network destinations",
}


def _row(entry: dict, indicator: dict, source: str) -> dict:
    action, why = decide_action(entry, indicator)
    row = {
        "action": action,
        "action_reason": why,
        "type": indicator["type"],
        "value": indicator_value(indicator),
        "surface": SCAN_SURFACE.get(indicator["type"], "unknown"),
        "severity": entry["severity"],
        "category": entry["category"],
        "status": entry["status"],
        "radar_id": entry["id"],
        "source": source,
    }
    if indicator.get("registry"):
        row["ecosystem"] = indicator["registry"]
    if indicator.get("marketplace"):
        row["marketplace"] = indicator["marketplace"]
    if indicator.get("algo"):
        row["hash_algorithm"] = indicator["algo"]
    if indicator.get("port"):
        row["port"] = indicator["port"]

    # Versions are the difference between a useful match and a false positive,
    # so they are flattened into one place a scanner can read without branching.
    versions = _versions(indicator)
    if versions:
        row["versions"] = versions
    ranges = (indicator.get("affected") or {}).get("ranges")
    if ranges:
        row["version_ranges"] = ranges
    if indicator.get("version"):
        row["version_note"] = indicator["version"]
    row["all_versions"] = not versions and not ranges
    return row


def _versions(indicator: dict) -> list[str]:
    return list((indicator.get("affected") or {}).get("versions") or [])


def _sort_key(row: dict) -> tuple:
    return (row["type"], row.get("ecosystem", ""), row["value"], row["radar_id"])


def build_radar_deny(feed: dict) -> dict:
    """Flatten a RADAR feed into deny rules. Pure function of `feed`."""
    from scripts.build_feed import primary_source  # local import: no cycle at module load

    rows = [
        _row(entry, indicator, primary_source(entry))
        for entry in feed["entries"]
        for indicator in entry["indicators"]
    ]
    rows.sort(key=_sort_key)

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["action"]] = counts.get(row["action"], 0) + 1

    return {
        "format": "radar-deny",
        "format_version": FORMAT_VERSION,
        "spec": f"{feed['homepage']}/blob/main/docs/consumers.md#radar-denyjson",
        "producer": feed["feed"],
        "producer_homepage": feed["homepage"],
        "license": feed["license"],
        "attribution": feed["attribution"],
        "last_updated": feed["last_updated"],
        "actions": {
            "block": "do not install or load this artifact",
            "warn": "match, report, and let the user decide",
            "monitor": "record a match; not a live threat",
        },
        "rule_count": len(rows),
        "action_counts": dict(sorted(counts.items())),
        "rules": rows,
    }
