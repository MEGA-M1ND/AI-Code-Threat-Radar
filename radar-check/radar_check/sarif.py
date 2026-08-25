"""SARIF 2.1.0 output, so findings land in GitHub code scanning.

The mapping that matters: RADAR's `low` is not SARIF's `note` when the finding
is malware. SARIF levels are error/warning/note/none and there are only three
useful ones, so severity is carried in `properties` for anything that reads it
and collapsed sensibly for anything that does not.
"""
from __future__ import annotations

from pathlib import Path

from .findings import Finding, ScanReport

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
VERSION = "2.1.0"

# A malicious artifact is an error whatever its severity; a resemblance is a
# note. Anything else follows severity.
LEVEL_BY_KIND = {"malicious": "error", "near-miss": "note"}
LEVEL_BY_SEVERITY = {"critical": "error", "high": "error", "medium": "warning",
                     "low": "note", "info": "note"}

RULES = {
    "radar/malicious": ("Malicious artifact",
                        "An artifact RADAR documents as malicious is present."),
    "radar/affected": ("Affected version",
                       "Legitimate software at a version RADAR records as affected."),
    "radar/near-miss": ("Name resembles a tracked package",
                        "A dependency name is one edit from a package RADAR tracks."),
    "radar/hook": ("Automatic execution configured",
                   "A hook or task runs code without the user initiating it."),
    "radar/uncertain": ("Match needs a human",
                        "Matched, but something could not be determined automatically."),
}


def _level(finding: Finding) -> str:
    return LEVEL_BY_KIND.get(finding.kind) or LEVEL_BY_SEVERITY[finding.severity]


def _uri(location: str, root: Path) -> str:
    try:
        return Path(location).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(location).as_posix()


def build(report: ScanReport, root: Path, version: str) -> dict:
    findings = report.sorted()
    used = sorted({f.rule_id for f in findings})
    return {
        "$schema": SCHEMA,
        "version": VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "radar-check",
                "version": version,
                "informationUri": "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar",
                "rules": [{
                    "id": rule_id,
                    "name": RULES[rule_id][0],
                    "shortDescription": {"text": RULES[rule_id][0]},
                    "fullDescription": {"text": RULES[rule_id][1]},
                    "helpUri": "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/blob/main/docs/FEED.md",
                } for rule_id in used],
            }},
            "properties": {
                "feedOrigin": report.feed_origin,
                "feedLastUpdated": report.feed_last_updated,
                "entryCount": report.entry_count,
            },
            "results": [{
                "ruleId": finding.rule_id,
                "level": _level(finding),
                "message": {"text": _message(finding)},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": _uri(finding.location, root)},
                    "region": {"startLine": finding.line},
                }}],
                "properties": {
                    "severity": finding.severity,
                    "kind": finding.kind,
                    "artifact": finding.artifact,
                    "installedVersion": finding.installed_version,
                    "radarId": finding.radar_id,
                    "source": finding.source,
                    **({"uncertainty": finding.uncertainty} if finding.uncertainty else {}),
                },
            } for finding in findings],
        }],
    }


def _message(finding: Finding) -> str:
    parts = [finding.title, finding.detail]
    if finding.uncertainty:
        parts.append(f"Uncertain: {finding.uncertainty}.")
    if finding.remediation:
        parts.append(finding.remediation)
    if finding.source:
        parts.append(f"Source: {finding.source}")
    return " ".join(p for p in parts if p)
