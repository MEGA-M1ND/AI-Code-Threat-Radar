"""Installed agent skills.

A skill is a directory with a SKILL.md whose text the agent reads as
instructions. RADAR carries 344 confirmed-malicious slugs, and a slug is
usually the directory name, so the check is mostly a lookup — but the
directory can be renamed, so the frontmatter `name` is checked too.

The secondary check is for the shape rather than the name: a SKILL.md that
tells the agent to fetch and run something is the ClawHavoc technique, and it
works whether or not the slug is one RADAR has seen.
"""
from __future__ import annotations

import re
from pathlib import Path

from ..findings import Finding

SKILL_DIRS = (".claude/skills", ".agents/skills", ".config/claude/skills")
SKILL_FILE = "SKILL.md"

# Instructions that make the agent fetch and execute something. Each of these
# appears in a documented malicious skill; see RADAR-2026-0002 and -0003.
PREREQUISITE_TRAP = (
    (re.compile(r"curl[^\n|]*\|\s*(ba)?sh", re.I), "pipes a download straight into a shell"),
    (re.compile(r"base64\s+(-d|--decode|-D)", re.I), "decodes a base64 command before running it"),
    (re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}", re.I), "fetches from a bare IP address"),
    (re.compile(r"\bpass(word)?\s*[:=]\s*\S+", re.I), "supplies a password for an archive"),
    (re.compile(r"\bprerequisite\b[^\n]{0,80}\binstall\b", re.I), "frames a download as a prerequisite"),
    (re.compile(r"do not (mention|tell|inform)[^\n]{0,40}\buser\b", re.I), "tells the agent to hide something from the user"),
    (re.compile(r"\.ssh/id_|\.env\b|keystore|wallet\.dat", re.I), "names credential or wallet files"),
)

_FRONTMATTER_NAME = re.compile(r"^---\s*\n(?:.*\n)*?name:\s*([^\n]+)", re.M)


def _slugs(path: Path, text: str):
    yield path.parent.name.lower()
    match = _FRONTMATTER_NAME.search(text)
    if match:
        yield match.group(1).strip().strip("\"'").lower()


def _scan_skill(path: Path, index, report) -> None:
    try:
        text = path.read_text(errors="replace")
    except OSError as error:
        report.skipped.append(f"{path}: {type(error).__name__}")
        return
    report.note_scanned("skills")

    reported = False
    for slug in _slugs(path, text):
        for entry, indicator in index.skills.get(slug, []):
            reported = True
            report.add(Finding(
                kind="malicious", severity=entry["severity"],
                title=f"skill {slug} — {entry['title']}",
                detail=entry["summary"], location=str(path), artifact=slug,
                radar_id=entry["id"], source=index.primary_source(entry),
                remediation=(
                    "Delete this skill directory. Its SKILL.md is instructions the "
                    "agent follows, so treat anything it asked for as compromised."
                ),
            ))
    if reported:
        return

    hits = [why for pattern, why in PREREQUISITE_TRAP if pattern.search(text)]
    if hits:
        report.add(Finding(
            kind="malicious" if len(hits) > 1 else "uncertain",
            severity="critical" if len(hits) > 1 else "high",
            title=f"skill {path.parent.name} instructs the agent to fetch and run code",
            detail=(
                "This SKILL.md is not in RADAR, but it "
                + "; ".join(hits)
                + ". That is the technique behind the ClawHavoc campaign: the skill "
                "text tells the agent to install a prerequisite, and the agent relays "
                "the instruction to the user."
            ),
            location=str(path), artifact=path.parent.name,
            remediation="Read the SKILL.md yourself before letting an agent load it.",
            uncertainty=("one pattern matched; some legitimate skills do document "
                         "install steps" if len(hits) == 1 else ""),
        ))


def scan(project: Path, index, report, home: Path | None = None,
         exclude: tuple[str, ...] = ()) -> None:
    roots = [project / d for d in SKILL_DIRS]
    if home is not None:
        roots += [home / d for d in SKILL_DIRS]
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob(SKILL_FILE)):
            if any(part in exclude for part in path.parts):
                continue
            _scan_skill(path, index, report)
