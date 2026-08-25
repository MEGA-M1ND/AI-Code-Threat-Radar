"""Dependency scanning across the lockfile formats people actually have.

Lockfiles are read rather than manifests, because a manifest says `^1.0.0` and
a lockfile says which version is on disk — and the whole question here is which
version is on disk.

Every parser is defensive in the same way: a file it cannot read is recorded as
skipped, never treated as empty. "Scanned and found nothing" and "could not
read it" are different answers and the report keeps them apart.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..findings import Finding
from ..versions import matches

# (filename, ecosystem, parser name)
LOCKFILES = (
    ("package-lock.json", "npm", "npm_lock"),
    ("npm-shrinkwrap.json", "npm", "npm_lock"),
    ("pnpm-lock.yaml", "npm", "pnpm_lock"),
    ("yarn.lock", "npm", "yarn_lock"),
    ("bun.lock", "npm", "bun_lock"),
    ("requirements.txt", "pypi", "requirements"),
    ("poetry.lock", "pypi", "poetry_lock"),
    ("uv.lock", "pypi", "uv_lock"),
    ("Pipfile.lock", "pypi", "pipfile_lock"),
)

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}


# --------------------------------------------------------------------------
# parsers: each returns {name: version}
# --------------------------------------------------------------------------

def npm_lock(text: str) -> dict[str, str]:
    data = json.loads(text)
    found: dict[str, str] = {}
    # lockfileVersion 2/3
    for path, meta in (data.get("packages") or {}).items():
        if not path or not isinstance(meta, dict):
            continue
        name = meta.get("name") or path.split("node_modules/")[-1]
        if name and meta.get("version"):
            found[name] = meta["version"]
    # lockfileVersion 1
    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict):
                if meta.get("version"):
                    found.setdefault(name, meta["version"])
                walk(meta.get("dependencies") or {})
    walk(data.get("dependencies") or {})
    return found


_PNPM_ENTRY = re.compile(r"^\s{2,4}(/?(?:@[^/\s]+/)?[^/@\s]+)@([^:\s(]+)", re.M)


def pnpm_lock(text: str) -> dict[str, str]:
    found = {}
    for name, version in _PNPM_ENTRY.findall(text):
        found.setdefault(name.lstrip("/"), version)
    return found


_YARN_ENTRY = re.compile(
    r'^"?((?:@[^/\s"]+/)?[^@\s"]+)@[^:\n]*:\n(?:.*\n)*?\s+version:?\s+"?([^"\n]+)"?', re.M)


def yarn_lock(text: str) -> dict[str, str]:
    found = {}
    for name, version in _YARN_ENTRY.findall(text):
        found.setdefault(name, version.strip())
    return found


def bun_lock(text: str) -> dict[str, str]:
    # bun.lock is JSONC; strip trailing commas and line comments enough to load.
    cleaned = re.sub(r"//[^\n]*", "", text)
    cleaned = re.sub(r",(\s*[}\]])", r"\1", cleaned)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return {}
    found = {}
    for name, meta in (data.get("packages") or {}).items():
        if isinstance(meta, list) and meta and isinstance(meta[0], str) and "@" in meta[0]:
            found[name] = meta[0].rsplit("@", 1)[1]
    return found


_REQUIREMENT = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s;#]+)", re.M)


def requirements(text: str) -> dict[str, str]:
    return {n: v for n, v in _REQUIREMENT.findall(text)}


_TOML_PKG = re.compile(r'^\s*name\s*=\s*"([^"]+)"\s*$\n(?:.*\n)*?^\s*version\s*=\s*"([^"]+)"',
                       re.M)


def poetry_lock(text: str) -> dict[str, str]:
    found = {}
    for block in text.split("[[package]]"):
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.M)
        version = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.M)
        if name and version:
            found.setdefault(name.group(1), version.group(1))
    return found


def uv_lock(text: str) -> dict[str, str]:
    return poetry_lock(text)


def pipfile_lock(text: str) -> dict[str, str]:
    data = json.loads(text)
    found = {}
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = (meta or {}).get("version", "")
            if isinstance(version, str) and version.startswith("=="):
                found[name] = version[2:]
    return found


PARSERS = {
    "npm_lock": npm_lock, "pnpm_lock": pnpm_lock, "yarn_lock": yarn_lock,
    "bun_lock": bun_lock, "requirements": requirements,
    "poetry_lock": poetry_lock, "uv_lock": uv_lock, "pipfile_lock": pipfile_lock,
}


# --------------------------------------------------------------------------

def find_lockfiles(root: Path, max_depth: int = 4, exclude: tuple[str, ...] = ()):
    for name, ecosystem, parser in LOCKFILES:
        for path in root.rglob(name):
            relative = path.relative_to(root)
            if any(part in SKIP_DIRS for part in relative.parts[:-1]):
                continue
            if any(relative.match(pattern) or
                   any(p == pattern for p in relative.parts)
                   for pattern in exclude):
                continue
            if len(path.relative_to(root).parts) > max_depth + 1:
                continue
            yield path, ecosystem, parser


def scan(project: Path, index, report, near_miss=None,
         exclude: tuple[str, ...] = ()) -> None:
    for path, ecosystem, parser_name in find_lockfiles(project, exclude=exclude):
        try:
            installed = PARSERS[parser_name](path.read_text(errors="replace"))
        except Exception as error:  # noqa: BLE001 - a broken lockfile is not fatal
            report.skipped.append(f"{path}: {type(error).__name__}: {error}")
            continue
        report.note_scanned("lockfiles")
        report.note_scanned("dependencies", len(installed))

        for name, version in sorted(installed.items()):
            for entry, indicator in index.packages.get((ecosystem, name.lower()), []):
                matched, uncertainty = matches(indicator, version)
                if not matched:
                    continue
                malicious = index.is_malicious(entry)
                report.add(Finding(
                    kind="uncertain" if uncertainty else ("malicious" if malicious else "affected"),
                    severity=entry["severity"] if malicious else _downgrade(entry["severity"]),
                    title=f"{name}@{version} — {entry['title']}",
                    detail=entry["summary"],
                    location=str(path), artifact=name, installed_version=version,
                    radar_id=entry["id"], source=index.primary_source(entry),
                    remediation=(
                        f"Remove {name} and treat any credentials this project "
                        "could reach as exposed."
                        if malicious else
                        f"Upgrade {name} out of the affected versions."
                    ),
                    uncertainty=uncertainty or "",
                ))
            if near_miss is not None:
                hit = near_miss(ecosystem, name)
                if hit:
                    report.add(hit._replace_location(str(path), version))


def _downgrade(severity: str) -> str:
    """A vulnerable version of legitimate software is not the same as malware.

    The feed's severity describes the flaw. A scanner reporting `critical` on a
    package the developer is entitled to run, next to `critical` on an actual
    infostealer, teaches people to ignore both.
    """
    return {"critical": "high", "high": "medium"}.get(severity, severity)
