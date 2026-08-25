"""MCP server configuration, wherever the agent keeps it.

An MCP server is a process the agent starts and trusts. It is configured in a
JSON file, often committed, and nothing installs it in a way a dependency
scanner would notice — the command may be an `npx` invocation resolved at run
time. So this reads the config files directly and checks three things: the
server name against the feed, the package in its command line, and the host it
talks to.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..findings import Finding
from ..versions import matches

# Relative to the project.
PROJECT_CONFIGS = (
    ".mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".claude/settings.json",
    ".claude/settings.local.json",
)
# Relative to home. Paths differ per platform; all are tried and missing ones
# are simply absent rather than an error.
HOME_CONFIGS = (
    ".claude.json",
    ".claude/settings.json",
    ".cursor/mcp.json",
    ".codeium/windsurf/mcp_config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    ".config/Claude/claude_desktop_config.json",
    "AppData/Roaming/Claude/claude_desktop_config.json",
)

# `npx -y some-package@1.2.3` / `uvx some-package`
_PACKAGE_ARG = re.compile(r"^(?:@[^/\s]+/)?[A-Za-z0-9._-]+(?:@([^\s]+))?$")
_RUNNERS = {"npx": "npm", "bunx": "npm", "pnpx": "npm", "uvx": "pypi", "pipx": "pypi"}


def _servers(document: dict):
    """Yield (name, config) from any of the shapes these files take."""
    for key in ("mcpServers", "mcp_servers", "servers"):
        block = document.get(key)
        if isinstance(block, dict):
            for name, config in block.items():
                if isinstance(config, dict):
                    yield name, config
    # Claude Code's settings.json nests per-project state.
    projects = document.get("projects")
    if isinstance(projects, dict):
        for project in projects.values():
            if isinstance(project, dict):
                yield from _servers(project)


def _package_from_command(config: dict) -> tuple[str, str, str] | None:
    """(ecosystem, package, version) if the command runs a registry package."""
    command = str(config.get("command") or "")
    runner = _RUNNERS.get(Path(command).name)
    if not runner:
        return None
    for argument in config.get("args") or []:
        text = str(argument)
        if text.startswith("-"):
            continue
        match = _PACKAGE_ARG.match(text)
        if match:
            name = text.split("@")[0] if not text.startswith("@") else "@" + text[1:].split("@")[0]
            return runner, name, match.group(1) or ""
    return None


def _hosts(config: dict):
    for key in ("url", "endpoint", "serverUrl"):
        value = config.get(key)
        if isinstance(value, str) and "://" in value:
            yield value.split("://", 1)[1].split("/")[0].split(":")[0].lower()


def _scan_file(path: Path, index, report) -> None:
    try:
        document = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        report.skipped.append(f"{path}: {type(error).__name__}")
        return
    if not isinstance(document, dict):
        return
    report.note_scanned("MCP config files")

    for name, config in _servers(document):
        report.note_scanned("MCP servers")

        for entry, indicator in index.mcp_servers.get(name.lower(), []):
            report.add(_finding(entry, indicator, index, path, name, "", "MCP server"))

        package = _package_from_command(config)
        if package:
            ecosystem, pkg_name, version = package
            for entry, indicator in index.packages.get((ecosystem, pkg_name.lower()), []):
                matched, uncertainty = matches(indicator, version) if version else (True, None)
                if matched:
                    report.add(_finding(entry, indicator, index, path, pkg_name,
                                        version, "MCP server package", uncertainty))

        for host in _hosts(config):
            for entry, indicator in index.domains.get(host, []):
                report.add(_finding(entry, indicator, index, path, host, "",
                                    "MCP server endpoint"))


def _finding(entry, indicator, index, path, artifact, version, what, uncertainty=None):
    malicious = index.is_malicious(entry)
    return Finding(
        kind="uncertain" if uncertainty else ("malicious" if malicious else "affected"),
        severity=entry["severity"],
        title=f"{what} {artifact} — {entry['title']}",
        detail=entry["summary"], location=str(path), artifact=artifact,
        installed_version=version, radar_id=entry["id"],
        source=index.primary_source(entry),
        remediation=(
            f"Remove this server from the configuration. An MCP server runs as a "
            f"process the agent trusts, so treat anything it could reach as exposed."
            if malicious else
            f"Check the affected versions for {artifact} before continuing to use it."
        ),
        uncertainty=uncertainty or "",
    )


def scan(project: Path, index, report, home: Path | None = None) -> None:
    for relative in PROJECT_CONFIGS:
        path = project / relative
        if path.is_file():
            _scan_file(path, index, report)
    if home is not None:
        for relative in HOME_CONFIGS:
            path = home / relative
            if path.is_file():
                _scan_file(path, index, report)
