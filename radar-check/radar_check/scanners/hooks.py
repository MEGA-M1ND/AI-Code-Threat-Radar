"""Agent-config hooks — the check nothing else does.

Two entries in RADAR establish this as a live technique rather than a
hypothetical. In RADAR-2026-0007 a compromised npm package globbed the
filesystem for `settings.json` and wrote a `SessionStart` hook into every one it
found. In RADAR-2026-0015, five packages shipped `.claude/settings.json` inside
the tarball with a hook pointing at a 4.5 MB ELF beside it.

What makes it worth a dedicated scanner: **the hook outlives the package that
installed it.** Uninstalling the dependency, deleting node_modules, even
rebuilding the lockfile leaves the hook in place, and it runs on every agent
session start. A dependency scanner that only reads lockfiles reports the
machine clean.

This scanner cannot know whether you configured a hook yourself, so it does not
claim to. It reports what runs automatically and where it came from, ranks the
shapes that are known-bad higher, and leaves the judgement to the reader.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from ..findings import Finding

# Settings files an agent reads on startup, relative to a project or to home.
PROJECT_SETTINGS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".vscode/tasks.json",
)
HOME_SETTINGS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
)

# Hook events that fire without the user doing anything. A PreToolUse hook at
# least runs in response to an action; these run because the agent started.
UNPROMPTED_EVENTS = {"SessionStart", "SessionEnd", "Notification"}

# Command shapes that have appeared in real payloads, or that no legitimate
# hook needs. Matching one raises the severity; matching none does not clear it.
SUSPICIOUS_COMMAND = re.compile(
    r"curl\s|wget\s|\|\s*(ba)?sh\b|base64\s+(-d|--decode)|"
    r"eval\s|python\s+-c|node\s+-e|Invoke-WebRequest|IEX\s|"
    r"\.claude/settings\b|/tmp/|chmod\s+\+x",
    re.IGNORECASE,
)


def _iter_hooks(settings: dict):
    """Yield (event, command, is_unprompted) from a settings document."""
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict):
                continue
            for hook in group.get("hooks") or []:
                if isinstance(hook, dict) and hook.get("command"):
                    yield event, str(hook["command"]), event in UNPROMPTED_EVENTS


def _scan_file(path: Path, report) -> None:
    try:
        settings = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        report.skipped.append(f"{path}: {type(error).__name__}")
        return
    if not isinstance(settings, dict):
        return
    report.note_scanned("agent settings files")

    for event, command, unprompted in _iter_hooks(settings):
        suspicious = SUSPICIOUS_COMMAND.search(command)
        if suspicious and unprompted:
            severity, detail = "critical", (
                f"A {event} hook runs `{command}` every time an agent session "
                f"starts, and the command matches a pattern seen in real "
                f"payloads ({suspicious.group(0).strip()!r})."
            )
        elif unprompted:
            severity, detail = "medium", (
                f"A {event} hook runs `{command}` every time an agent session "
                f"starts. This is a normal thing to configure deliberately."
            )
        elif suspicious:
            severity, detail = "high", (
                f"A {event} hook runs `{command}`, which matches a pattern seen "
                f"in real payloads ({suspicious.group(0).strip()!r})."
            )
        else:
            continue

        report.add(Finding(
            kind="hook", severity=severity,
            title=f"{event} hook in {path.name}",
            detail=detail, location=str(path), artifact=command[:120],
            remediation=(
                "If you did not add this hook, remove it. Removing the package "
                "that installed it does not remove the hook — that is the point "
                "of the technique. See RADAR-2026-0007 and RADAR-2026-0015."
            ),
            uncertainty="only you know whether you configured this",
        ))

    # A tasks.json folderOpen task is the VS Code equivalent and was used by the
    # same payload; it is not a "hook" in the settings sense.
    for task in settings.get("tasks") or []:
        if not isinstance(task, dict):
            continue
        run_on = (task.get("runOptions") or {}).get("runOn")
        if run_on == "folderOpen":
            command = str(task.get("command", ""))
            report.add(Finding(
                kind="hook",
                severity="critical" if SUSPICIOUS_COMMAND.search(command) else "medium",
                title="Task runs on folderOpen",
                detail=f"`{command}` runs whenever this folder is opened in VS Code.",
                location=str(path), artifact=command[:120],
                remediation="Remove the task if you did not add it. See RADAR-2026-0007.",
                uncertainty="only you know whether you configured this",
            ))


def scan(project: Path, report, home: Path | None = None) -> None:
    for relative in PROJECT_SETTINGS:
        path = project / relative
        if path.is_file():
            _scan_file(path, report)
    if home is not None:
        for relative in HOME_SETTINGS:
            path = home / relative
            if path.is_file():
                _scan_file(path, report)
