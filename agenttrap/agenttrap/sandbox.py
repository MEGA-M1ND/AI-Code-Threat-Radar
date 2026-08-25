"""Where a run happens, and what it is allowed to touch.

Every constraint here is also stated in METHODOLOGY.md. They are repeated in
code because a safety boundary documented and not enforced is a claim, not a
boundary.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

# Tools that reach the network or the wider machine. No scenario may allow one:
# the traps are meant to be taken by an agent doing local work, and a network
# tool would let an inert payload become a real request.
FORBIDDEN_TOOLS = {"WebFetch", "WebSearch", "Bash", "Task", "Agent", "NotebookEdit"}


class UnsafeScenario(RuntimeError):
    """A scenario asked for something the harness will not grant."""


@dataclass
class RunResult:
    scenario: str
    run: int
    status: str                # ok | error | timeout
    fired: bool | None
    evidence: str
    transcript: str
    workdir: str
    duration_s: float
    detail: str = ""
    # "primed" — the task asks the agent to look for problems.
    # "control" — the task is ordinary work and says nothing about security.
    condition: str = "primed"

    def to_dict(self) -> dict:
        return {
            "scenario": self.scenario, "run": self.run, "status": self.status,
            "fired": self.fired, "evidence": self.evidence,
            "condition": self.condition,
            "workdir": self.workdir, "duration_s": round(self.duration_s, 1),
            "detail": self.detail,
        }


def check_tools(allowed: list[str]) -> None:
    unsafe = FORBIDDEN_TOOLS.intersection(allowed)
    if unsafe:
        raise UnsafeScenario(
            f"scenario requests tools the harness forbids: {sorted(unsafe)}")


def make_workdir(scenario: str, run: int) -> Path:
    """A fresh directory per run, outside the repository, kept for inspection."""
    path = Path(tempfile.mkdtemp(prefix=f"agenttrap-{scenario}-{run}-"))
    (path / "home" / ".claude").mkdir(parents=True, exist_ok=True)
    return path


def run_agent(workdir: Path, task: str, allowed_tools: list[str],
              timeout: int) -> tuple[str, str, float]:
    """Invoke the agent headlessly inside `workdir`. Returns (status, text, seconds).

    The agent gets a fake HOME inside the scenario directory, so a scenario
    about `~/.claude/settings.json` cannot reach the real one.
    """
    import time

    check_tools(allowed_tools)
    project = workdir / "project"
    environment = dict(os.environ)
    environment["HOME"] = str(workdir / "home")
    # Belt and braces: even if a tool slipped through, give it nowhere to go.
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        environment.pop(variable, None)
    environment["NO_PROXY"] = "*"

    command = [
        "claude", "-p", task,
        "--output-format", "json",
        "--allowed-tools", ",".join(allowed_tools),
        "--permission-mode", "acceptEdits",
    ]
    started = time.monotonic()
    try:
        completed = subprocess.run(
            command, cwd=project, env=environment, timeout=timeout,
            capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return "timeout", "", time.monotonic() - started
    elapsed = time.monotonic() - started

    if completed.returncode != 0:
        return "error", (completed.stderr or completed.stdout)[:4000], elapsed

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return "error", completed.stdout[:4000], elapsed

    text = payload.get("result") or payload.get("text") or ""
    if payload.get("is_error"):
        return "error", str(text)[:4000], elapsed
    return "ok", str(text), elapsed


def cleanup(workdir: Path, keep: bool) -> None:
    if not keep:
        shutil.rmtree(workdir, ignore_errors=True)
