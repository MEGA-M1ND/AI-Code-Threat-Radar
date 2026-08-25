"""Running scenarios and recording what happened.

A harness failure is recorded as `error`, never dropped and never counted as a
pass. A scenario where the harness broke is not a scenario the agent survived,
and a report that cannot tell those apart is worth nothing.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .sandbox import RunResult, cleanup, make_workdir, run_agent
from .scenario import Scenario

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
RUNS_DIR = RESULTS_DIR / "runs"


def agent_version() -> str:
    try:
        out = subprocess.run(["claude", "--version"], capture_output=True,
                             text=True, timeout=30)
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001
        return "unknown"


def run_once(scenario: Scenario, run: int, keep: bool = False) -> RunResult:
    workdir = make_workdir(scenario.name, run)
    (workdir / "project").mkdir(parents=True, exist_ok=True)
    try:
        scenario.stage(workdir)
    except Exception as error:  # noqa: BLE001
        return RunResult(scenario.name, run, "error", None, "", "",
                         str(workdir), 0.0, f"staging failed: {error}")

    status, text, elapsed = run_agent(
        workdir, scenario.task, scenario.allowed_tools, scenario.timeout)

    if status != "ok":
        # Keep the directory: an error is the case most worth inspecting.
        return RunResult(scenario.name, run, status, None, "", text,
                         str(workdir), elapsed,
                         detail=f"agent returned {status}")

    try:
        verdict = scenario.detect(workdir, text)
    except Exception as error:  # noqa: BLE001
        return RunResult(scenario.name, run, "error", None, "", text,
                         str(workdir), elapsed, f"detection failed: {error}")

    result = RunResult(scenario.name, run, "ok", verdict.fired, verdict.evidence,
                       text, str(workdir), elapsed, verdict.notes)
    cleanup(workdir, keep or verdict.fired)
    return result


def save(result: RunResult) -> Path:
    RUNS_DIR.mkdir(parents=True, exist_ok=True)
    path = RUNS_DIR / f"{result.scenario}-{result.run:02d}.json"
    path.write_text(json.dumps(
        {**result.to_dict(), "transcript": result.transcript},
        indent=2, ensure_ascii=False) + "\n")
    return path


def load_all() -> list[dict]:
    if not RUNS_DIR.is_dir():
        return []
    return [json.loads(p.read_text()) for p in sorted(RUNS_DIR.glob("*.json"))]
