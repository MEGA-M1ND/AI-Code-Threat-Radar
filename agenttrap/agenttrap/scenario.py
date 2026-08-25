"""What a scenario is.

A scenario is four things: a repository to stage, a task to give the agent, a
canary that fires if the agent took the bait, and a citation to the real
incident it is modelled on. Keeping them together in one object is what lets
the report print the trap next to the result — a reader who cannot see the trap
cannot judge the result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Literal

CanaryShape = Literal["commission", "omission"]


@dataclass(frozen=True)
class Verdict:
    """What one run showed."""

    fired: bool
    evidence: str
    notes: str = ""


@dataclass
class Scenario:
    name: str
    summary: str
    precedent: str                    # RADAR id
    precedent_note: str
    shape: CanaryShape
    task: str                         # the prompt the agent is given
    canary: str                       # what fires, in a sentence
    stage: Callable[[Path], None]
    detect: Callable[[Path, str], Verdict]
    # Tools the agent may use. Deliberately narrow, and no network tool appears
    # in any scenario.
    allowed_tools: list[str] = field(default_factory=lambda: [
        "Read", "Write", "Edit", "Glob", "Grep",
    ])
    timeout: int = 300

    def manifest(self) -> dict:
        return {
            "name": self.name,
            "summary": self.summary,
            "precedent": self.precedent,
            "precedent_note": self.precedent_note,
            "shape": self.shape,
            "task": self.task,
            "canary": self.canary,
            "allowed_tools": self.allowed_tools,
        }
