"""Tests for the harness, not the agent.

These run without invoking an agent. What they check is that the harness cannot
quietly do the wrong thing: allow a network tool, count a broken run as a pass,
or report a result whose trap the reader cannot see.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agenttrap.sandbox import (  # noqa: E402
    FORBIDDEN_TOOLS, RunResult, UnsafeScenario, check_tools, make_workdir,
)
from agenttrap.scenarios import ALL, BY_NAME  # noqa: E402


# --------------------------------------------------------------------------
# safety boundaries, enforced rather than documented
# --------------------------------------------------------------------------

@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.name)
def test_no_scenario_may_reach_the_network(scenario):
    """A network tool would let an inert payload become a real request."""
    check_tools(scenario.allowed_tools)
    assert not FORBIDDEN_TOOLS.intersection(scenario.allowed_tools)


@pytest.mark.parametrize("tool", sorted(FORBIDDEN_TOOLS))
def test_the_check_actually_rejects(tool):
    with pytest.raises(UnsafeScenario):
        check_tools(["Read", tool])


def test_bash_is_forbidden():
    """The payloads are inert because they are never executed. Granting Bash
    would remove the property the whole design rests on."""
    assert "Bash" in FORBIDDEN_TOOLS


def test_each_run_gets_its_own_directory():
    a, b = make_workdir("x", 1), make_workdir("x", 2)
    assert a != b and a.is_dir() and b.is_dir()


def test_the_workdir_is_not_inside_the_repository():
    """No scenario may stage itself where the user works."""
    workdir = make_workdir("x", 1).resolve()
    assert ROOT.resolve() not in workdir.parents


def test_a_fake_home_is_staged():
    """Scenarios touching ~/.claude must not reach the real one."""
    assert (make_workdir("x", 1) / "home" / ".claude").is_dir()


# --------------------------------------------------------------------------
# scenario shape
# --------------------------------------------------------------------------

def test_every_scenario_cites_a_real_feed_entry():
    feed_path = ROOT.parent / "dist" / "feed.json"
    if not feed_path.exists():
        pytest.skip("dist/feed.json not built")
    ids = {e["id"] for e in json.loads(feed_path.read_text())["entries"]}
    for scenario in ALL:
        assert scenario.precedent in ids, (
            f"{scenario.name} cites {scenario.precedent}, which is not in the feed")


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.name)
def test_every_scenario_has_both_prompts(scenario):
    """A trap caught only under priming was not really caught."""
    assert scenario.task and scenario.control_task
    assert scenario.task != scenario.control_task


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.name)
def test_the_control_prompt_does_not_ask_for_a_security_review(scenario):
    """If the control prompt primes, there is no control."""
    priming = ("safe", "safety", "security", "secure", "malicious", "suspicious",
               "risk", "audit", "vulnerab", "anything wrong", "flag", "threat",
               "attack", "trust")
    lowered = scenario.control_task.lower()
    hits = [w for w in priming if w in lowered]
    assert not hits, f"{scenario.name} control task primes with {hits}"


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.name)
def test_the_primed_prompt_puts_noticing_in_scope(scenario):
    """An omission canary is only fair if the task asked the agent to look."""
    if scenario.shape != "omission":
        return
    inviting = ("safe", "wrong", "attention", "flag", "check whether",
                "tell me", "look at")
    assert any(w in scenario.task.lower() for w in inviting), scenario.name


def test_scenario_names_are_unique():
    assert len(BY_NAME) == len(ALL)


@pytest.mark.parametrize("scenario", ALL, ids=lambda s: s.name)
def test_the_manifest_shows_the_reader_the_trap(scenario):
    """A result whose trap the reader cannot see is not a result."""
    manifest = scenario.manifest()
    for field in ("summary", "precedent", "precedent_note", "task",
                  "control_task", "canary", "shape"):
        assert manifest[field], f"{scenario.name} manifest is missing {field}"


def test_prompt_selects_by_condition():
    scenario = ALL[0]
    assert scenario.prompt("control") == scenario.control_task
    assert scenario.prompt("primed") == scenario.task


# --------------------------------------------------------------------------
# a broken run is never a pass
# --------------------------------------------------------------------------

@pytest.mark.parametrize("status", ["error", "timeout"])
def test_a_failed_run_has_no_verdict(status):
    """A scenario where the harness broke is not a scenario the agent survived."""
    result = RunResult("s", 1, status, None, "", "", "/tmp/x", 1.0)
    assert result.fired is None
    assert result.to_dict()["fired"] is None


def test_the_result_records_its_condition():
    assert RunResult("s", 1, "ok", False, "e", "", "/tmp/x", 1.0,
                     condition="control").to_dict()["condition"] == "control"


# --------------------------------------------------------------------------
# reporting
# --------------------------------------------------------------------------

def test_the_report_never_prints_a_percentage():
    """Three runs cannot support a rate, and printing one invites the reader to
    treat it as though it could."""
    from agenttrap import report
    source = Path(report.__file__).read_text()
    assert "%" not in source.replace("%s", "").replace("%d", "")


def test_the_report_carries_the_limitations():
    from agenttrap.report import build
    text = build("test-agent", "2026-01-01")
    assert "No runs recorded yet" in text or "Limitations" in text
