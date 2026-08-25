"""The collector workflow's job is to be unable to publish.

A daily cron with write access, running code that reads attacker-controlled
registry data, is the highest-privilege thing in this repo. These tests assert
the properties that keep it boring: it cannot reach the feed, it cannot ask for
more permission than it needs, and it cannot be talked into running something
else by the contents of a workflow input.
"""
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/radar-collect.yml"
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def workflow():
    return yaml.safe_load(WORKFLOW.read_text())


@pytest.fixture(scope="module")
def steps(workflow):
    return workflow["jobs"]["collect"]["steps"]


def test_the_workflow_exists():
    assert WORKFLOW.exists()


def test_permissions_are_explicit_and_minimal(workflow):
    """No token scope beyond opening a pull request against its own repo."""
    assert workflow["permissions"] == {"contents": "write", "pull-requests": "write"}


def test_every_action_is_pinned_to_a_commit(steps):
    """A tag can be moved; a commit cannot."""
    for step in steps:
        if "uses" not in step:
            continue
        _, _, ref = step["uses"].partition("@")
        assert SHA_RE.match(ref), f"{step['uses']} is not pinned to a SHA"


def test_it_refuses_to_open_a_pr_if_the_feed_changed(steps):
    """The one structural guarantee: a collector cannot publish."""
    guard = next((s for s in steps if "Refuse" in (s.get("name") or "")), None)
    assert guard is not None, "no guard step"
    for path in ("data", "dist", "schema", "scripts"):
        assert path in guard["run"], f"the guard does not cover {path}/"
    assert "exit 1" in guard["run"]


def test_workflow_inputs_never_reach_a_shell_directly(steps):
    """`${{ inputs.x }}` inside run: is a command injection. Via env: it is a string."""
    for step in steps:
        run = step.get("run")
        if run:
            assert "inputs." not in run, f"step {step.get('name')!r} interpolates an input"


def test_the_only_input_is_a_closed_choice(workflow):
    """A free-text collector name is a value the runner would have to trust."""
    only = workflow[True]["workflow_dispatch"]["inputs"]["only"]
    assert only["type"] == "choice"
    from collectors.run import COLLECTORS
    assert set(only["options"]) - {""} == set(COLLECTORS)


def test_the_branch_is_checked_out_before_the_collectors_run(steps):
    """Switching branches with a tree full of fresh candidates conflicts."""
    names = [s.get("name") or s.get("uses", "") for s in steps]
    switch = next(i for i, n in enumerate(names) if "triage branch" in n)
    run = next(i for i, n in enumerate(names) if n == "Run collectors")
    assert switch < run


def test_the_watchlist_is_refreshed_before_the_collectors_run(steps):
    """The watchlist is derived from the feed; a stale one scores against
    yesterday's list of legitimate names."""
    names = [s.get("name") or s.get("uses", "") for s in steps]
    assert names.index("Refresh the watchlist") < names.index("Run collectors")
    assert names.index("Build the feed") < names.index("Refresh the watchlist")


def test_runs_are_not_allowed_to_overlap(workflow):
    """Two runs sharing collector state would fight over the same cursors."""
    assert workflow["concurrency"]["group"]
    assert workflow["concurrency"]["cancel-in-progress"] is False
