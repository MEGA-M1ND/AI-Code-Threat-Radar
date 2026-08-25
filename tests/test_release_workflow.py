"""The release workflow must not enumerate what the build produces.

radar-v0.1.0 shipped without feed-malicious-package.json: the build emitted it,
SHA256SUMS listed it, and the workflow's hand-written file list — written when
there were six categories — did not mention it. Nothing failed, because nothing
was checking. These tests check.
"""
import re
from pathlib import Path

import build_feed as B

WORKFLOW = Path(__file__).resolve().parent.parent / ".github/workflows/radar-release.yml"


def workflow_text() -> str:
    return WORKFLOW.read_text()


def test_release_workflow_exists():
    assert WORKFLOW.exists(), "the release workflow is what publishes the feed"


def test_release_does_not_enumerate_category_feeds():
    """One `dist/feed-<category>.json` per line is the shape of the bug."""
    enumerated = re.findall(r"dist/feed-[a-z-]+\.json", workflow_text())
    assert not enumerated, (
        "the workflow names per-category feeds explicitly: "
        f"{sorted(set(enumerated))}. Glob dist/*.json instead — an explicit list "
        "silently drops the next category someone adds."
    )


def test_release_globs_the_dist_directory():
    assert "dist/*.json" in workflow_text()


def test_release_checks_the_category_count():
    """A belt-and-braces guard inside the job itself."""
    text = workflow_text()
    assert "build_feed.CATEGORIES" in text
    assert "per-category feeds, found" in text


def test_release_is_idempotent_for_an_existing_release():
    """Re-running for a tag that already has a release completes it rather than failing."""
    text = workflow_text()
    assert "gh release view" in text
    assert "--clobber" in text


def test_every_category_would_be_attached(tmp_path):
    """The build really does emit one file per category the workflow will glob."""
    B.build(dist_dir=tmp_path)
    produced = {p.name for p in tmp_path.glob("feed-*.json")}
    expected = {f"feed-{c}.json" for c in B.CATEGORIES}
    assert produced == expected


def test_ci_runs_when_any_workflow_changes():
    """These tests assert things about radar-release.yml, so a change to it has
    to trigger them. PR #4 only ran CI because it also touched tests/."""
    ci = (WORKFLOW.parent / "radar-ci.yml").read_text()
    assert '.github/workflows/**' in ci, (
        "the CI path filter must cover every workflow, not just radar-ci.yml — "
        "otherwise a release-workflow-only change skips the tests that check it"
    )
