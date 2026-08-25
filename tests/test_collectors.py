"""Tests for the collector machinery and the slopsquat passes.

No network. The npm and PyPI responses here are trimmed copies of real
documents, kept because the shapes are what the code gets wrong: npm serves a
`0.0.1-security` stub for a package it removed for malware, and reading that as
"live" turns twenty correctly-remediated typosquats into twenty false alarms.
"""
import json

import pytest

from collectors.base import (
    Candidate, Result, SkipCollector, load_dismissed, run_collector,
)
from collectors.slopsquat import _age_days, npm_state
from collectors.watchlist import LEGITIMATE_CATEGORIES, MALICIOUS_CATEGORIES, from_feed


@pytest.fixture
def queue(tmp_path):
    return tmp_path / "queue"


def make(key="pypi:claud-code", **kw):
    return Candidate(
        source="slopsquat", key=key, title="t", why="w",
        suggested_category="slopsquat-package", confidence="medium", **kw)


# --------------------------------------------------------------------------
# candidates
# --------------------------------------------------------------------------

def test_candidate_rejects_a_category_the_schema_does_not_have():
    with pytest.raises(ValueError, match="not a RADAR category"):
        Candidate(source="s", key="k", title="t", why="w",
                  suggested_category="typosquat", confidence="high")


def test_candidate_id_is_stable_across_runs():
    assert make().id == make().id


def test_candidate_id_changes_with_the_finding():
    assert make("pypi:a").id != make("pypi:b").id


def test_saving_twice_is_not_a_second_candidate(queue):
    _, first = make().save(queue)
    _, second = make().save(queue)
    assert (first, second) == (True, False)
    assert len(list(queue.glob("*.json"))) == 1


def test_reconfirming_leaves_the_file_byte_identical(queue):
    """A triage PR whose diff is forty refreshed timestamps is a PR nobody reads."""
    path, _ = make().save(queue)
    before = path.read_bytes()
    make().save(queue)
    assert path.read_bytes() == before


def test_discovered_at_survives_a_reconfirmation(queue):
    path, _ = make(discovered_at="2026-01-01T00:00:00Z").save(queue)
    make(discovered_at="2026-08-01T00:00:00Z").save(queue)
    assert json.loads(path.read_text())["discovered_at"] == "2026-01-01T00:00:00Z"


def test_a_changed_finding_does_rewrite(queue):
    path, _ = make().save(queue)
    make(evidence={"age_days": 3}).save(queue)
    assert json.loads(path.read_text())["evidence"] == {"age_days": 3}


# --------------------------------------------------------------------------
# running
# --------------------------------------------------------------------------

def test_one_collector_raising_does_not_kill_the_run(queue):
    def boom():
        raise RuntimeError("registry exploded")
    result = run_collector("x", boom, queue, dismissed=set())
    assert result.status == "error" and "registry exploded" in result.detail


def test_unreachable_is_skipped_not_reported_as_zero_findings(queue):
    """The two states look identical in a log and mean opposite things."""
    def unreachable():
        raise SkipCollector("pypi.org unreachable")
    result = run_collector("x", unreachable, queue, dismissed=set())
    assert result.status == "skipped"
    assert result.status != "ok" and result.new == 0
    assert "unreachable" in result.line()


def test_zero_findings_reports_ok(queue):
    assert run_collector("x", lambda: [], queue, dismissed=set()).status == "ok"


def test_dismissed_candidates_do_not_come_back(queue):
    result = run_collector("x", lambda: [make()], queue, dismissed={"pypi:claud-code"})
    assert (result.new, result.dismissed) == (0, 1)
    assert not list(queue.glob("*.json"))


def test_dismissal_works_by_id_too(queue):
    result = run_collector("x", lambda: [make()], queue, dismissed={make().id})
    assert result.dismissed == 1


def test_dismissed_file_ignores_comments_and_blanks(tmp_path):
    path = tmp_path / "dismissed.txt"
    path.write_text("# a comment\n\npypi:foo   # inline reason\nnpm:bar\n")
    assert load_dismissed(path) == {"pypi:foo", "npm:bar"}


def test_result_line_distinguishes_the_three_outcomes():
    assert "ok" in Result("a", "ok", new=1).line()
    assert "SKIPPED" in Result("a", "skipped", detail="d").line()
    assert "ERROR" in Result("a", "error", detail="d").line()


# --------------------------------------------------------------------------
# npm's four states
# --------------------------------------------------------------------------

SECURITY_HOLDING = {  # what npm serves after removing malware, e.g. claud-code
    "name": "claud-code",
    "dist-tags": {"latest": "0.0.1-security"},
    "versions": {"0.0.1-security": {"name": "claud-code"}},
    "time": {"created": "2026-02-20T16:52:47.177Z",
             "modified": "2026-02-20T16:52:49.713Z",
             "0.0.1-security": "2026-02-20T16:52:49.713Z"},
}
UNPUBLISHED = {  # e.g. postmark-mcp
    "name": "postmark-mcp",
    "time": {"created": "2025-09-15T10:44:07.824Z",
             "modified": "2025-09-25T03:31:54.381Z",
             "unpublished": {"time": "2025-09-25T03:31:54.381Z", "versions": ["1.0.0"]}},
}
LIVE = {
    "name": "something",
    "versions": {"1.0.0": {}, "1.0.1": {}},
    "time": {"created": "2026-08-01T00:00:00.000Z", "1.0.0": "2026-08-01T00:00:00.000Z",
             "1.0.1": "2026-08-02T00:00:00.000Z"},
}


def test_a_security_stub_is_not_a_republication():
    """The bug this guards: reading npm's removal stub as live code turned
    twenty correctly-remediated typosquats into twenty high-confidence alarms."""
    status, _ = npm_state(SECURITY_HOLDING)
    assert status == "security-holding"


def test_unpublished_is_not_a_republication():
    assert npm_state(UNPUBLISHED)[0] == "unpublished"


def test_live_code_is_a_republication():
    status, versions = npm_state(LIVE)
    assert status == "live" and versions == ["1.0.0", "1.0.1"]


def test_a_document_with_no_versions_is_absent():
    assert npm_state({"name": "x", "time": {}})[0] == "absent"


def test_a_live_version_alongside_a_stub_still_counts_as_live():
    doc = {"name": "x", "versions": {"0.0.1-security": {}, "2.0.0": {}}, "time": {}}
    status, versions = npm_state(doc)
    assert status == "live" and versions == ["2.0.0"]


# --------------------------------------------------------------------------
# ages
# --------------------------------------------------------------------------

def test_age_of_nothing_is_unknown_not_zero():
    """An unknown creation date must not read as "published today"."""
    assert _age_days(None) is None
    assert _age_days("not a date") is None


def test_age_handles_both_timestamp_shapes():
    assert _age_days("2020-01-01T00:00:00Z") > 1000
    assert _age_days("2020-01-01T00:00:00.123456Z") > 1000


# --------------------------------------------------------------------------
# the watchlist split
# --------------------------------------------------------------------------

def test_the_two_category_sets_do_not_overlap():
    assert not (LEGITIMATE_CATEGORIES & MALICIOUS_CATEGORIES)


def test_no_known_bad_name_is_on_the_watchlist():
    """`claud-code` in the watchlist would score a fresh copy of itself as a
    zero-distance match on a legitimate name — the opposite of what it is."""
    legit, bad = from_feed()
    assert not (legit & bad)


def test_the_shipped_watchlist_holds_no_known_bad_name():
    from collectors.watchlist import load
    assert not (set(load()) & from_feed()[1])


# --------------------------------------------------------------------------
# MCP registry signals
#
# The live registry produced zero candidates from 2,500 records in a week,
# which is the right answer and also indistinguishable from a collector that
# cannot fire at all. These are the synthetic records that tell them apart.
# --------------------------------------------------------------------------

from collectors.mcp_registry import _claimed_owner, _github_owner, _same_hands, signals
from collectors.similarity import ALL_RULES, SquatMatcher


@pytest.fixture
def mcp_matcher():
    return SquatMatcher(["claude-code", "langchain", "mcp-remote"],
                        max_distance=2, rules=ALL_RULES)


def server(**kw):
    base = {"name": "io.github.alice/thing", "version": "1.0.0"}
    return {**base, **kw}


def test_a_squatting_package_identifier_fires(mcp_matcher):
    found, _ = signals(
        server(packages=[{"registryType": "npm", "identifier": "claud-code"}]),
        mcp_matcher, set())
    assert [f[0] for f in found] == ["package-edit"]
    assert "claud-code" in found[0][2]


def test_a_package_the_feed_already_calls_malicious_fires_high(mcp_matcher):
    found, _ = signals(
        server(packages=[{"registryType": "npm", "identifier": "Claud-Code"}]),
        mcp_matcher, {"claud-code"})
    assert found[0][0] == "known-bad-package" and found[0][1] == "high"


def test_borrowing_a_reputable_repository_fires(mcp_matcher):
    found, mismatch = signals(
        server(name="io.github.alice/thing",
               repository={"url": "https://github.com/anthropics/claude-code"}),
        mcp_matcher, set())
    assert [f[0] for f in found] == ["borrowed-repository"] and mismatch


def test_an_ordinary_namespace_mismatch_is_evidence_not_a_candidate(mcp_matcher):
    """Across 2,500 live records this fired 21 times, all benign: a person
    publishing under their own account with the code in their company org."""
    found, mismatch = signals(
        server(name="io.github.hassaanali723/giggal-mcp",
               repository={"url": "https://github.com/giggal-ai/giggal-mcp"}),
        mcp_matcher, set())
    assert found == [] and mismatch is True


@pytest.mark.parametrize("claimed,actual", [
    ("csoai-org", "csao-org"),                    # transposition
    ("agentsgetpaid", "agentsgetpaidmore"),       # prefix
    ("aion-autonomous-org", "aion-autonomous-labs"),
])
def test_a_publisher_tripping_over_their_own_name_is_not_a_mismatch(claimed, actual):
    assert _same_hands(claimed, actual)


def test_unrelated_owners_are_not_the_same_hands():
    assert not _same_hands("alice", "anthropics")


def test_an_ordinary_listing_fires_nothing(mcp_matcher):
    found, mismatch = signals(
        server(name="io.github.alice/weather",
               repository={"url": "https://github.com/alice/weather"},
               packages=[{"registryType": "npm", "identifier": "weather-mcp"}]),
        mcp_matcher, set())
    assert found == [] and mismatch is False


def test_owner_extraction():
    assert _claimed_owner("io.github.Alice/thing") == "alice"
    assert _claimed_owner("com.example/thing") is None
    assert _github_owner("https://github.com/Bob/repo") == "bob"
    assert _github_owner("https://gitlab.com/bob/repo") is None


def test_a_low_confidence_match_gets_a_tighter_age_window():
    """`langchain-mcp` and `tiktoken-cli` are affix hits on legitimate community
    packages. Six months in they are settled ecosystem; brand new they would be
    worth a look. The window, not the rule, is what separates those."""
    from collectors.similarity import Match
    from collectors.slopsquat import LOW_CONFIDENCE_MAX_AGE_DAYS, _age_limit

    affix = Match("langchain-mcp", "langchain", "affix", 0)
    edit = Match("langchian", "langchain", "edit", 1)
    assert affix.confidence == "low" and edit.confidence == "medium"
    assert _age_limit(affix, 400) == LOW_CONFIDENCE_MAX_AGE_DAYS
    assert _age_limit(edit, 400) == 400


def test_the_tighter_window_never_widens_an_explicit_limit():
    from collectors.similarity import Match
    from collectors.slopsquat import _age_limit
    assert _age_limit(Match("x", "y", "affix", 0), 30) == 30


# --------------------------------------------------------------------------
# republication is a transition, not a state
# --------------------------------------------------------------------------

@pytest.mark.parametrize("was,status,expected", [
    ("security-holding", "live", True),    # npm's removal stub replaced by real code
    ("unpublished", "live", True),
    ("gone", "live", True),                # a 404 name someone has now claimed
    ("live", "live", False),               # a status:active entry restating itself
    (None, "live", False),                 # first look: a baseline, not a discovery
    ("live", "security-holding", False),   # npm caught up; good news, not a candidate
    ("gone", "gone", False),
])
def test_only_a_transition_into_live_is_a_republication(was, status, expected):
    """Reporting the state rather than the change would put a permanent false
    alarm in the queue for every live threat RADAR catalogues — three of them
    the day this was written."""
    from collectors.slopsquat import is_republication
    assert is_republication(was, status) is expected
