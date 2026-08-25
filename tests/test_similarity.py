"""Tests for the slopsquat name matcher.

The thresholds in similarity.py were tuned by sweeping the real PyPI index, so
these lock in what that sweep established: the shapes that must match, and —
more importantly — the legitimate names that must not. Every "must not" case
here is a real package that an earlier, looser version of the matcher flagged.
"""
import pytest

from collectors.similarity import (
    ALL_RULES, SWEEP_RULES, SquatMatcher, bare, is_distinctive, levenshtein,
    normalize_pypi, strip_separators,
)

WATCHLIST = [
    "claude-code", "langchain", "langchain-core", "codex-cli", "openclaw",
    "transformers", "anthropic", "mcp", "nx", "agent-sdk", "mcp-client",
    "@ctrl/tinycolor", "@nx/js", "@tanstack/react-router", "gemini-cli",
]


@pytest.fixture
def sweep():
    return SquatMatcher(WATCHLIST, max_distance=1, rules=SWEEP_RULES)


@pytest.fixture
def targeted():
    return SquatMatcher(WATCHLIST, max_distance=2, rules=ALL_RULES)


# --------------------------------------------------------------------------
# distance
# --------------------------------------------------------------------------

def test_transposition_is_one_edit_not_two():
    """`langchian` is the single most common real typo shape for `langchain`."""
    assert levenshtein("langchian", "langchain") == 1


@pytest.mark.parametrize("a,b,expected", [
    ("claude-code", "claude-code", 0),
    ("claud-code", "claude-code", 1),      # omission
    ("clauude-code", "claude-code", 1),    # duplication
    ("claube-code", "claude-code", 1),     # substitution
    ("claudee-codee", "claude-code", 2),   # two insertions
])
def test_distance(a, b, expected):
    assert levenshtein(a, b, max_distance=3) == expected


def test_distance_is_bounded_not_computed():
    """Past the bound it returns max+1, so callers cannot read a real distance."""
    assert levenshtein("abcdefghij", "zzzzzzzzzz", max_distance=2) == 3


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def test_pypi_normalization_collapses_separators():
    assert normalize_pypi("Claude_Code") == normalize_pypi("claude.code") == "claude-code"


def test_bare_strips_the_scope():
    assert bare("@anthropic-ai/claude-code") == "claude-code"
    assert bare("claude-code") == "claude-code"
    assert bare("@anthropic-ai") == "@anthropic-ai"


def test_strip_separators():
    assert strip_separators("claude-code") == strip_separators("claude_code") == "claudecode"


@pytest.mark.parametrize("name", ["claude-code", "langchain", "@ctrl/tinycolor", "openclaw"])
def test_product_names_are_distinctive(name):
    assert is_distinctive(name)


@pytest.mark.parametrize("name", [
    "mcp", "agent-sdk", "mcp-client", "mcp-server", "agent-tools", "sdk", "cli",
    "scale", "eslint", "deluge", "@nx/js",
])
def test_category_words_and_short_single_words_are_not(name):
    """These matched hundreds of unrelated legitimate PyPI packages."""
    assert not is_distinctive(name)


# --------------------------------------------------------------------------
# what must match
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name,target,rule", [
    ("claud-code", "claude-code", "edit"),
    ("langchian", "langchain", "edit"),
    ("claude_code", "claude-code", "separator"),
    ("c1aude-code", "claude-code", "homoglyph"),
    ("klaude-code", "claude-code", "homoglyph"),
    ("tinycolor", "@ctrl/tinycolor", "scope-drop"),
])
def test_sweep_catches_real_squat_shapes(sweep, name, target, rule):
    match = sweep.match(name)
    assert match is not None, name
    assert (match.target, match.rule) == (target, rule)


def test_a_watchlist_name_never_matches_itself(sweep):
    for name in WATCHLIST:
        assert sweep.match(name) is None, name


# --------------------------------------------------------------------------
# what must not match — every one of these is a real package
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "ace-client",       # was: 2 edits from mcp-client
    "acp", "ncp", "mkp",  # was: 1 edit or homoglyph from mcp
    "6x", "9x", "mx",   # was: 1 edit from nx
    "agent0-sdk", "agentdk",   # was: near agent-sdk
    "langchain-cohere", "langchain-forge",  # was: 2 edits from langchain-core
    "x-transformers", "pytransformers", "vtransformer",  # was: 2 edits
    "langchain-community", "langchain-openai", "llama-index-core",
])
def test_sweep_does_not_flag_legitimate_packages(sweep, name):
    assert sweep.match(name) is None, f"false positive on {name}"


@pytest.mark.parametrize("name", [
    "claude-code-sdk", "langchain-cli", "gemini-cli-mcp", "anthropic-tools",
])
def test_affix_is_off_for_sweeps_and_on_for_targeted(sweep, targeted, name):
    """Affixing is how ecosystems name companion packages — 5% precision on a
    full index, worth a look when a human is already reading one brand."""
    assert sweep.match(name) is None, name
    match = targeted.match(name)
    assert match is not None and match.rule == "affix"
    assert match.confidence == "low"


def test_targeted_allows_two_edits_and_the_sweep_does_not(sweep, targeted):
    assert sweep.match("claudee-codee") is None
    match = targeted.match("claudee-codee")
    assert match is not None and match.distance == 2
    assert match.confidence == "low", "two edits is never better than a guess"


# --------------------------------------------------------------------------
# scoring
# --------------------------------------------------------------------------

def test_one_edit_outranks_two(targeted):
    assert targeted.match("claud-code").confidence == "medium"
    assert targeted.match("claudee-codee").confidence == "low"


def test_why_reads_as_a_sentence(sweep):
    for name in ("claud-code", "claude_code", "c1aude-code", "tinycolor"):
        why = sweep.match(name).why()
        assert why and not why[0].isupper() and not why.endswith(".")
