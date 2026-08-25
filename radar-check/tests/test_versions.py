"""The version parser, tested against the strings RADAR actually publishes.

Every `parses` case below is a real string from the feed. The parser exists
because these are human notation — a researcher wrote `0.0.5 - 0.1.15` in an
article and the entry quotes it verbatim so a reader can check the citation.
"""
import json

import pytest

from radar_check.versions import (
    Constraint, UnparseableVersion, constraints_for, key, matches, parse,
    parse_affected,
)


@pytest.mark.parametrize("spec,expected", [
    ("1.0.4", ["1.0.4"]),
    ("0.0.16, 0.0.17", ["0.0.16", "0.0.17"]),
    ("0.0.5 - 0.1.15", ["0.0.5 to 0.1.15"]),
    ("1.0.0-1.0.32", ["1.0.0 to 1.0.32"]),
    ("1.0.0-1.0.22+", ["1.0.0 to any later version"]),
    ("<1.3.9", ["<1.3.9"]),
    ("<=0.6.2", ["<=0.6.2"]),
    (">=1.0.16", [">=1.0.16"]),
    ("2026.2.17", ["2026.2.17"]),
    ("20.9.0, 21.5.0", ["20.9.0", "21.5.0"]),
])
def test_real_feed_shapes_parse(spec, expected):
    assert [c.describe() for c in parse(spec)] == expected


def test_every_version_string_in_the_feed_parses(feed):
    """The parser is only worth having if it handles the whole corpus."""
    failures = []
    for entry in feed["entries"]:
        for indicator in entry["indicators"]:
            if indicator.get("version"):
                try:
                    parse(indicator["version"])
                except UnparseableVersion as error:
                    failures.append((entry["id"], indicator["version"], str(error)))
    assert not failures, failures


# --------------------------------------------------------------------------
# the hyphen ambiguity
# --------------------------------------------------------------------------

def test_an_unspaced_hyphen_can_be_a_range():
    assert parse("1.0.0-1.0.32")[0].kind == "range"


@pytest.mark.parametrize("spec", ["1.0.0-alpha", "0.0.1-security", "2.0.0-rc.1"])
def test_or_a_prerelease_tag(spec):
    """`0.0.1-security` is npm's malware-removal stub, and it is a version, not
    a range. Reading it as one would produce a range with no upper bound."""
    parsed = parse(spec)
    assert parsed[0].kind == "exact" and parsed[0].value == spec


# --------------------------------------------------------------------------
# ordering
# --------------------------------------------------------------------------

def test_components_compare_as_numbers_not_text():
    """The feed carries 1.0.9 and 1.0.91 as separate affected versions of the
    same package. String comparison puts 1.0.91 below 1.0.9."""
    assert key("1.0.91") > key("1.0.9")
    assert key("1.161.10") > key("1.161.9")


def test_a_prerelease_sorts_below_its_release():
    assert key("1.0.0-alpha") < key("1.0.0")


def test_calendar_versions_order():
    assert key("2026.2.17") > key("2025.7.1")


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------

@pytest.mark.parametrize("spec,version,expected", [
    ("2.43.2", "2.43.2", True),
    ("2.43.2", "2.43.1", False),      # the clean decoy must not match
    ("0.0.5 - 0.1.15", "0.1.0", True),
    ("0.0.5 - 0.1.15", "0.1.16", False),
    ("0.0.5 - 0.1.15", "0.0.4", False),
    ("<1.3.9", "1.3.8", True),
    ("<1.3.9", "1.3.9", False),
    (">=1.0.16", "1.0.16", True),
    (">=1.0.16", "1.0.15", False),
    ("0.0.16, 0.0.17", "0.0.17", True),
    ("0.0.16, 0.0.17", "0.0.18", False),
])
def test_matching(spec, version, expected):
    assert matches({"version": spec}, version)[0] is expected


def test_no_version_means_every_version():
    matched, uncertainty = matches({"type": "package", "name": "x"}, "9.9.9")
    assert matched is True and uncertainty is None


# --------------------------------------------------------------------------
# structured affected takes precedence, and half-open ranges stay half-open
# --------------------------------------------------------------------------

def test_fixed_is_the_first_unaffected_version():
    """Treating `fixed` as the last affected version flags someone who already
    upgraded to the fix — the one action the finding told them to take."""
    indicator = {"affected": {"ranges": [{"introduced": "1.0.0", "fixed": "1.2.0"}]}}
    assert matches(indicator, "1.1.9")[0] is True
    assert matches(indicator, "1.2.0")[0] is False


def test_last_affected_is_inclusive():
    indicator = {"affected": {"ranges": [{"introduced": "1.0.0", "last_affected": "1.2.0"}]}}
    assert matches(indicator, "1.2.0")[0] is True
    assert matches(indicator, "1.2.1")[0] is False


def test_an_open_ended_range_has_no_upper_bound():
    indicator = {"affected": {"ranges": [{"introduced": "1.0.16"}]}}
    assert matches(indicator, "99.0.0")[0] is True
    assert matches(indicator, "1.0.15")[0] is False


def test_structured_affected_wins_over_the_prose_string():
    indicator = {"version": "definitely not parseable",
                 "affected": {"versions": ["1.0.0"]}}
    assert matches(indicator, "1.0.0") == (True, None)
    assert matches(indicator, "2.0.0")[0] is False


# --------------------------------------------------------------------------
# the defensive contract
# --------------------------------------------------------------------------

def test_an_unparseable_string_reports_rather_than_guesses():
    """Answering "no match" hides a real hit. Answering "match" silently cries
    wolf. The only honest answer is to flag it and say why."""
    matched, uncertainty = matches({"version": "sometime last tuesday"}, "1.0.0")
    assert matched is True
    assert uncertainty and "could not parse" in uncertainty


def test_an_unparseable_installed_version_is_also_surfaced():
    matched, uncertainty = matches({"version": "1.0.0"}, "git+ssh://whatever")
    assert matched is True and "installed version" in uncertainty


@pytest.mark.parametrize("spec", ["", "   ", "latest", "^1.0.0", "~2", "*"])
def test_shapes_the_parser_refuses(spec):
    """A semver range operator is not something this feed emits. Refusing is
    better than half-implementing npm's range grammar."""
    with pytest.raises(UnparseableVersion):
        parse(spec)
