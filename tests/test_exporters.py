"""Tests for the guard exporters.

Two things these have to guarantee, and they pull in opposite directions:

* **Never cause a false positive.** A guard acting on this data blocks software
  on a developer's machine. An entry naming a legitimate package that had a bug
  must never produce a `block` rule, whatever its severity.
* **Never overstate coverage.** An advisory emitted under a matcher that cannot
  fire is worse than no advisory: it makes the export look richer than it is
  and it silently protects nobody.
"""
import json

import pytest

from exporters.common import (
    LEGITIMATE_CATEGORIES, MALICIOUS_CATEGORIES, decide_action, feed_epoch,
    feed_version, indicator_value,
)
from exporters.hol_guard import UNSIGNED, build_hol_guard_bundle, matcher_key
from exporters.radar_deny import build_radar_deny

# The matcher registry as it actually exists in hol-guard, from
# src/codex_plugin_scanner/guard/runtime/advisory_matchers.py. If an export
# emits a key that is not in here, hol-guard's get_matcher() returns None and
# the advisory is inert.
HOL_GUARD_MATCHERS = {
    "osv", "github_advisory", "nvd_cve", "npm", "pypi", "github_action",
    "mcp_server", "skill_hash", "malicious_domain", "malicious_package_hash",
}


def entry(**kw):
    base = {
        "id": "RADAR-2026-0001", "category": "slopsquat-package", "status": "active",
        "severity": "critical", "title": "T", "summary": "S",
        "first_seen": "2026-01-01", "last_updated": "2026-01-01",
        "indicators": [{"type": "package", "registry": "npm", "name": "evil"}],
        "sources": [{"url": "https://example.com/a", "publisher": "P", "type": "primary"}],
        "affected_tools": ["claude-code"],
    }
    return {**base, **kw}


def feed(entries=None):
    entries = entries if entries is not None else [entry()]
    return {
        "feed": "radar", "schema_version": "1.0.0",
        "homepage": "https://example.com/repo", "license": "CC-BY-4.0",
        "attribution": "CC BY 4.0", "last_updated": "2026-08-25",
        "entry_count": len(entries), "entries": entries,
    }


# --------------------------------------------------------------------------
# the false-positive guarantee
# --------------------------------------------------------------------------

@pytest.mark.parametrize("category", sorted(LEGITIMATE_CATEGORIES))
@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low"])
def test_a_legitimate_package_is_never_blocked(category, severity):
    """`platform-vuln` names software the developer is entitled to run.
    Blocking @anthropic-ai/claude-code over a fixed bug is worse than the bug."""
    action, _ = decide_action(
        entry(category=category, status="active", severity=severity),
        {"type": "package", "registry": "npm", "name": "@anthropic-ai/claude-code"})
    assert action == "warn"


def test_that_guarantee_survives_the_whole_pipeline():
    e = entry(category="platform-vuln", severity="critical", status="active",
              indicators=[{"type": "package", "registry": "npm", "name": "legit"}])
    rules = build_radar_deny(feed([e]))["rules"]
    assert [r["action"] for r in rules] == ["warn"]


@pytest.mark.parametrize("category", sorted(MALICIOUS_CATEGORIES))
def test_a_malicious_artifact_that_is_live_is_blocked(category):
    action, _ = decide_action(entry(category=category, status="active"),
                              {"type": "package", "registry": "npm", "name": "evil"})
    assert action == "block"


@pytest.mark.parametrize("status,expected", [
    ("active", "block"),
    ("remediated", "monitor"),   # removed; a reappearance is a note, not an alarm
    ("disputed", "warn"),        # the claim is not settled
])
def test_status_decides_how_hard_to_act(status, expected):
    action, _ = decide_action(entry(status=status),
                              {"type": "package", "registry": "npm", "name": "evil"})
    assert action == expected


def test_a_breached_application_is_not_an_install_target():
    action, why = decide_action(entry(category="vibe-app-breach", status="active"),
                                {"type": "domain", "value": "app.example"})
    assert action == "monitor" and "installable" in why


def test_every_rule_carries_its_reason():
    for rule in build_radar_deny(feed())["rules"]:
        assert rule["action_reason"] and rule["action"] in {"block", "warn", "monitor"}


# --------------------------------------------------------------------------
# versions — the difference between a match and a false positive
# --------------------------------------------------------------------------

def test_pinned_versions_are_flattened_for_the_scanner():
    e = entry(indicators=[{"type": "package", "registry": "npm", "name": "p",
                           "version": "3.4.2", "affected": {"versions": ["3.4.2"]}}])
    row = build_radar_deny(feed([e]))["rules"][0]
    assert row["versions"] == ["3.4.2"]
    assert row["all_versions"] is False


def test_an_unpinned_indicator_says_so_explicitly():
    """A scanner must not have to infer "every version" from a missing key."""
    row = build_radar_deny(feed())["rules"][0]
    assert row["all_versions"] is True and "versions" not in row


def test_ranges_survive_the_export():
    e = entry(indicators=[{"type": "package", "registry": "npm", "name": "p",
                           "affected": {"ranges": [{"introduced": "1.0", "fixed": "1.2"}]}}])
    row = build_radar_deny(feed([e]))["rules"][0]
    assert row["version_ranges"] == [{"introduced": "1.0", "fixed": "1.2"}]


# --------------------------------------------------------------------------
# determinism — no clock, no network
# --------------------------------------------------------------------------

def test_exports_are_pure_functions():
    f = feed()
    for build in (build_radar_deny, build_hol_guard_bundle):
        assert json.dumps(build(f), sort_keys=True) == json.dumps(build(f), sort_keys=True)


def test_timestamps_come_from_the_feed_not_the_clock():
    """A rebuild a year from now must produce the same bytes."""
    bundle = build_hol_guard_bundle(feed())
    assert bundle["generated_at"] == feed_epoch("2026-08-25")
    assert bundle["expires_at"] > bundle["generated_at"]


def test_the_bundle_version_rises_with_the_feed_date():
    """hol-guard's check_bundle_rollback rejects a bundle older than the cached one."""
    assert feed_version("2026-08-25") == 20260825
    assert feed_version("2026-12-01") > feed_version("2026-08-25")


# --------------------------------------------------------------------------
# hol-guard: no advisory that cannot fire
# --------------------------------------------------------------------------

def test_every_emitted_matcher_key_exists_in_hol_guard():
    e = entry(indicators=[
        {"type": "package", "registry": "npm", "name": "a"},
        {"type": "package", "registry": "pypi", "name": "b"},
        {"type": "mcp-server", "name": "c"},
        {"type": "domain", "value": "d.example"},
        {"type": "hash", "algo": "sha256", "value": "ab" * 32},
    ])
    keys = {a["matcher_key"] for a in build_hol_guard_bundle(feed([e]))["advisories"]}
    assert keys and keys <= HOL_GUARD_MATCHERS


def test_skill_slugs_are_not_emitted_under_the_hash_matcher():
    """match_skill_hash compares a content hash. Feeding it 344 marketplace
    slugs would look like coverage and match nothing."""
    e = entry(category="malicious-skill",
              indicators=[{"type": "skill", "slug": "clawhub-6yr3b", "marketplace": "clawhub.ai"}])
    bundle = build_hol_guard_bundle(feed([e]))
    assert bundle["advisories"] == []
    assert bundle["radar"]["skipped_indicators"] == {"skill": 1}


def test_a_skill_content_hash_does_use_the_skill_matcher():
    e = entry(category="malicious-skill",
              indicators=[{"type": "hash", "algo": "sha256", "value": "cd" * 32}])
    assert build_hol_guard_bundle(feed([e]))["advisories"][0]["matcher_key"] == "skill_hash"


def test_an_mcp_server_without_a_name_is_skipped():
    """match_mcp_server compares a server name; a repo URL cannot match one."""
    e = entry(category="malicious-mcp-server",
              indicators=[{"type": "mcp-server", "repo": "https://github.com/x/y"}])
    bundle = build_hol_guard_bundle(feed([e]))
    assert bundle["advisories"] == []
    assert bundle["radar"]["skipped_indicators"] == {"mcp-server/no-name": 1}


@pytest.mark.parametrize("indicator", [
    {"type": "ip", "value": "1.2.3.4"},
    {"type": "url", "value": "https://x.example/y"},
    {"type": "application", "name": "cursor"},
    {"type": "package", "registry": "vscode", "name": "pub.ext"},
])
def test_types_hol_guard_cannot_match_are_counted_not_dropped(indicator):
    bundle = build_hol_guard_bundle(feed([entry(indicators=[indicator])]))
    assert bundle["advisories"] == []
    assert sum(bundle["radar"]["skipped_indicators"].values()) == 1


def test_matcher_key_is_none_for_an_unmatchable_indicator():
    assert matcher_key(entry(), {"type": "ip", "value": "1.2.3.4"}) is None


# --------------------------------------------------------------------------
# hol-guard: the signature is not faked
# --------------------------------------------------------------------------

def test_the_signature_field_is_honestly_unsigned():
    """RADAR does not hold hol-guard's key. The field is a required non-empty
    string, so it says what it is rather than carrying something signature-shaped."""
    bundle = build_hol_guard_bundle(feed())
    assert bundle["signature"] == UNSIGNED == "unsigned"
    assert bundle["radar"]["unsigned"] is True


def test_the_unsigned_marker_is_not_valid_base64_of_a_signature():
    """verify_bundle_signature() base64-decodes this field. It must fail loudly."""
    import base64
    bundle = build_hol_guard_bundle(feed())
    decoded = base64.b64decode(bundle["signature"] + "==", validate=False)
    assert len(decoded) < 32, "must not be mistakable for an RSA-PSS signature"


def test_the_bundle_carries_the_required_fields_hol_guard_parses():
    """ThreatIntelBundle.from_dict raises if any of these is missing or the
    wrong type; the bundle must at least parse before it can be rejected."""
    bundle = build_hol_guard_bundle(feed())
    assert isinstance(bundle["version"], int)
    assert isinstance(bundle["generated_at"], (int, float))
    assert isinstance(bundle["expires_at"], (int, float))
    assert isinstance(bundle["source"], str) and bundle["source"].strip()
    assert isinstance(bundle["signature"], str) and bundle["signature"].strip()
    for advisory in bundle["advisories"]:
        for field in ("advisory_id", "source", "severity", "title",
                      "affected_type", "matcher", "recommendation"):
            assert isinstance(advisory[field], str) and advisory[field].strip(), field


def test_severities_stay_inside_hol_guards_vocabulary():
    ranks = {"info", "low", "medium", "high", "critical"}
    for advisory in build_hol_guard_bundle(feed())["advisories"]:
        assert advisory["severity"] in ranks


def test_advisory_ids_are_unique():
    e = entry(indicators=[{"type": "package", "registry": "npm", "name": "a"},
                          {"type": "package", "registry": "npm", "name": "b"}])
    ids = [a["advisory_id"] for a in build_hol_guard_bundle(feed([e]))["advisories"]]
    assert len(ids) == len(set(ids))


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

@pytest.mark.parametrize("indicator,expected", [
    ({"type": "package", "name": "p"}, "p"),
    ({"type": "skill", "slug": "s"}, "s"),
    ({"type": "domain", "value": "d"}, "d"),
    ({"type": "mcp-server", "repo": "r"}, "r"),
])
def test_indicator_value_finds_the_matchable_string(indicator, expected):
    assert indicator_value(indicator) == expected


# --------------------------------------------------------------------------
# the actionless-format rule
# --------------------------------------------------------------------------

def test_a_legitimate_artifact_never_reaches_the_hol_guard_bundle():
    """ThreatAdvisory has a severity and no action field. Shipping
    @anthropic-ai/claude-code at severity high into a format that cannot say
    "do not block this" invites the exact false positive radar-deny prevents."""
    e = entry(category="platform-vuln", severity="critical", status="active",
              indicators=[{"type": "package", "registry": "npm",
                           "name": "@anthropic-ai/claude-code", "version": "<1.2"}])
    bundle = build_hol_guard_bundle(feed([e]))
    assert bundle["advisories"] == []
    assert bundle["radar"]["skipped_indicators"] == {"legitimate-artifact": 1}


def test_radar_deny_does_carry_it_because_it_has_an_action():
    e = entry(category="platform-vuln", severity="critical", status="active",
              indicators=[{"type": "package", "registry": "npm",
                           "name": "@anthropic-ai/claude-code", "version": "<1.2"}])
    rules = build_radar_deny(feed([e]))["rules"]
    assert len(rules) == 1 and rules[0]["action"] == "warn"


def test_no_advisory_in_the_real_bundle_names_a_legitimate_artifact():
    """Belt and braces against the shipped feed, not a fixture."""
    from pathlib import Path
    path = Path(__file__).resolve().parent.parent / "dist" / "hol-guard-threat-intel.json"
    if not path.exists():
        pytest.skip("dist not built")
    feed_path = path.parent / "feed.json"
    published = json.loads(feed_path.read_text())
    legitimate = {
        ind.get("name") or ind.get("slug") or ind.get("value")
        for e in published["entries"] if e["category"] in LEGITIMATE_CATEGORIES
        for ind in e["indicators"]
    }
    emitted = {a["matcher"] for a in json.loads(path.read_text())["advisories"]}
    assert not (emitted & legitimate), sorted(emitted & legitimate)


# --------------------------------------------------------------------------
# the drafts in outbox/ quote numbers; stale numbers make an outreach look sloppy
# --------------------------------------------------------------------------

def test_outbox_drafts_quote_the_current_counts():
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    deny = root / "dist" / "radar-deny.json"
    if not deny.exists():
        pytest.skip("dist not built")
    published = json.loads((root / "dist" / "feed.json").read_text())
    rules = json.loads(deny.read_text())
    entries, indicators = published["entry_count"], rules["rule_count"]
    for draft in sorted((root / "outbox").glob("*-issue.md")):
        text = draft.read_text()
        assert f"{entries} entries" in text, f"{draft.name} quotes a stale entry count"
        assert f"{indicators} indicators" in text, f"{draft.name} quotes a stale indicator count"


def test_consumers_doc_covers_three_tools():
    from pathlib import Path
    text = (Path(__file__).resolve().parent.parent / "docs" / "consumers.md").read_text()
    for tool in ("hol-guard", "PurpleLlama", "vexscan-claude-code"):
        assert tool in text, tool
