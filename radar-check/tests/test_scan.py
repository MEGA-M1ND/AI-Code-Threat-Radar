"""End-to-end scanning against the seeded fixture and the real feed.

`fixtures/seeded/` is a project with one of everything radar-check is supposed
to catch. `fixtures/clean/` is a project with none of it. Between them they
pin both halves of the contract: everything seeded is found, and nothing that
should be quiet makes noise.
"""
import json

import pytest

from radar_check.cli import EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS, main, run_scan
from radar_check.findings import Finding
from radar_check.sarif import build as build_sarif


@pytest.fixture
def report(seeded, index):
    return run_scan(seeded, index, home=None, skip=set())


def artifacts(report):
    return {f.artifact for f in report.findings}


# --------------------------------------------------------------------------
# everything seeded is found
# --------------------------------------------------------------------------

def test_a_malicious_dependency_is_found(report):
    hit = next(f for f in report.findings if f.artifact == "ms-graph-types")
    assert hit.kind == "malicious" and hit.severity == "critical"
    assert hit.radar_id and hit.source.startswith("https://")


def test_a_malicious_pypi_dependency_is_found(report):
    assert "aliyun-ai-labs-sdk" in artifacts(report)


def test_a_compromised_legitimate_package_is_found(report):
    hit = next(f for f in report.findings if f.artifact == "@ctrl/tinycolor")
    assert hit.kind == "affected"


def test_a_malicious_mcp_server_package_is_found(report):
    assert "postmark-mcp" in artifacts(report)
    assert "@apexfdn/copilot-mcp" in artifacts(report)


def test_a_malicious_skill_is_found_by_slug(report):
    hit = next(f for f in report.findings if f.artifact == "clawhub-6yr3b")
    assert hit.kind == "malicious" and "SKILL.md" in hit.location


def test_the_session_start_hook_is_found(report):
    hit = next(f for f in report.findings if f.kind == "hook")
    assert hit.severity == "critical"
    assert "settings.json" in hit.location
    assert "does not remove the hook" in hit.remediation


def test_a_near_miss_is_found(report):
    hit = next(f for f in report.findings if f.kind == "near-miss")
    assert hit.artifact == "tinycolour" and hit.uncertainty


def test_nothing_seeded_goes_unreported(report):
    """The whole fixture, in one assertion, so adding a trap to the fixture
    without teaching a scanner about it fails here."""
    assert {"ms-graph-types", "aliyun-ai-labs-sdk", "@ctrl/tinycolor",
            "postmark-mcp", "@apexfdn/copilot-mcp", "clawhub-6yr3b",
            "tinycolour"} <= artifacts(report)
    assert {f.kind for f in report.findings} >= {"malicious", "affected", "hook", "near-miss"}


# --------------------------------------------------------------------------
# and nothing else does
# --------------------------------------------------------------------------

def test_the_clean_decoy_version_is_not_flagged(report):
    """microsoft-applicationinsights-common 3.4.2 is malware and 3.4.1 is not.
    The fixture pins 3.4.1. Flagging it would be the false positive the whole
    version parser exists to prevent."""
    assert "microsoft-applicationinsights-common" not in artifacts(report)


@pytest.mark.parametrize("name", ["express", "requests", "some-weather-mcp"])
def test_ordinary_dependencies_are_quiet(report, name):
    assert name not in artifacts(report)


def test_a_clean_project_produces_nothing(clean, index):
    result = run_scan(clean, index, home=None, skip=set())
    assert result.findings == []
    assert result.scanned.get("lockfiles") == 1


def test_scanning_finds_lockfiles_in_subdirectories(report):
    assert report.scanned["lockfiles"] >= 3


# --------------------------------------------------------------------------
# severity is about the artifact, not only the flaw
# --------------------------------------------------------------------------

def test_a_vulnerable_legitimate_package_ranks_below_malware(report):
    malware = next(f for f in report.findings if f.artifact == "ms-graph-types")
    legit = next(f for f in report.findings if f.artifact == "@ctrl/tinycolor")
    from radar_check.findings import SEVERITY_RANK
    assert SEVERITY_RANK[malware.severity] < SEVERITY_RANK[legit.severity]


# --------------------------------------------------------------------------
# the CLI contract
# --------------------------------------------------------------------------

def test_exit_code_says_found_something(seeded, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE_DIR", str(tmp_path))
    code = main(["--feed", _feed_path(), "--no-home", "--quiet", str(seeded)])
    assert code == EXIT_FINDINGS


def test_exit_code_says_clean(clean, tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE_DIR", str(tmp_path))
    assert main(["--feed", _feed_path(), "--no-home", "--quiet", str(clean)]) == EXIT_CLEAN


def test_a_missing_feed_is_an_error_not_a_clean_scan(clean, capsys):
    """A scan with no data finds nothing and looks exactly like a clean project.
    Exiting 2 is the difference between "you are fine" and "I could not look"."""
    code = main(["--feed", "/nonexistent/feed.json", "--no-home", str(clean)])
    assert code == EXIT_ERROR


def test_fail_on_threshold_is_respected(seeded, tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE_DIR", str(tmp_path))
    args = ["--feed", _feed_path(), "--no-home", "--quiet", str(seeded)]
    assert main(args + ["--fail-on", "never"]) == EXIT_CLEAN
    assert main(args + ["--fail-on", "critical"]) == EXIT_FINDINGS


def test_skip_turns_a_scanner_off(seeded, index):
    result = run_scan(seeded, index, home=None, skip={"hooks", "skills"})
    assert not any(f.kind in ("hook",) for f in result.findings)
    assert "clawhub-6yr3b" not in {f.artifact for f in result.findings}


def test_json_output_is_machine_readable(seeded, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("RADAR_CACHE_DIR", str(tmp_path))
    main(["--feed", _feed_path(), "--no-home", "--format", "json", str(seeded)])
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "radar-check"
    assert payload["feed"]["entry_count"] > 0
    assert payload["findings"] and payload["findings"][0]["severity"]


# --------------------------------------------------------------------------
# SARIF
# --------------------------------------------------------------------------

def test_sarif_is_wellformed(report, seeded):
    doc = build_sarif(report, seeded, "0.1.0")
    assert doc["version"] == "2.1.0" and doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    declared = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} <= declared
    for result in run["results"]:
        assert result["level"] in ("error", "warning", "note", "none")
        assert result["message"]["text"]
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_paths_are_relative_to_the_scanned_project(report, seeded):
    run = build_sarif(report, seeded, "0.1.0")["runs"][0]
    for result in run["results"]:
        uri = result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert not uri.startswith("/"), uri


def test_a_near_miss_is_a_note_not_an_error(report, seeded):
    run = build_sarif(report, seeded, "0.1.0")["runs"][0]
    near = next(r for r in run["results"] if r["ruleId"] == "radar/near-miss")
    assert near["level"] == "note"


def test_malware_is_an_error_whatever_its_severity(seeded):
    from radar_check.findings import ScanReport
    report = ScanReport()
    report.add(Finding(kind="malicious", severity="low", title="t", detail="d",
                       location=str(seeded / "package-lock.json")))
    run = build_sarif(report, seeded, "0.1.0")["runs"][0]
    assert run["results"][0]["level"] == "error"


def test_sarif_records_which_feed_was_used(report, seeded):
    report.feed_origin = "cache"
    run = build_sarif(report, seeded, "0.1.0")["runs"][0]
    assert run["properties"]["feedOrigin"] == "cache"


def _feed_path() -> str:
    from pathlib import Path
    return str(Path(__file__).resolve().parent.parent.parent / "dist" / "feed.json")


# --------------------------------------------------------------------------
# excluding a directory
# --------------------------------------------------------------------------

def test_exclude_skips_a_directory(seeded, index):
    """A scanner that cannot be told to skip its own test fixtures cannot be
    run in its own CI."""
    from pathlib import Path
    root = Path(seeded).parent.parent
    with_fixtures = run_scan(root, index, home=None, skip=set())
    without = run_scan(root, index, home=None, skip=set(), exclude=("fixtures",))
    assert with_fixtures.findings and without.findings == []


def test_exclude_does_not_silently_widen(seeded, index):
    """Excluding an unrelated name must leave the scan intact."""
    result = run_scan(seeded, index, home=None, skip=set(), exclude=("unrelated",))
    assert len(result.findings) >= 8
