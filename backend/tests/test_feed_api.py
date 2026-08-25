"""
Tests for GET /api/feed — a thin read-only proxy over the published RADAR feed.

These assert the *shape* of what the proxy returns, not entry counts. Counts
change every time an entry is added; pinning them made the previous suite pass
only against the mock dataset it shipped with.
"""
import os

import requests
from pathlib import Path

CATEGORIES = {
    "malicious-skill",
    "slopsquat-package",
    "malicious-mcp-server",
    "malicious-package",
    "compromised-package",
    "platform-vuln",
    "vibe-app-breach",
}
STATUSES = {"active", "remediated", "disputed"}
SEVERITIES = {"critical", "high", "medium", "low"}
INDICATOR_TYPES = {
    "package", "application", "mcp-server", "skill", "hash", "domain", "ip", "url",
}


def _load_backend_url():
    url = os.environ.get('REACT_APP_BACKEND_URL')
    if url:
        return url.rstrip('/')
    env_path = Path(__file__).resolve().parents[2] / 'frontend' / '.env'
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            if line.startswith('REACT_APP_BACKEND_URL='):
                return line.split('=', 1)[1].strip().rstrip('/')
    raise RuntimeError('REACT_APP_BACKEND_URL not found')


BASE_URL = _load_backend_url()


def get_feed():
    resp = requests.get(f"{BASE_URL}/api/feed")
    resp.raise_for_status()
    return resp


def test_feed_status_code():
    assert get_feed().status_code == 200


def test_feed_cache_control_header():
    assert "no-store" in get_feed().headers.get("Cache-Control", "")


def test_feed_reports_where_it_came_from():
    """The proxy says whether it served the release, a stale cache or a local build."""
    origin = get_feed().headers.get("X-Radar-Feed-Origin")
    assert origin in {"release", "stale-cache", "local-build"}


def test_feed_envelope():
    data = get_feed().json()
    assert data["feed"] == "radar"
    assert data["schema_version"]
    assert data["license"] == "CC-BY-4.0"
    assert "CC BY 4.0" in data["attribution"]
    assert isinstance(data["entries"], list)
    assert data["entry_count"] == len(data["entries"])


def test_feed_is_not_empty():
    assert len(get_feed().json()["entries"]) > 0


def test_every_entry_has_the_required_fields():
    for entry in get_feed().json()["entries"]:
        assert entry["id"].startswith("RADAR-"), entry["id"]
        assert entry["category"] in CATEGORIES, entry["id"]
        assert entry["status"] in STATUSES, entry["id"]
        assert entry["severity"] in SEVERITIES, entry["id"]
        assert entry["title"] and entry["summary"]
        assert entry["first_seen"] and entry["last_updated"]
        assert entry["affected_tools"]


def test_every_entry_has_a_primary_source():
    """The sourcing standard, asserted at the API boundary."""
    for entry in get_feed().json()["entries"]:
        assert any(s["type"] == "primary" for s in entry["sources"]), entry["id"]
        for source in entry["sources"]:
            assert source["url"].startswith("https://")
            assert source["publisher"]


def test_indicators_are_typed_and_present():
    for entry in get_feed().json()["entries"]:
        assert entry["indicators"], entry["id"]
        for ind in entry["indicators"]:
            assert ind["type"] in INDICATOR_TYPES, f'{entry["id"]}: {ind["type"]}'


def test_no_mock_entries_survive():
    """The previous feed's ids and its fabricated report host must never return."""
    data = get_feed().json()
    ids = [e["id"] for e in data["entries"]]
    assert not any(i.startswith(("ms-", "mcp-", "sl-", "pv-", "inc-", "cve-")) for i in ids)
    urls = [s["url"] for e in data["entries"] for s in e["sources"]]
    assert not any("ai-code-threat-radar/feed" in u for u in urls)
