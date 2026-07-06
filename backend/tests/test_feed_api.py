"""
Tests for GET /api/feed - thin read-only proxy serving static feed.json.
No DB usage; verifies structure, counts, and no-store cache headers.
"""
import os
import requests
from pathlib import Path

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


def test_feed_status_code():
    resp = requests.get(f"{BASE_URL}/api/feed")
    assert resp.status_code == 200


def test_feed_response_structure():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    assert "entries" in data
    assert "indicator_index" in data
    assert "entry_count" in data
    assert isinstance(data["entries"], list)
    assert len(data["entries"]) == 15
    assert data["entry_count"] == 15


def test_feed_cache_control_header():
    resp = requests.get(f"{BASE_URL}/api/feed")
    cache_control = resp.headers.get("Cache-Control", "")
    assert "no-store" in cache_control


def test_feed_category_counts():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    counts = {}
    for e in data["entries"]:
        cat = e.get("_category")
        counts[cat] = counts.get(cat, 0) + 1
    assert counts.get("malicious-skills") == 3
    assert counts.get("mcp-threats") == 3
    assert counts.get("slopsquatting") == 3
    assert counts.get("platform-vulns") == 2
    assert counts.get("incidents") == 2
    assert counts.get("agent-tool-cves") == 2


def test_agent_tool_cves_have_source_attribution():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    cve_entries = [e for e in data["entries"] if e.get("_category") == "agent-tool-cves"]
    assert len(cve_entries) == 2
    for e in cve_entries:
        assert "source_attribution" in e
        assert "vibe-radar-ten.vercel.app" in e["source_attribution"]["url"]


def test_non_cve_entries_have_no_source_attribution():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    non_cve_entries = [e for e in data["entries"] if e.get("_category") != "agent-tool-cves"]
    for e in non_cve_entries:
        assert "source_attribution" not in e


def test_indicator_index_lookup():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    assert "react-codeshift" in data["indicator_index"]
    assert data["indicator_index"]["react-codeshift"] == ["2026-01-react-codeshift"]


def test_no_mongo_id_leak():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    for e in data["entries"]:
        assert "_id" not in e
