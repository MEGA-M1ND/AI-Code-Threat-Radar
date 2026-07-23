"""
Tests for GET /api/feed - thin read-only proxy serving static feed.json.
No DB usage; verifies structure, counts, cache headers, and that every entry
is backed by real, HTTP(S) references (the feed's credibility guarantee).
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

# The feed is intentionally small and fully sourced. Update these when entries
# change (and re-run scripts/build_indicator_index.py to regenerate the index).
EXPECTED_ENTRY_COUNT = 4
EXPECTED_CATEGORY_COUNTS = {
    "incidents": 2,
    "platform-vulns": 1,
    "slopsquatting": 1,
}


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
    assert len(data["entries"]) == EXPECTED_ENTRY_COUNT
    assert data["entry_count"] == EXPECTED_ENTRY_COUNT


def test_entry_count_matches_actual_entries():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    assert data["entry_count"] == len(data["entries"])


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
    assert counts == EXPECTED_CATEGORY_COUNTS


def test_every_entry_has_real_http_references():
    """Credibility guard: no entry ships without at least one HTTP(S) source."""
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    for e in data["entries"]:
        refs = e.get("references", [])
        assert isinstance(refs, list) and len(refs) >= 1, (
            f"entry {e.get('id')} has no references"
        )
        for ref in refs:
            assert isinstance(ref, str) and ref.startswith(("http://", "https://")), (
                f"entry {e.get('id')} has a non-URL reference: {ref!r}"
            )


def test_indicator_index_is_consistent_with_entries():
    """Every indexed indicator must map to real entry IDs that declare it."""
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    entries_by_id = {e["id"]: e for e in data["entries"]}
    for indicator, entry_ids in data["indicator_index"].items():
        for entry_id in entry_ids:
            assert entry_id in entries_by_id, (
                f"indicator {indicator!r} points at unknown entry {entry_id!r}"
            )
            assert indicator in entries_by_id[entry_id].get("indicators", []), (
                f"entry {entry_id!r} does not declare indicator {indicator!r}"
            )


def test_indicator_index_lookup():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    assert "react-codeshift" in data["indicator_index"]
    assert data["indicator_index"]["react-codeshift"] == ["sl-2026-01-react-codeshift"]


def test_no_mongo_id_leak():
    resp = requests.get(f"{BASE_URL}/api/feed")
    data = resp.json()
    for e in data["entries"]:
        assert "_id" not in e
