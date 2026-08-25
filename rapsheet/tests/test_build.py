"""The build must be deterministic and the blocklist must be complete."""
import json

import pytest

import build as B
import validate as V


@pytest.fixture(scope="module")
def dist(tmp_path_factory):
    out = tmp_path_factory.mktemp("dist")
    B.build(dist_dir=out)
    return out


def read(dist, name):
    return json.loads((dist / name).read_text())


def test_build_is_deterministic(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    B.build(dist_dir=first)
    B.build(dist_dir=second)
    names = sorted(p.name for p in first.glob("*.json"))
    assert names == sorted(p.name for p in second.glob("*.json"))
    for name in names:
        assert (first / name).read_bytes() == (second / name).read_bytes(), name


def test_feed_contains_every_entry(dist):
    feed = read(dist, "feed.json")
    assert feed["entry_count"] == len(feed["entries"])
    assert feed["entry_count"] == len(V.load_entries())


def test_feed_entries_are_sorted_by_id(dist):
    ids = [e["id"] for e in read(dist, "feed.json")["entries"]]
    assert ids == sorted(ids)


def test_feed_carries_licence_and_attribution(dist):
    for name in ["feed.json", "blocklist.json"]:
        payload = read(dist, name)
        assert payload["license"] == "CC-BY-4.0"
        assert "CC BY 4.0" in payload["attribution"]
        assert payload["schema_version"]


def test_category_feeds_partition_the_full_feed(dist):
    feed = read(dist, "feed.json")
    collected = []
    for category in B.CATEGORIES:
        sub = read(dist, f"feed-{category}.json")
        assert all(e["category"] == category for e in sub["entries"])
        assert sub["entry_count"] == len(sub["entries"])
        collected.extend(e["id"] for e in sub["entries"])
    assert sorted(collected) == sorted(e["id"] for e in feed["entries"])


def test_every_category_has_a_file(dist):
    for category in B.CATEGORIES:
        assert (dist / f"feed-{category}.json").exists()


def test_blocklist_is_complete(dist):
    """Every indicator on every entry has to reach the blocklist."""
    feed = read(dist, "feed.json")
    blocklist = read(dist, "blocklist.json")

    def key(entry_id, indicator):
        return (entry_id, json.dumps(indicator, sort_keys=True))

    got = set()
    for row in blocklist["indicators"]:
        indicator = {
            k: v
            for k, v in row.items()
            if k not in {"id", "severity", "category", "status", "source"}
        }
        got.add(key(row["id"], indicator))

    want = {key(e["id"], i) for e in feed["entries"] for i in e["indicators"]}
    assert want == got
    assert blocklist["indicator_count"] == len(blocklist["indicators"])


def test_blocklist_rows_carry_triage_context(dist):
    """A guard needs category and status to avoid blocking a legitimate package."""
    for row in read(dist, "blocklist.json")["indicators"]:
        assert row["id"].startswith("RS-")
        assert row["severity"] in {"critical", "high", "medium", "low"}
        assert row["category"] in B.CATEGORIES
        assert row["status"] in {"active", "remediated", "disputed"}
        assert row["source"].startswith("https://")


def test_blocklist_source_prefers_a_primary(dist):
    feed = {e["id"]: e for e in read(dist, "feed.json")["entries"]}
    for row in read(dist, "blocklist.json")["indicators"]:
        entry = feed[row["id"]]
        primaries = {s["url"] for s in entry["sources"] if s["type"] == "primary"}
        assert row["source"] in primaries


def test_build_refuses_a_bad_entry(tmp_path):
    bad = tmp_path / "entries"
    bad.mkdir()
    (bad / "RS-9999-0001.json").write_text(json.dumps({"id": "RS-9999-0001"}))
    with pytest.raises(SystemExit):
        B.build(entries_dir=bad, dist_dir=tmp_path / "dist")
