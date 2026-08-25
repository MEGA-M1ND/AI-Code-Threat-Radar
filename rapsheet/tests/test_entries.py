"""Rules that every real entry in data/entries/ has to satisfy."""
import re

import pytest

import validate as V

ENTRIES = [entry for _, entry in V.load_entries()]
IDS = [e["id"] for e in ENTRIES]
DEFANGED = re.compile(r"\[\.\]|hxxp|\[:\]|\(dot\)", re.IGNORECASE)


def test_there_are_entries():
    assert len(ENTRIES) >= 25


def test_full_validation_passes():
    assert V.validate(quiet=True) == []


def test_ids_are_unique():
    assert len(IDS) == len(set(IDS))


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_entry_has_a_primary_source(entry):
    assert any(s["type"] == "primary" for s in entry["sources"])


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_indicators_are_not_defanged(entry):
    """A guard matches on the real string, so indicators are stored live."""
    for indicator in entry["indicators"]:
        for key, value in indicator.items():
            if isinstance(value, str):
                assert not DEFANGED.search(value), f"{entry['id']}: {key}={value!r} is defanged"


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_source_urls_are_https_and_distinct(entry):
    urls = [s["url"] for s in entry["sources"]]
    assert all(u.startswith("https://") for u in urls)
    assert len(urls) == len(set(urls))


@pytest.mark.parametrize("entry", ENTRIES, ids=IDS)
def test_hashes_are_lowercase_and_the_right_length(entry):
    lengths = {"md5": 32, "sha1": 40, "sha256": 64, "sha512": 128}
    for indicator in entry["indicators"]:
        if indicator["type"] == "hash":
            assert indicator["value"] == indicator["value"].lower()
            assert len(indicator["value"]) == lengths[indicator["algo"]]
