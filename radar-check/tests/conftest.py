import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIXTURES = ROOT / "fixtures"
# The scanner is only meaningful against a real feed, and the repo builds one.
FEED_PATH = ROOT.parent / "dist" / "feed.json"


@pytest.fixture(scope="session")
def feed():
    if not FEED_PATH.exists():
        pytest.skip("dist/feed.json not built")
    return json.loads(FEED_PATH.read_text())


@pytest.fixture(scope="session")
def index(feed):
    from radar_check.feed import FeedIndex
    return FeedIndex(feed)


@pytest.fixture
def seeded():
    return FIXTURES / "seeded"


@pytest.fixture
def clean():
    return FIXTURES / "clean"
