"""Getting the feed, and being clear about which copy you got.

Three sources, tried in order: an explicit path, a cached download, the
network. A scan that silently ran against a six-month-old cache is worse than
one that failed, so the origin travels into the report and is printed.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

FEED_URL = os.environ.get(
    "RADAR_FEED_URL",
    "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/feed.json",
)
CACHE_DIR = Path(os.environ.get(
    "RADAR_CACHE_DIR", Path.home() / ".cache" / "radar-check"))
CACHE_PATH = CACHE_DIR / "feed.json"
CACHE_MAX_AGE = 6 * 3600


class FeedUnavailable(RuntimeError):
    """No copy of the feed could be obtained. Never scan without one."""


def _read(path: Path) -> dict:
    """Read a feed file, turning every failure into FeedUnavailable.

    The caller's contract is that it exits 2 rather than scanning without data,
    and it can only honour that if failures arrive as one exception type. A
    FileNotFoundError escaping here is a traceback where the user needed a
    sentence.
    """
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as error:
        raise FeedUnavailable(f"{path} does not exist") from error
    except OSError as error:
        raise FeedUnavailable(f"could not read {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise FeedUnavailable(f"{path} is not valid JSON: {error}") from error
    if not isinstance(data, dict) or "entries" not in data:
        raise FeedUnavailable(f"{path} is not a RADAR feed")
    return data


def _download(url: str, timeout: int) -> dict:
    import urllib.request
    request = urllib.request.Request(url, headers={
        "User-Agent": "radar-check (+https://github.com/MEGA-M1ND/AI-Code-Threat-Radar)",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def load(path: str | None = None, offline: bool = False, refresh: bool = False,
         timeout: int = 20) -> tuple[dict, str]:
    """Return (feed, origin). Origin is one of file, cache, network, stale-cache."""
    if path:
        return _read(Path(path)), f"file:{path}"

    fresh_cache = (
        CACHE_PATH.is_file()
        and (time.time() - CACHE_PATH.stat().st_mtime) < CACHE_MAX_AGE
    )
    if fresh_cache and not refresh:
        return _read(CACHE_PATH), "cache"

    if offline:
        if CACHE_PATH.is_file():
            return _read(CACHE_PATH), "stale-cache"
        raise FeedUnavailable(
            "--offline was given and there is no cached feed. Run once without "
            "it, or pass --feed with a downloaded feed.json.")

    try:
        feed = _download(FEED_URL, timeout)
    except Exception as error:  # noqa: BLE001 - any failure falls back the same way
        if CACHE_PATH.is_file():
            return _read(CACHE_PATH), "stale-cache"
        raise FeedUnavailable(
            f"could not fetch {FEED_URL} ({type(error).__name__}: {error}) and "
            "there is no cached copy") from error

    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_PATH.write_text(json.dumps(feed))
    return feed, "network"


# ---------------------------------------------------------------------------
# indexing
# ---------------------------------------------------------------------------

# Categories naming an artifact that was never legitimate. A match on the name
# alone is enough; anywhere else the version has to match too.
MALICIOUS_CATEGORIES = frozenset({
    "slopsquat-package", "malicious-package", "malicious-mcp-server",
    "malicious-skill",
})


class FeedIndex:
    """Lookup tables built once per scan."""

    def __init__(self, feed: dict):
        self.feed = feed
        self.packages: dict[tuple[str, str], list[tuple[dict, dict]]] = {}
        self.skills: dict[str, list[tuple[dict, dict]]] = {}
        self.mcp_servers: dict[str, list[tuple[dict, dict]]] = {}
        self.domains: dict[str, list[tuple[dict, dict]]] = {}

        for entry in feed.get("entries", []):
            for indicator in entry.get("indicators", []):
                pair = (entry, indicator)
                kind = indicator["type"]
                if kind == "package":
                    key = (indicator.get("registry", ""), indicator["name"].lower())
                    self.packages.setdefault(key, []).append(pair)
                elif kind == "skill":
                    self.skills.setdefault(indicator["slug"].lower(), []).append(pair)
                elif kind == "mcp-server" and indicator.get("name"):
                    self.mcp_servers.setdefault(indicator["name"].lower(), []).append(pair)
                elif kind in ("domain", "url"):
                    value = (indicator.get("value") or "").lower()
                    if value:
                        self.domains.setdefault(value, []).append(pair)

    @staticmethod
    def is_malicious(entry: dict) -> bool:
        return entry["category"] in MALICIOUS_CATEGORIES

    @staticmethod
    def primary_source(entry: dict) -> str:
        for source in entry.get("sources", []):
            if source.get("type") == "primary":
                return source["url"]
        return entry.get("sources", [{}])[0].get("url", "")

    def legitimate_names(self, registry: str) -> set[str]:
        """Names in the feed that belong to legitimate software.

        Used as near-miss targets. A malicious name must never end up here: a
        fresh copy of a known typosquat would then score as a zero-distance
        match on a *legitimate* name, which is the opposite of the truth.
        """
        return {
            name for (reg, name), pairs in self.packages.items()
            if reg == registry and not any(self.is_malicious(e) for e, _ in pairs)
        }
