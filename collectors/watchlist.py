"""The names an attacker would squat to reach AI coding agent users.

Two lists, and keeping them apart matters:

* **watchlist** — *legitimate* names worth impersonating. New registry packages
  are scored by how close they sit to one of these.
* **known bad** — names already in the feed as malicious. An exact hit on one of
  these is not "close to a legitimate name", it is a republication of something
  already catalogued, and it is scored high immediately.

Mixing them would be a real bug: `claud-code` is a confirmed typosquat, so if it
sat in the watchlist a fresh package by that exact name would score as a
zero-distance match on a legitimate name — the opposite of what it is.
"""
from __future__ import annotations

import json
from pathlib import Path

from .base import ROOT

WATCHLIST_PATH = Path(__file__).resolve().parent / "watchlist.txt"
FEED_PATH = ROOT / "dist" / "feed.json"

# Names that are not in the feed but are exactly what an attacker aims at.
CURATED = """
claude claude-code claude-agent-sdk anthropic anthropic-sdk
codex codex-cli openai openai-agents gemini gemini-cli google-genai
cursor windsurf copilot github-copilot @github/copilot amazon-q aws-toolkit-vscode
mcp mcp-sdk mcp-server mcp-client mcp-use modelcontextprotocol
fastmcp mcp-agent mcp-proxy mcp-inspector mcp-scan
langchain langchain-core langgraph llamaindex llama-index crewai autogen
openclaw clawhub moltbot clawdbot
agent-sdk agent-tools agent-skills skill-md
tiktoken transformers huggingface-hub sentence-transformers
""".split()

# Categories whose package indicators name something that was *legitimate*.
LEGITIMATE_CATEGORIES = {"compromised-package", "platform-vuln"}
# Categories whose package indicators name something malicious outright.
MALICIOUS_CATEGORIES = {
    "slopsquat-package", "malicious-package",
    "malicious-mcp-server", "malicious-skill",
}


def _feed(feed_path: Path = FEED_PATH) -> dict:
    if not feed_path.exists():
        raise FileNotFoundError(
            f"{feed_path} not found — run scripts/build_feed.py first"
        )
    return json.loads(feed_path.read_text())


def from_feed(feed_path: Path = FEED_PATH) -> tuple[set[str], set[str]]:
    """Return (legitimate names, known-bad names) drawn from the feed."""
    feed = _feed(feed_path)
    legit: set[str] = set()
    bad: set[str] = set()
    for entry in feed["entries"]:
        bucket = (
            legit if entry["category"] in LEGITIMATE_CATEGORIES
            else bad if entry["category"] in MALICIOUS_CATEGORIES
            else None
        )
        if bucket is None:
            continue
        for ind in entry["indicators"]:
            if ind["type"] != "package" or ind["registry"] not in ("npm", "pypi"):
                continue
            name = ind["name"]
            bucket.add(name)
            # A compromised scoped package makes its whole scope worth watching.
            if bucket is legit and name.startswith("@") and "/" in name:
                legit.add(name.split("/", 1)[0])
    return legit, bad


def load(path: Path = WATCHLIST_PATH) -> list[str]:
    if not path.exists():
        return sorted(set(CURATED))
    names = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            names.append(line)
    return names


def known_bad(feed_path: Path = FEED_PATH) -> set[str]:
    try:
        return from_feed(feed_path)[1]
    except FileNotFoundError:
        return set()


def refresh(path: Path = WATCHLIST_PATH, feed_path: Path = FEED_PATH) -> list[str]:
    """Rewrite watchlist.txt from CURATED plus the feed's legitimate names."""
    legit, bad = from_feed(feed_path)
    names = sorted(set(CURATED) | legit)
    overlap = sorted(set(names) & bad)
    assert not overlap, f"watchlist must not contain known-bad names: {overlap}"
    path.write_text(
        "# Legitimate names worth impersonating, for the slopsquat detector to\n"
        "# score new registry packages against. Confirmed-malicious names live in\n"
        "# the feed, not here — see collectors/watchlist.py for why that matters.\n"
        "#\n"
        "# Regenerate: python -m collectors.watchlist --refresh\n\n"
        + "\n".join(names) + "\n"
    )
    return names


if __name__ == "__main__":
    import sys
    if "--refresh" in sys.argv:
        names = refresh()
        legit, bad = from_feed()
        print(f"watchlist: {len(names)} legitimate names "
              f"({len(CURATED)} curated + {len(legit)} from the feed)")
        print(f"known bad (excluded, matched separately): {len(bad)}")
    else:
        print("\n".join(load()))
