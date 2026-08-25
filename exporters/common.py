"""Shared decisions every exporter has to make the same way.

The hard part of exporting this feed is not the file format. It is deciding
what a guard should *do* with each indicator, and that decision cannot be read
off the indicator alone:

* A `platform-vuln` entry names a package the developer is entitled to use.
  Blocking `@anthropic-ai/claude-code` because a version of it had a bug would
  be worse than the bug.
* A `compromised-package` entry names a package that was trustworthy before and
  after the incident. Only the listed versions are bad.
* A `slopsquat-package` or `malicious-package` entry names something that was
  never legitimate. The name itself is the indicator.

So the action is derived from category, status and whether the entry pins
versions — never from severity alone. Getting this wrong produces exactly the
false positive the sourcing standard exists to prevent.
"""
from __future__ import annotations

from datetime import datetime, timezone

# Categories whose named artifact is malicious in itself. The name is enough.
MALICIOUS_CATEGORIES = frozenset({
    "slopsquat-package", "malicious-package", "malicious-mcp-server",
    "malicious-skill",
})
# Categories that name something legitimate which had, or has, a problem.
# Blocking the name would deny the developer software they are entitled to run.
LEGITIMATE_CATEGORIES = frozenset({"platform-vuln", "compromised-package"})

BLOCK, WARN, MONITOR = "block", "warn", "monitor"


def decide_action(entry: dict, indicator: dict) -> tuple[str, str]:
    """Return (action, why) for one indicator of one entry.

    `block` means the artifact should not be installed or loaded at all.
    `warn` means match it, tell the user, and let them decide — used wherever
    the name is legitimate and only some versions are not.
    `monitor` is for a remediated malicious artifact: worth flagging if it turns
    up, not worth an alarm.
    """
    category, status = entry["category"], entry["status"]

    if category in LEGITIMATE_CATEGORIES:
        if _pins_versions(indicator):
            return WARN, ("a legitimate artifact with specific affected versions; "
                          "match the version, never the bare name")
        return WARN, ("a legitimate artifact named by an entry that does not pin "
                      "versions; surface it, do not block it")

    if category not in MALICIOUS_CATEGORIES:
        # vibe-app-breach names a deployed application, not something installed.
        return MONITOR, "not an installable artifact; informational"

    if status == "disputed":
        return WARN, "the entry is disputed and the claim is not settled"
    if status == "remediated":
        return MONITOR, ("removed from its registry; a reappearance is worth "
                         "flagging but is not a live threat")
    return BLOCK, "malicious as published and still reachable"


def _pins_versions(indicator: dict) -> bool:
    if indicator.get("version"):
        return True
    affected = indicator.get("affected") or {}
    return bool(affected.get("versions") or affected.get("ranges"))


def indicator_value(indicator: dict) -> str:
    """The bare string a scanner matches on."""
    for key in ("name", "slug", "value", "url", "repo"):
        if indicator.get(key):
            return str(indicator[key])
    return ""


def feed_epoch(last_updated: str) -> int:
    """Midnight UTC of the feed's own last_updated date, as a Unix timestamp.

    Exporters need a timestamp and the build must stay deterministic, so the
    time comes from the data rather than from the clock. Rebuilding an
    unchanged feed a year later produces the same bytes.
    """
    parsed = datetime.strptime(last_updated, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def feed_version(last_updated: str) -> int:
    """A monotonic integer version derived from the feed date, e.g. 20260825.

    Consumers that reject a bundle older than the one they hold need this to
    increase. It does so as long as the feed's last_updated does.
    """
    return int(last_updated.replace("-", ""))
