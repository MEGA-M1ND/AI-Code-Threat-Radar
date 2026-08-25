"""Shared machinery for RADAR collectors.

A collector surfaces *candidates*. A candidate is not an entry and never becomes
one automatically: it lands in triage/queue/ for a human to verify against a
primary source. The feed's credibility rests on that gap staying open.

Three properties every collector has to hold:

* **Idempotent.** Re-running on the same day produces no duplicate candidates.
  The candidate id is a hash of (source, key), so the same finding overwrites
  its own file and only `last_seen` moves.
* **Isolated.** One collector failing must not kill the run. `run_collector`
  catches everything and records the failure.
* **Honest about reachability.** A collector whose source it cannot reach
  reports SKIPPED with the reason, rather than reporting zero findings. Those
  two states look identical in a log and mean opposite things.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Literal

ROOT = Path(__file__).resolve().parent.parent
QUEUE_DIR = ROOT / "triage" / "queue"
STATE_DIR = ROOT / "collectors" / "state"
DISMISSED_PATH = ROOT / "triage" / "dismissed.txt"

Confidence = Literal["high", "medium", "low"]

CATEGORIES = (
    "malicious-skill",
    "slopsquat-package",
    "malicious-mcp-server",
    "malicious-package",
    "compromised-package",
    "platform-vuln",
    "vibe-app-breach",
)

USER_AGENT = (
    "RADAR-collectors/0.1 (+https://github.com/MEGA-M1ND/AI-Code-Threat-Radar) "
    "candidate discovery, read-only"
)


def utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def slug(value: str, limit: int = 60) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return s[:limit] or "unnamed"


@dataclass
class Candidate:
    """One thing worth a human look. Never an entry."""

    source: str                  # which collector found it
    key: str                     # stable identity within that source
    title: str
    why: str                     # why it was flagged, in a sentence
    suggested_category: str
    confidence: Confidence
    evidence: dict[str, Any] = field(default_factory=dict)
    urls: list[str] = field(default_factory=list)
    discovered_at: str = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        if self.suggested_category not in CATEGORIES:
            raise ValueError(
                f"{self.suggested_category!r} is not a RADAR category: {CATEGORIES}"
            )
        if self.confidence not in ("high", "medium", "low"):
            raise ValueError(f"bad confidence {self.confidence!r}")

    @property
    def id(self) -> str:
        digest = hashlib.sha256(f"{self.source}:{self.key}".encode()).hexdigest()[:10]
        return f"{self.source}-{slug(self.key, 40)}-{digest}"

    def path(self, queue_dir: Path = QUEUE_DIR) -> Path:
        return queue_dir / f"{self.id}.json"

    def save(self, queue_dir: Path = QUEUE_DIR) -> tuple[Path, bool]:
        """Write the candidate if it is new or has changed. Returns (path, is_new).

        A queue file is only rewritten when the *finding* changes. The daily run
        would otherwise touch every file it re-confirms, and a triage PR whose
        diff is forty unchanged candidates with a new timestamp is a PR nobody
        reads. "Still seen on this date" is tracked in collector state instead,
        where it costs one line of diff for the whole run.
        """
        queue_dir.mkdir(parents=True, exist_ok=True)
        path = self.path(queue_dir)
        is_new = not path.exists()
        if not is_new:
            try:
                prior = json.loads(path.read_text())
                self.discovered_at = prior.get("discovered_at", self.discovered_at)
            except (json.JSONDecodeError, OSError):
                prior = None
        payload = {"id": self.id, **asdict(self)}
        serialized = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if is_new or serialized != path.read_text():
            path.write_text(serialized)
        return path, is_new


@dataclass
class Result:
    """What one collector did. SKIPPED is not the same as zero findings."""

    name: str
    status: Literal["ok", "skipped", "error"]
    new: int = 0
    seen: int = 0
    dismissed: int = 0
    detail: str = ""

    def line(self) -> str:
        if self.status == "ok":
            tail = f", {self.dismissed} dismissed" if self.dismissed else ""
            return (f"  {self.name:18s} ok       {self.new} new, "
                    f"{self.seen} already queued{tail}")
        if self.status == "skipped":
            return f"  {self.name:18s} SKIPPED  {self.detail}"
        return f"  {self.name:18s} ERROR    {self.detail}"


def load_dismissed(path: Path = DISMISSED_PATH) -> set[str]:
    """Candidate ids and keys a human has already looked at and rejected.

    Without this a triaged-and-rejected candidate reappears on every run: the
    queue file is gone, so the collector has no memory that anyone decided.
    """
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def run_collector(name: str, fn: Callable[[], Iterable[Candidate]],
                  queue_dir: Path = QUEUE_DIR,
                  dismissed: set[str] | None = None) -> Result:
    """Run one collector. Never raises."""
    try:
        candidates = list(fn())
    except SkipCollector as exc:
        return Result(name, "skipped", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - one collector must not kill the run
        return Result(name, "error", detail=f"{type(exc).__name__}: {exc}".replace("\n", " ")[:160])

    if dismissed is None:
        dismissed = load_dismissed()

    new = seen = dropped = 0
    today = utcnow()[:10]
    still_seen = load_state("seen")
    for candidate in candidates:
        if candidate.id in dismissed or candidate.key in dismissed:
            dropped += 1
            continue
        _, is_new = candidate.save(queue_dir)
        still_seen[candidate.id] = today
        new += is_new
        seen += not is_new
    # A candidate whose file a human has triaged away no longer needs tracking.
    live = {p.stem for p in queue_dir.glob("*.json")} if queue_dir.exists() else set()
    save_state("seen", {k: v for k, v in still_seen.items() if k in live})
    return Result(name, "ok", new=new, seen=seen, dismissed=dropped)


class SkipCollector(Exception):
    """Raised when a source is unreachable or unconfigured.

    Distinct from an error: it means "could not look", not "looked and found
    nothing". Reported as SKIPPED with the reason.
    """


# --------------------------------------------------------------------------
# state + http
# --------------------------------------------------------------------------

def state_path(name: str, state_dir: Path = STATE_DIR) -> Path:
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir / f"{name}.json"


def load_state(name: str, default: Any = None, state_dir: Path = STATE_DIR) -> Any:
    path = state_path(name, state_dir)
    if not path.exists():
        return {} if default is None else default
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return {} if default is None else default


def save_state(name: str, value: Any, state_dir: Path = STATE_DIR) -> None:
    state_path(name, state_dir).write_text(
        json.dumps(value, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )


def get_json(url: str, timeout: int = 20, retries: int = 2) -> Any:
    """GET JSON, or raise SkipCollector if the host is not reachable from here.

    Reachability is environment-dependent: a sandbox may allow the package
    registries and refuse the vendor blogs. That is a skip, not a failure.
    """
    import requests

    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            resp = requests.get(url, timeout=timeout, headers={
                "User-Agent": USER_AGENT, "Accept": "application/json"})
            if resp.status_code == 429:
                # A registry saying "slow down" wants seconds, not milliseconds.
                time.sleep(float(resp.headers.get("Retry-After") or 5 * (attempt + 1)))
                last = RuntimeError("rate limited (429)")
                continue
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            last = exc
            if attempt < retries:
                time.sleep(1 + attempt)
    raise SkipCollector(f"{url} unreachable: {type(last).__name__}: {last}"[:200])


def get_conditional(url: str, etag: str | None = None, timeout: int = 60,
                    accept: str = "application/json") -> tuple[Any, str | None, bool]:
    """GET with an If-None-Match. Returns (payload, etag, changed).

    The PyPI name index is 43 MB and changes constantly but not every hour.
    A 304 is a real answer — nothing new has been published — so it is worth
    the round trip to avoid parsing 878k names for nothing.
    """
    import requests

    headers = {"User-Agent": USER_AGENT, "Accept": accept,
               "Accept-Encoding": "gzip"}
    if etag:
        headers["If-None-Match"] = etag
    try:
        resp = requests.get(url, timeout=timeout, headers=headers)
    except Exception as exc:  # noqa: BLE001
        raise SkipCollector(f"{url} unreachable: {type(exc).__name__}: {exc}"[:200])
    if resp.status_code == 304:
        return None, etag, False
    if resp.status_code >= 400:
        raise SkipCollector(f"{url} returned HTTP {resp.status_code}")
    return resp.json(), resp.headers.get("ETag"), True


__all__ = [
    "Candidate", "Result", "SkipCollector", "run_collector", "load_dismissed",
    "load_state", "save_state", "get_json", "get_text", "utcnow", "slug",
    "QUEUE_DIR", "STATE_DIR", "ROOT", "CATEGORIES", "DISMISSED_PATH",
]
