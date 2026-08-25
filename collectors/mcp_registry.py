"""MCP registry collector — new servers worth a second look.

The official MCP registry is open publication: anyone can list a server, and
nothing there has been reviewed. That makes it the natural place to find
`malicious-mcp-server` candidates, and it also makes it noisy — roughly 2,500
records move in a week, a good share of them bulk-generated. So this reports
only on *substantive* signals, never on "new and unfamiliar":

* **A package identifier that impersonates something.** 468 of the first 800
  servers ship an npm or PyPI package. If that package name is a squat, the
  server shipping it is the story, and the same matcher that finds slopsquats
  finds it.
* **A listing borrowing a well-known repository.** The registry verifies the
  `io.github.alice` namespace against GitHub; the repository URL is the
  unverified half. A listing by `io.github.alice` pointing at
  `github.com/anthropics/…` is attaching someone else's reputation to itself.
  Note the narrowness: mismatch *in general* is not reported. Across 2,500
  records it fired 21 times and every one was a person publishing under their
  personal account with the code in their company org — benign, and exactly
  the kind of finding that teaches a triager to stop reading the queue. It is
  recorded as evidence instead.
* **A server that disappeared.** Going from active to deleted or deprecated
  often follows a report, and the entry is the last chance to read what it
  claimed before it is gone.

Everything else — no repository, an unrelated remote host — is recorded as
evidence on a candidate that already qualified, never as a reason to open one.

Nothing here writes to the feed. Every finding lands in triage/queue/.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlparse

from .base import Candidate, SkipCollector, get_json, load_state, save_state, utcnow
from .similarity import ALL_RULES, SquatMatcher, levenshtein
from .watchlist import known_bad, load as load_watchlist

NAME = "mcp-registry"

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
PAGE_SIZE = 100
# Pages per run. The registry moves ~2,500 records a week, so this clears a
# day's churn several times over and still bounds a cold start.
PAGE_BUDGET = 40
# How far back the first run reaches when there is no watermark yet.
COLD_START_DAYS = 7
GONE_STATUSES = {"deleted", "deprecated"}

# GitHub owners whose name on a listing is worth something. A stranger's
# listing pointing at one of these repositories is borrowing that reputation;
# a listing *claiming* one of these namespaces and pointing elsewhere is worse.
# Deliberately short: every name here has to be one a user would trust on sight.
REPUTABLE_OWNERS = {
    "anthropics", "modelcontextprotocol", "openai", "google-gemini",
    "googleapis", "google", "github", "microsoft", "getcursor", "langchain-ai",
    "run-llama", "crewaiinc", "huggingface", "docker", "stripe", "slackapi",
    "makenotion", "cloudflare", "supabase", "browserbase", "postmanlabs",
    "atlassian", "jetbrains", "getsentry", "elastic", "mongodb", "redis",
    "aws", "awslabs", "hashicorp", "grafana", "figma", "vercel", "sourcegraph",
}


def _official(record: dict) -> dict:
    meta = record.get("_meta") or {}
    return meta.get("io.modelcontextprotocol.registry/official") or {}


def _github_owner(url: str) -> str | None:
    if not url or "github.com/" not in url:
        return None
    return url.split("github.com/", 1)[1].split("/")[0].lower() or None


def _claimed_owner(name: str) -> str | None:
    """`io.github.alice/thing` claims to be published by GitHub user alice."""
    if not name.startswith("io.github."):
        return None
    return name[len("io.github."):].split("/")[0].lower() or None


def _same_hands(a: str, b: str) -> bool:
    """True if two owner names are one party, not two.

    `csoai-org` and `csao-org` differ by a transposition; `agentsgetpaid` is a
    prefix of `agentsgetpaidmore`; `aion-autonomous-org` and
    `aion-autonomous-labs` share sixteen characters before diverging. Each is a
    publisher tripping over their own name or renaming an org, and none is an
    identity being borrowed.

    This only ever suppresses the evidence flag. A mismatch involving a
    reputable owner is reported whatever this returns, because
    `io.github.anthropic-official` pointing at `anthropics/` is precisely the
    case a same-hands heuristic would talk itself out of.
    """
    if a in b or b in a or levenshtein(a, b, 2) <= 2:
        return True
    shared = 0
    for x, y in zip(a, b):
        if x != y:
            break
        shared += 1
    return shared >= 8


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def walk(state: dict, page_budget: int = PAGE_BUDGET):
    """Yield registry records updated since the watermark, resumably.

    Records come back ordered by name, not by update time, so a partial walk
    cannot advance the watermark — it would skip whatever it did not reach.
    The cursor is persisted instead and the same window resumes next run.
    """
    since = state.get("updated_since") or (
        datetime.now(timezone.utc) - timedelta(days=COLD_START_DAYS)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    started = utcnow()
    cursor = state.get("cursor")
    pages = 0

    while pages < page_budget:
        url = f"{REGISTRY}?limit={PAGE_SIZE}&version=latest&updated_since={quote(since)}"
        if cursor:
            url += f"&cursor={quote(cursor)}"
        payload = get_json(url, timeout=30, retries=1)
        for record in payload.get("servers", []):
            yield record
        pages += 1
        cursor = (payload.get("metadata") or {}).get("nextCursor")
        if not cursor:
            state["updated_since"] = started
            state["cursor"] = None
            state["last_walk"] = {"pages": pages, "completed": True, "window_from": since}
            return

    state["cursor"] = cursor
    state["last_walk"] = {"pages": pages, "completed": False, "window_from": since}
    state.setdefault("warnings", []).append(
        f"page budget {page_budget} reached; resuming from cursor next run")


def signals(server: dict, matcher: SquatMatcher,
            bad: set[str]) -> tuple[list[tuple[str, str, str]], bool]:
    """Reasons to open a candidate, and whether the namespace merely mismatched.

    Returns (findings, namespace_mismatch). A finding is (rule, confidence,
    why); the flag is evidence, never a reason on its own.
    """
    found: list[tuple[str, str, str]] = []

    claimed = _claimed_owner(server.get("name", ""))
    repo_url = (server.get("repository") or {}).get("url", "")
    actual = _github_owner(repo_url)
    differ = bool(claimed and actual and claimed != actual)
    mismatch = differ and not _same_hands(claimed, actual)
    if differ and (actual in REPUTABLE_OWNERS or claimed in REPUTABLE_OWNERS):
        found.append((
            "borrowed-repository", "high",
            f"the registry verified this listing as GitHub user {claimed}, but it "
            f"points at a repository belonging to {actual}",
        ))

    for package in server.get("packages") or []:
        identifier = package.get("identifier") or ""
        registry = package.get("registryType") or "?"
        if not identifier:
            continue
        if identifier.lower() in bad:
            found.append((
                "known-bad-package", "high",
                f"ships {registry} package {identifier}, which the feed already "
                "documents as malicious",
            ))
            continue
        match = matcher.match(identifier)
        if match:
            found.append((
                f"package-{match.rule}", match.confidence,
                f"ships {registry} package {identifier}, {match.why()}",
            ))
    return found, mismatch


def collect(page_budget: int = PAGE_BUDGET):
    state = load_state(NAME)
    state.pop("warnings", None)
    matcher = SquatMatcher(load_watchlist(), max_distance=2, rules=ALL_RULES)
    bad = {n.lower() for n in known_bad()}
    statuses: dict[str, str] = state.setdefault("statuses", {})

    seen = 0
    try:
        for record in walk(state, page_budget):
            server = record.get("server") or {}
            name = server.get("name")
            if not name:
                continue
            seen += 1
            official = _official(record)
            status = official.get("status", "")
            was = statuses.get(name)
            statuses[name] = status

            found, mismatch = signals(server, matcher, bad)
            if was and was != status and status in GONE_STATUSES:
                found.append((
                    "status-change", "medium",
                    f"the registry moved this server from {was} to {status}",
                ))
            if not found:
                continue

            rule, confidence, why = min(
                found, key=lambda f: {"high": 0, "medium": 1, "low": 2}[f[1]])
            remotes = [r.get("url", "") for r in (server.get("remotes") or [])]
            yield Candidate(
                source=NAME,
                key=f"mcp:{name}",
                title=f"MCP server {name}: {rule.replace('-', ' ')}",
                why=why,
                suggested_category="malicious-mcp-server",
                confidence=confidence,
                evidence={
                    "server": name,
                    "rule": rule,
                    "version": server.get("version"),
                    "status": status,
                    "description": (server.get("description") or "")[:200],
                    "repository": (server.get("repository") or {}).get("url", ""),
                    "website": server.get("websiteUrl", ""),
                    "packages": [f'{p.get("registryType")}:{p.get("identifier")}'
                                 for p in (server.get("packages") or [])][:5],
                    "remote_hosts": sorted({_host(u) for u in remotes if u}),
                    # Not a trigger on its own — an unauditable server is
                    # common. It matters once something else already flagged it.
                    "unauditable": not server.get("repository"),
                    # Common and usually benign — a person publishing with the
                    # code in their company org. Worth seeing once something
                    # else has already flagged the listing.
                    "namespace_mismatch": mismatch,
                    "published_at": official.get("publishedAt"),
                    "all_signals": [f[0] for f in found],
                },
                urls=[u for u in ([(server.get("repository") or {}).get("url", ""),
                                   server.get("websiteUrl", "")] + remotes) if u][:4],
            )
    finally:
        state["last_seen_count"] = seen
        # The status map is the only reason a vanished server can be reported,
        # so it is kept for every server ever walked, not just flagged ones.
        save_state(NAME, state)


def main() -> int:
    from .base import run_collector

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--page-budget", type=int, default=PAGE_BUDGET)
    args = parser.parse_args()
    result = run_collector(NAME, lambda: collect(args.page_budget))
    print(result.line())
    return 0 if result.status != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
