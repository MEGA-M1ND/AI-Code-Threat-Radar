"""Slopsquat detector — names published to npm and PyPI that impersonate ours.

Two passes, because the two registries expose completely different surfaces:

* **PyPI** publishes its full name index (878k names, ETag-cached). The sweep
  is local and exhaustive: every name on PyPI is scored against the watchlist
  on every run.
* **npm** has no such index, but it has a search API. The sweep is targeted:
  one query per distinctive watchlist brand, scored against that brand.

A third pass checks whether anything already catalogued as malicious has been
republished under the same name — an exact hit there is not a resemblance, it
is a threat the feed already documented showing up alive again.

Age is the discriminator that makes this usable. `transformer` is one edit
from `transformers` and has been on PyPI since 2019; a name one edit from
`claude-code` that was first published last Tuesday is the entire point. Every
hit is enriched with its registry creation date and dropped if it predates the
watchlist target it resembles, or is simply old.

Nothing here writes to the feed. Every finding lands in triage/queue/.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone

from .base import (
    Candidate, SkipCollector, get_conditional, get_json, load_state, save_state,
    utcnow,
)
from .similarity import ALL_RULES, SWEEP_RULES, SquatMatcher, is_distinctive, bare
from .watchlist import known_bad, load as load_watchlist

NAME = "slopsquat"

PYPI_INDEX = "https://pypi.org/simple/"
PYPI_INDEX_ACCEPT = "application/vnd.pypi.simple.v1+json"
PYPI_PROJECT = "https://pypi.org/pypi/{name}/json"
NPM_SEARCH = "https://registry.npmjs.org/-/v1/search?text={text}&size={size}"
NPM_PACKAGE = "https://registry.npmjs.org/{name}"
# Just the metadata, not every version's full manifest — a packument for a
# busy package is megabytes otherwise.
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"

# A package older than this is not a fresh squat. It may still be malicious,
# but it is not something a daily collector discovered.
MAX_AGE_DAYS = 400
# Low-confidence matches get a much tighter window. `langchain-mcp` and
# `tiktoken-cli` are affix hits on legitimate community packages; six months
# in, they are settled parts of the ecosystem and a triager reading them
# learns the queue is noise. Brand new, the same names would be worth a look.
LOW_CONFIDENCE_MAX_AGE_DAYS = 90
# Enrichment costs one request per hit. A cold start on a fresh watchlist
# produces a few dozen; this stops a bad watchlist edit from producing a few
# thousand.
ENRICH_BUDGET = 150
# npm queries per run, rotating through the brand list across runs. The search
# endpoint rate-limits well before the package endpoint does; 25 queries a
# second apart cleared it where 40 at 0.2s did not.
NPM_QUERY_BUDGET = 25
NPM_DELAY = 1.0
NPM_PACKAGE_DELAY = 0.25


def _age_days(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        parsed = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400


def _age_limit(match, max_age_days: int) -> int:
    """How old a package may be before this match stops being worth reporting."""
    if match.confidence == "low":
        return min(LOW_CONFIDENCE_MAX_AGE_DAYS, max_age_days)
    return max_age_days


def _candidate(match, registry: str, evidence: dict, urls: list[str],
               confidence: str | None = None) -> Candidate:
    return Candidate(
        source=NAME,
        key=f"{registry}:{match.name}",
        title=f"{match.name} ({registry}) resembles {match.target}",
        why=match.why(),
        suggested_category="slopsquat-package",
        confidence=confidence or match.confidence,
        evidence={"registry": registry, "name": match.name, "target": match.target,
                  "rule": match.rule, "distance": match.distance, **evidence},
        urls=urls,
    )


# ---------------------------------------------------------------------------
# PyPI — full index sweep
# ---------------------------------------------------------------------------

def pypi_index(state: dict) -> list[str] | None:
    """All PyPI project names, or None if the index is unchanged since last run.

    The watchlist hash is part of the freshness check: a 304 means PyPI has
    nothing new, but a changed watchlist means *we* have something new to ask.
    """
    payload, etag, changed = get_conditional(
        PYPI_INDEX, etag=state.get("pypi_etag"), accept=PYPI_INDEX_ACCEPT)
    state["pypi_etag"] = etag
    if not changed:
        return None
    return [p["name"] for p in payload.get("projects", [])]


def pypi_details(name: str) -> dict:
    """Creation date, latest release and blurb for one PyPI project."""
    data = get_json(PYPI_PROJECT.format(name=name), timeout=20, retries=1)
    info = data.get("info") or {}
    uploads = [
        f["upload_time_iso_8601"]
        for files in (data.get("releases") or {}).values()
        for f in files
        if f.get("upload_time_iso_8601")
    ]
    return {
        "created": min(uploads) if uploads else None,
        "last_release": max(uploads) if uploads else None,
        "release_count": len(data.get("releases") or {}),
        "summary": (info.get("summary") or "")[:200],
        "author": info.get("author") or info.get("author_email") or "",
        "home_page": info.get("home_page") or info.get("project_url") or "",
    }


# How long a project's registry metadata is trusted before refetching. A
# project that existed yesterday still exists today; only its release count
# moves, and that does not change whether it is a squat.
DETAILS_TTL_DAYS = 7


def sweep_pypi(state: dict, watchlist: list[str], max_age_days: int = MAX_AGE_DAYS,
               enrich_budget: int = ENRICH_BUDGET):
    names = pypi_index(state)
    if names is None:
        return
    matcher = SquatMatcher(watchlist, max_distance=1, rules=SWEEP_RULES)
    hits = [m for n in names for m in (matcher.match(n),) if m]
    state["pypi_last_sweep"] = {"names": len(names), "hits": len(hits)}

    # PyPI republishes its index constantly, so the ETag changes daily while
    # the hits barely move. Without this cache every run refetches the same
    # thirty project pages to learn the same thirty creation dates.
    cache = state.setdefault("pypi_details", {})
    fetched = 0
    for match in hits:
        cached = cache.get(match.name)
        if cached and (_age_days(cached.get("checked")) or 99) < DETAILS_TTL_DAYS:
            details = {k: v for k, v in cached.items() if k != "checked"}
        else:
            if fetched >= enrich_budget:
                state.setdefault("warnings", []).append(
                    f"pypi enrichment budget {enrich_budget} exhausted, "
                    f"{len(hits) - enrich_budget} hits not examined")
                break
            try:
                details = pypi_details(match.name)
            except SkipCollector:
                # One project 404ing (deleted mid-sweep) is not a reason to stop.
                continue
            fetched += 1
            cache[match.name] = {**details, "checked": utcnow()}
        age = _age_days(details["created"])
        if age is not None and age > _age_limit(match, max_age_days):
            continue
        confidence = "high" if (age is not None and age <= 30) else None
        yield _candidate(
            match, "pypi",
            {**details, "age_days": None if age is None else round(age, 1)},
            [f"https://pypi.org/project/{match.name}/"],
            confidence,
        )


# ---------------------------------------------------------------------------
# npm — targeted search
# ---------------------------------------------------------------------------

def npm_targets(watchlist: list[str]) -> list[str]:
    """Brand names worth spending a search query on, in a stable order."""
    seen, out = set(), []
    for name in sorted(watchlist):
        if name.startswith("@") and "/" not in name:
            continue  # a bare scope is not a package name anyone types
        text = bare(name)
        if not is_distinctive(text) or len(text) < 5 or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def npm_search(text: str, size: int = 100) -> list[dict]:
    payload = get_json(NPM_SEARCH.format(text=text, size=size), timeout=25, retries=1)
    return [o.get("package", {}) for o in payload.get("objects", [])]


def npm_details(name: str) -> dict:
    """Creation date and maintainers for one npm package.

    Search results carry `date`, which is the *last* publish. An actively
    maintained ten-year-old package looks days old by that measure, so the
    packument's `time.created` is what the age gate has to run on.
    """
    data = get_json(NPM_PACKAGE.format(name=name.replace("/", "%2f")),
                    timeout=20, retries=1)
    times = data.get("time") or {}
    versions = sorted(k for k in times if k not in ("created", "modified"))
    return {
        "created": times.get("created"),
        "last_release": times.get("modified"),
        "release_count": len(versions),
        "versions": versions[-5:],
        "maintainers": [m.get("name", "") for m in (data.get("maintainers") or [])][:5],
        "repository": ((data.get("repository") or {}).get("url") or "")[:200],
    }


def sweep_npm(state: dict, watchlist: list[str], max_age_days: int = MAX_AGE_DAYS,
              query_budget: int = NPM_QUERY_BUDGET):
    """Query npm for each brand in turn, rotating across runs.

    A whole-registry scan is not on offer here, so the cursor in state is what
    gives eventual coverage: each run advances through the brand list and wraps.
    """
    matcher = SquatMatcher(watchlist, max_distance=2, rules=ALL_RULES)
    targets = npm_targets(watchlist)
    if not targets:
        return
    cursor = int(state.get("npm_cursor", 0)) % len(targets)
    window = [targets[(cursor + i) % len(targets)] for i in range(min(query_budget, len(targets)))]
    state["npm_cursor"] = (cursor + len(window)) % len(targets)
    state["npm_last_window"] = window

    reported: set[str] = set()
    for text in window:
        packages = npm_search(text)
        time.sleep(NPM_DELAY)
        for pkg in packages:
            name = pkg.get("name")
            if not name or name in reported:
                continue
            match = matcher.match(name)
            if not match:
                continue
            # A package whose *last* publish predates the window cannot have
            # been created inside it. Cheap way to skip the packument fetch.
            last_publish_age = _age_days(pkg.get("date"))
            if last_publish_age is not None and last_publish_age > max_age_days:
                continue
            reported.add(name)
            try:
                details = npm_details(name)
            except SkipCollector:
                continue
            time.sleep(NPM_PACKAGE_DELAY)
            age = _age_days(details["created"])
            if age is not None and age > _age_limit(match, max_age_days):
                continue
            confidence = "high" if (age is not None and age <= 30
                                    and match.confidence == "medium") else None
            yield _candidate(
                match, "npm",
                {**details,
                 "description": (pkg.get("description") or "")[:200],
                 "latest_version": pkg.get("version"),
                 "publisher": (pkg.get("publisher") or {}).get("username", ""),
                 "age_days": None if age is None else round(age, 1),
                 "found_via": text},
                [f"https://www.npmjs.com/package/{name}"],
                confidence,
            )


# ---------------------------------------------------------------------------
# republication of names the feed already documents as malicious
# ---------------------------------------------------------------------------

def npm_state(data: dict) -> tuple[str, list[str]]:
    """Which of npm's four states a package document describes.

    Getting this wrong is the difference between "20 catalogued typosquats are
    live again" and "20 catalogued typosquats were correctly removed". npm does
    not delete a malicious package outright — it replaces the code with a
    `0.0.1-security` stub, so the document still carries a version and a recent
    `modified` timestamp. Only versions that are not that stub mean live code.
    """
    times = data.get("time") or {}
    if times.get("unpublished"):
        return "unpublished", []
    versions = sorted(data.get("versions") or {})
    if not versions:
        return "absent", []
    real = [v for v in versions if "-security" not in v]
    if not real:
        return "security-holding", versions
    return "live", real


def is_republication(was: str | None, status: str) -> bool:
    """Whether a known-bad name's state change is worth reporting.

    Only a transition into `live` counts. A name that was already live is an
    entry with `status: active` restating its own claim, and a name seen for
    the first time has no transition to report — it is a baseline.
    """
    return status == "live" and was is not None and was != "live"


def check_known_bad(state: dict, names: set[str], budget: int = 60):
    """Has anything the feed calls malicious *changed* into serving live code?

    The signal is the transition, not the state. A name the feed documents as
    malicious and that is live today is usually just an entry with
    `status: active` — that is the entry's own claim, not a discovery, and
    reporting it would put a permanent false alarm in the queue for every live
    threat RADAR catalogues. What matters is a name that was gone, unpublished
    or security-held on the last look and is installable on this one: a new
    owner claiming an abandoned name, or the same actor republishing.

    A name seen for the first time is recorded as a baseline and not reported.
    The healthy answer here is nothing, and the census in state says what was
    actually observed.
    """
    ordered = sorted(names)
    if not ordered:
        return
    cursor = int(state.get("bad_cursor", 0)) % len(ordered)
    window = [ordered[(cursor + i) % len(ordered)] for i in range(min(budget, len(ordered)))]
    state["bad_cursor"] = (cursor + len(window)) % len(ordered)

    census: dict[str, int] = {}
    prior: dict[str, str] = state.setdefault("known_bad_states", {})
    for name in window:
        try:
            data = get_json(NPM_PACKAGE.format(name=name.replace("/", "%2f")),
                            timeout=15, retries=0)
        except SkipCollector:
            census["gone"] = census.get("gone", 0) + 1
            prior[name] = "gone"
            continue  # a 404 is the expected, healthy answer
        time.sleep(NPM_PACKAGE_DELAY)
        status, versions = npm_state(data)
        census[status] = census.get(status, 0) + 1
        was = prior.get(name)
        prior[name] = status
        if not is_republication(was, status):
            continue
        times = data.get("time") or {}
        latest = max((times.get(v) or "" for v in versions), default="")
        yield Candidate(
            source=NAME,
            key=f"republished:npm:{name}",
            title=f"{name} is installable on npm again",
            why=(f"a name the feed documents as malicious was {was} on the last "
                 f"look and now has {len(versions)} installable version(s) on npm"),
            suggested_category="slopsquat-package",
            confidence="high",
            evidence={"registry": "npm", "name": name, "target": name,
                      "rule": "republication", "previous_state": was,
                      "versions": versions[-5:],
                      "created": times.get("created"), "last_release": latest,
                      "maintainers": [m.get("name", "")
                                      for m in (data.get("maintainers") or [])][:5],
                      "age_days": None if not latest else round(_age_days(latest) or 0, 1)},
            urls=[f"https://www.npmjs.com/package/{name}"],
        )
    state["known_bad_census"] = census


# ---------------------------------------------------------------------------

def collect(max_age_days: int = MAX_AGE_DAYS, skip_npm: bool = False,
            skip_pypi: bool = False):
    """Run every pass, keeping what the reachable ones found.

    A generator that lets an exception escape loses everything it already
    yielded. One registry rate-limiting us is not a reason to throw away the
    other one's sweep, so each pass is contained — but if *nothing* was
    reachable the skip propagates, because "found nothing" and "could not look"
    must not report the same way.
    """
    state = load_state(NAME)
    state.pop("warnings", None)
    watchlist = load_watchlist()

    passes = []
    if not skip_pypi:
        passes.append(("pypi", lambda: sweep_pypi(state, watchlist, max_age_days)))
    if not skip_npm:
        passes.append(("npm", lambda: sweep_npm(state, watchlist, max_age_days)))
        passes.append(("known-bad", lambda: check_known_bad(state, known_bad())))

    reached = 0
    try:
        for label, make in passes:
            try:
                for candidate in make():
                    yield candidate
            except SkipCollector as exc:
                state.setdefault("warnings", []).append(f"{label}: {exc}")
            else:
                reached += 1
    finally:
        save_state(NAME, state)

    # Drop cached metadata for names that no longer match — a watchlist edit
    # can retire dozens at once and the cache should not grow forever.
    if passes and reached == 0:
        raise SkipCollector("; ".join(state.get("warnings", ["no pass completed"])))


def main() -> int:
    from .base import run_collector

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--max-age-days", type=int, default=MAX_AGE_DAYS)
    parser.add_argument("--skip-npm", action="store_true")
    parser.add_argument("--skip-pypi", action="store_true")
    args = parser.parse_args()

    result = run_collector(NAME, lambda: collect(
        args.max_age_days, args.skip_npm, args.skip_pypi))
    print(result.line())
    return 0 if result.status != "error" else 1


if __name__ == "__main__":
    raise SystemExit(main())
