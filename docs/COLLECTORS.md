# Collectors

Collectors find *candidates*. A candidate is not an entry and never becomes one
automatically: it lands in `triage/queue/` for a human to verify against a
primary source. That gap is the whole reason the feed is citable, and the daily
workflow enforces it — if a collector writes anything under `data/`, `dist/`,
`schema/` or `scripts/`, the run fails instead of opening a pull request.

```
registries ──► collector ──► triage/queue/*.json ──► human reads the primary
                                                     source ──► data/entries/
```

## Running them

```bash
python scripts/build_feed.py             # the watchlist is derived from the feed
python -m collectors.watchlist --refresh
python -m collectors.run                 # all of them
python -m collectors.run --only slopsquat
python -m collectors.slopsquat --skip-npm    # each is runnable on its own
```

Every run prints one line per collector:

```
  slopsquat          ok       3 new, 12 already queued
  mcp-registry       SKIPPED  registry.modelcontextprotocol.io unreachable: ...
```

`SKIPPED` and `ok, 0 new` are different answers and are reported differently on
purpose. One means the source could not be reached; the other means it was read
and had nothing. In a log those look identical unless you make them not, and a
pipeline that has been silently broken for a month reads exactly like a quiet
month.

## What each one looks at

### `slopsquat` — npm and PyPI

Package names that impersonate names in the AI coding agent ecosystem.

PyPI publishes its full name index, so that pass is exhaustive: all 878k names
are scored against the watchlist on every run, locally, in about seven seconds.
The index is ETag-cached, so a run where PyPI has published nothing new costs
one request.

npm has no such index but has a search API, so that pass is targeted: one query
per distinctive brand on the watchlist, rotating through the list across runs so
each day covers a different slice.

A third pass asks whether anything the feed already documents as malicious is
serving installable code again.

### `mcp-registry` — the official MCP registry

The registry is open publication: anyone can list a server and nothing there has
been reviewed. Roughly 2,500 records move in a week, so this reports only on
substantive signals — a package identifier that impersonates something, a
listing pointing at a well-known repository it has no claim to, a server that
went from active to deleted after we had seen it. "New and unfamiliar" is not a
signal.

The walk is incremental (`updated_since`) and resumable: records come back
ordered by name rather than by update time, so a run that hits its page budget
saves its cursor rather than advancing the watermark past records it never read.

## Why the thresholds are what they are

The matcher in `collectors/similarity.py` was tuned by sweeping the real PyPI
index and reading the output, not by picking numbers that sounded careful. The
first draft returned 952 hits. Three things were wrong:

- **Generic targets.** `mcp`, `agent-sdk` and `mcp-client` matched several
  hundred unrelated legitimate packages. A name built only from category words
  now earns no fuzzy matching.
- **Affix matching.** `claude-code-sdk`, `langchain-cli` — this is how
  ecosystems name legitimate companion packages. Roughly 5% precision on a full
  sweep, useful when a human is already reading one brand's results, so it is
  opt-in per call site rather than on by default.
- **Edit distance 2.** `langchain-cohere` is two edits from `langchain-core` and
  entirely legitimate. The sweep uses distance 1 and counts a transposition as
  one edit, so `langchian` is still caught.

That took it to 41. A creation-date gate took it to 15. The same discipline
retired the MCP registry's namespace-mismatch rule: it fired 21 times across
2,500 records and every one was a person publishing under their personal GitHub
account with the code in their company org. It is recorded as evidence on
candidates that qualified some other way, and it opens nothing on its own.

The general shape: **measure a rule against real data before trusting it, and
demote it to evidence when it does not earn a candidate.** A queue with a bad
signal in it is worse than a smaller queue, because a triager who learns the
queue is mostly noise stops reading it.

## Triaging

Each file in `triage/queue/` carries the rule that produced it, the target it
matched, and enough registry metadata to decide without opening a browser —
creation date, release count, maintainers, the project's own description.

Three outcomes:

1. **It is real.** Read the primary source, write the entry under
   `data/entries/`, delete the candidate file.
2. **It is not.** Delete the candidate file and add its `key` to
   `triage/dismissed.txt` with the reason. Without that it comes back tomorrow —
   the queue file is gone, so the collector has no memory that anyone decided.
3. **It might be.** Leave it queued, or move it to `triage/unverified.md` with
   what is missing. An unproven lead is worth keeping; an unproven entry is not.

Reconfirming a candidate does not rewrite its file, so a triage pull request
whose diff is forty unchanged candidates with a fresh timestamp cannot happen.
"Still seen on this date" lives in `collectors/state/seen.json` instead.

## State

`collectors/state/` is committed. GitHub Actions has no disk between runs, and
the ETags, cursors and watermarks in there are what make the next run
incremental rather than a cold start. It is also an audit trail: `slopsquat.json`
records how many names were swept and how many hit, and `known_bad_census`
records what the registry currently serves for every name the feed calls
malicious — the healthy reading is that they are all gone, held or unpublished.

## Reachability

Collectors are CI-first. Several sources are not reachable from every
development sandbox, and a collector that cannot reach its source reports
`SKIPPED` with the reason rather than a clean zero. The daily Action is where
they all genuinely run.

## Adding one

1. Write `collectors/<name>.py` exposing `NAME` and a `collect()` generator that
   yields `Candidate` objects.
2. Raise `SkipCollector` when the source is unreachable or unconfigured. Never
   return an empty list to mean "could not look".
3. Register it in `collectors/run.py` and add it to the workflow's `only`
   choices — a test asserts those two lists agree.
4. Measure it against real data before trusting a threshold, and write down what
   you measured.
