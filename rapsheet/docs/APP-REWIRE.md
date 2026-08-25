# Rewiring the web app to the Rapsheet feed

Handover notes. Nothing in `frontend/` or `backend/` was touched while building Rapsheet; this describes the work, it does not do it.

## The one URL

```
https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/feed.json
```

That path is a GitHub-maintained redirect to the newest release, so the proxy never needs to know a tag. Follow redirects (`httpx.AsyncClient(follow_redirects=True)`).

## Backend

`backend/server.py` currently reads `backend/data/feed.json` off disk on every request. Replace the read with a fetch of the URL above, keep the `/api/feed` route and its `Cache-Control: no-store` header so the front end is unaffected, and add a short in-process cache (60–300 s) plus a fallback to the last good payload, because the app now depends on a network hop that it did not before. `backend/data/feed.json` can then be deleted, along with the `FEED_PATH` constant.

`backend/tests/test_feed_api.py` asserts `len(data["entries"]) == 15` and a fixed count per category. Those assertions are pinned to the mock data and will fail against any real feed; replace them with shape assertions (`entry_count == len(entries)`, every entry has a `category` in the known set, every entry has at least one `primary` source).

## Field mapping

Old entry shape on the left, Rapsheet on the right.

| Old field | New field | Notes |
| --- | --- | --- |
| `id` | `id` | Format changed: `ms-001-cloud-billing-autopilot` → `RS-2025-0001`. No old id survives; there is no migration table because no old entry survives either. |
| `_category` | `category` | Values changed. See the category table below. |
| `type` | *(gone)* | It duplicated `_category`. Use `category`. |
| `title` | `title` | Same meaning. |
| `description` | `summary` | Now capped at two sentences. Any UI that expects a paragraph will look sparse; the detail page should lean on `severity_rationale` and the source links instead. |
| `impact`, `root_cause`, `notes` | *(gone)* | Dropped as editorialising. Nothing replaces them. |
| `status` | `status` | Values changed: `confirmed`/`reported` → `active`; `remediated` and `disputed` keep their names. |
| — | `severity` | New. `critical`/`high`/`medium`/`low`. |
| — | `severity_rationale` | New. One line. Good candidate for the card subtitle. |
| `date_disclosed` | `first_seen` | Same meaning, ISO date. |
| `added` | *(gone)* | Not tracked. |
| `last_updated` | `last_updated` | Same. |
| `indicators: ["string"]` | `indicators: [{...}]` | **Breaking.** Now typed objects, not strings. See below. |
| `references: ["url"]` | `sources: [{url, publisher, type}]` | Each source carries its publisher and whether it is `primary` or `secondary`. |
| `tags` | *(gone)* | Filter on `category`, `severity`, `status` and `affected_tools` instead. |
| `ecosystem` | *(partly)* | Closest equivalent is the indicator's `registry`, or `affected_tools`. |
| `source_attribution` | *(gone)* | Was only on `agent-tool-cves` entries. Attribution now lives on every source and in the feed envelope. |
| — | `affected_tools` | New. Array from `claude-code`, `cursor`, `codex-cli`, `gemini-cli`, `copilot`, `generic-mcp`, `other`. A good new filter facet. |
| — | `related` | New. `CVE-…`, `GHSA-…`, `OSV-…`, `MAL-…` strings. Link them out. |
| `indicator_index` (top level) | *(gone)* | Use `blocklist.json`, or build the index client-side. |
| `generated` (top level) | `last_updated` | Now derived from the entries, not from the build clock. |
| `name` (top level) | `feed` | Value is `"rapsheet"`. |
| — | `schema_version`, `license`, `attribution`, `homepage` (top level) | New. `attribution` must be displayed somewhere: the data is CC BY 4.0. |

### Categories

| Old | New |
| --- | --- |
| `malicious-skills` | `malicious-skill` |
| `mcp-threats` | `malicious-mcp-server` |
| `slopsquatting` | `slopsquat-package` |
| `platform-vulns` | `platform-vuln` |
| `incidents` | `vibe-app-breach` |
| `agent-tool-cves` | *(no equivalent — out of scope, cite Vibe Security Radar instead)* |
| — | `compromised-package` *(new)* |

### Indicators

Old:

```json
"indicators": ["cloud-billing-autopilot"]
```

New:

```json
"indicators": [
  {"type": "package", "registry": "npm", "name": "postmark-mcp", "version": ">=1.0.16"},
  {"type": "domain", "value": "giftshop.club"}
]
```

Types are `package` (with `registry` of `npm`/`pypi`/`crates`/`vscode`), `application`, `mcp-server`, `skill`, `hash`, `domain`, `url`. A display string can be derived as `name || slug || value || url`. Full definitions in [FEED.md](FEED.md).

## Front-end touch points

- `frontend/src/lib/feed.js` — `computeHomeStats` sets `criticalCount` from `status === 'confirmed'`, which no longer exists. It should read `severity === 'critical'`. `computeCategoryCounts` reads `entry._category`; change to `entry.category`. `sortEntriesByDate` defaults to `date_disclosed`; change the default to `first_seen`. The `maliciousSkills` / `mcpThreats` / `slopsquatting` / `platformVulns` keys read old category names.
- `frontend/src/constants/categories.js` — `CATEGORY_ORDER`, `CATEGORY_LABELS`, `STATUS_ORDER`, `STATUS_LABELS` and `STATUS_COLORS` all use old values. `GITHUB_REPO_URL` points at `github.com/ai-code-threat-radar/feed`, which does not exist; it should point at this repository. Add a `SEVERITY_ORDER` / `SEVERITY_COLORS` pair, since severity is now the primary ranking signal.
- `frontend/src/components/ThreatCard.jsx`, `StatusBadge.jsx`, `CategoryBadge.jsx`, `FilterBar.jsx` — read `_category`, `status` and `date_disclosed`. Mechanical renames, plus a severity badge.
- `frontend/src/pages/EntryDetail.jsx` — renders `description`, `impact`, `root_cause`, `notes` and a flat `references` list. Rework to `summary`, `severity_rationale`, typed `indicators` and `sources` with publisher and primary/secondary labelling. Showing which source is primary is worth the space; it is the whole sourcing standard made visible.
- `frontend/src/components/SourceAttributionBadge.jsx` — was for the `agent-tool-cves` lane. Repurpose it to display the feed-level `attribution` string, which the licence requires.
- `frontend/src/lib/checker.js` — whatever it matches against `indicators` needs to handle objects. `blocklist.json` is a better input for it than `feed.json`; if you use it, respect the category rule in [FEED.md](FEED.md) and do not flag a `platform-vuln` indicator as malicious.

## Order of work

1. Point the proxy at the release URL, add the cache and fallback, delete `backend/data/feed.json`.
2. Fix `backend/tests/test_feed_api.py` to assert shape rather than counts.
3. Rename fields in `feed.js` and `categories.js`. Most of the front end follows from those two files.
4. Rework `EntryDetail.jsx` and the indicator rendering, which is the only part that is not a rename.
5. Add severity as a filter and a sort. It is the field the old feed did not have and the one a reader wants first.
