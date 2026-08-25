# RADAR

RADAR is a public database of supply-chain threats in the AI coding agent ecosystem: malicious agent skills, typosquatted packages aimed at AI tooling, malicious or compromised MCP servers, vulnerabilities in agent platforms, and breaches of applications that were vibe-coded. Every entry is built around machine-matchable indicators and carries at least one primary source that a reader can check. It exists because runtime guards for AI agents each ship their own private blocklist, and there is no shared intelligence source underneath them.

[![entries](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgithub.com%2FMEGA-M1ND%2FAI-Code-Threat-Radar%2Freleases%2Flatest%2Fdownload%2Ffeed.json&query=%24.entry_count&label=entries&color=blue)](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest)
[![indicators](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fgithub.com%2FMEGA-M1ND%2FAI-Code-Threat-Radar%2Freleases%2Flatest%2Fdownload%2Fblocklist.json&query=%24.indicator_count&label=indicators&color=blue)](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest)

## Consume the feed

```sh
curl -sL https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/feed.json
```

`blocklist.json` is the file a runtime guard wants: a flat list of indicators, each carrying the entry id, severity, category, status and one source URL.

```sh
curl -sL https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/blocklist.json
```

Per-category feeds are published as `feed-malicious-skill.json`, `feed-slopsquat-package.json`, `feed-malicious-mcp-server.json`, `feed-malicious-package.json`, `feed-compromised-package.json`, `feed-platform-vuln.json` and `feed-vibe-app-breach.json`. Field semantics, stability guarantees and update cadence are in [docs/FEED.md](docs/FEED.md).

## Sourcing standard

An entry ships only when it has a working primary source that was read in full: a vendor advisory, a registry takedown notice, a maintainer disclosure, or the original researcher writeup. A news article reporting on one of those is a secondary source and cannot stand alone; the schema rejects an entry that has no primary source.

Indicator values are copied character-for-character from that source and are stored live rather than defanged, because a guard matches on the real string. A wrong package name in a blocklist causes false positives in someone else's tool, so indicator accuracy is treated as the highest-stakes part of the data set. Candidates that cannot be sourced to this standard are recorded in [triage/unverified.md](triage/unverified.md) rather than added to the feed.

The full inclusion criteria, the severity rubric and the dispute process are in [docs/METHODOLOGY.md](docs/METHODOLOGY.md).

## Licences

The split is deliberate and is not going to be simplified into one licence.

- Code — everything under `scripts/`, `tests/` and `schema/` — is MIT. See [LICENSE](LICENSE).
- Data — everything under `data/`, and every artifact built from it — is CC BY 4.0. See [data/LICENSE](data/LICENSE).

The data is free to use in any tool, commercial or not, including closed-source products, with attribution to RADAR. Every built artifact carries the attribution string in its `attribution` field.

## Build it yourself

```sh
pip install -e ".[dev]"     # or: pip install -r requirements.txt
python scripts/validate.py  # schema and house rules
python scripts/build_feed.py     # writes dist/
python -m pytest tests/
```

## Where entries come from

Collectors sweep npm, PyPI and the MCP registry daily for names that impersonate
the AI coding agent ecosystem, and write what they find to `triage/queue/` — a
holding area, not the feed. Nothing reaches `data/entries/` until a human has
read a primary source, and the daily workflow fails rather than opening a pull
request if a collector touches feed data at all. See
[docs/COLLECTORS.md](docs/COLLECTORS.md).

```sh
python -m collectors.run           # all of them
python -m collectors.run --only slopsquat
```

## Contribute or dispute

To propose an entry, open a [submit an entry](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/issues/new?template=submit-an-entry.yml) issue or send a pull request adding one JSON file under `data/entries/`. Read [CONTRIBUTING.md](CONTRIBUTING.md) first.

To contest an entry, open a [dispute an entry](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/issues/new?template=dispute-an-entry.yml) issue. Disputed entries stay in the feed with `status: disputed` until the question is settled, so consumers can see the contest rather than watch data disappear. To report something privately, see [SECURITY.md](SECURITY.md).

## The web app

`frontend/` and `backend/` hold a React console and a thin FastAPI proxy that render the feed as a browsable database with an exposure checker. The app is a viewer; the feed under `data/` is the product, and the app has no data of its own. See [docs/WEBAPP.md](docs/WEBAPP.md) for its architecture and [docs/APP-REWIRE.md](docs/APP-REWIRE.md) for the field mapping between the feed and what the app currently expects.

## Scope

RADAR catalogues incidents: skills, packages, MCP servers, platform failures and breaches. It cites CVE, GHSA and OSV identifiers in each entry's `related` field rather than restating their content. Cataloguing agent-tool CVEs as such is [Georgia Tech SSLab's Vibe Security Radar](https://vibe-radar-ten.vercel.app/) lane, and RADAR points at it rather than duplicating it.

The feed, its schema, its build scripts and its tests live at the repository root; see [docs/MIGRATION.md](docs/MIGRATION.md) for how this layout came about and what was dropped along the way.
