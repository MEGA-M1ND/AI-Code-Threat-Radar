# Migration from AI Code Threat Radar

Rapsheet replaces the threat-data half of the AI Code Threat Radar project. This document records what was carried over from the earlier work, what was dropped, and why.

## What the earlier version was

The earlier project lives in this same repository: a React front end (`frontend/`) and a FastAPI backend (`backend/`) whose only data endpoint, `GET /api/feed`, reads `backend/data/feed.json` from disk on every request and returns it with `Cache-Control: no-store`. There is no database in that path. The feed file held 15 entries across six categories: `malicious-skills` (3), `mcp-threats` (3), `slopsquatting` (3), `platform-vulns` (2), `incidents` (2) and `agent-tool-cves` (2).

## What was carried over

- **The category idea, reshaped.** The earlier six categories map onto Rapsheet's, except that `agent-tool-cves` is dropped as a category because citing CVEs is not Rapsheet's lane, and `incidents` becomes the narrower `vibe-app-breach`.
- **An indicator index.** The old feed carried a top-level `indicator_index` mapping an indicator string to entry ids. Rapsheet's `blocklist.json` serves the same purpose but is typed, carries severity, category and status, and is the file a runtime guard consumes directly.
- **The stance that a feed should be a static file.** No database, no service. Files, Python and GitHub releases.
- **Attribution to Georgia Tech's Vibe Security Radar.** The earlier project deliberately kept a lane boundary with it. Rapsheet keeps that boundary and states it in the README.

## What was dropped, and why

- **All 15 entries.** Every one of them is mock data. Thirteen of the fifteen cite a report URL under `github.com/ai-code-threat-radar/feed`, a repository that does not exist, as their only or primary reference. Several describe incidents with no public record at all (`cloud-billing-autopilot`, `gitsync-assistant`, `docqa-skill-pack`, `fintech-terraform-breach`). One of them, `react-codeshift`, uses a package name that the USENIX Security 2025 package-hallucination study cites as an *example of a name an LLM invents* — it is a hallucinated name, presented in the old feed as a real published attack. None of them reach the feed. This is the single most important thing this migration does.
- **The `indicator_index` top-level object.** Replaced by `blocklist.json`, which is typed and carries triage context.
- **Free-text `indicators: ["some-string"]`.** Replaced by typed indicator objects, so a consumer knows whether a value is an npm package, a VS Code extension id, a skill slug, a hash or a domain, and does not have to guess.
- **`impact`, `root_cause`, `notes`, `tags`, `ecosystem`.** Prose fields that invite editorialising and that no consumer can act on. What remains is `summary` (capped at two sentences), `severity` and a one-line `severity_rationale`.
- **The `confirmed` / `reported` status values.** "Reported" described the reporter's confidence, which is now handled by the primary-source requirement instead: an entry either has one and ships, or does not and goes to `triage/unverified.md`. Status now describes the artifact, not the evidence: `active`, `remediated` or `disputed`.
- **The web application.** Rapsheet does not touch `frontend/` or `backend/`. Rewiring the app to the new feed is described in [APP-REWIRE.md](APP-REWIRE.md) and is a separate job.
- **Git history.** Rapsheet starts from the new schema. Nothing was rewritten in place.

## Two deliberate departures from the original specification

Both are additive. Neither removes or renames anything the specification asked for, so a consumer built against the specified shape still works.

1. **A sixth category, `compromised-package`.** The five specified categories have no home for a supply-chain compromise of a *legitimate* package or extension. That excludes the s1ngularity Nx attack, all four Shai-Hulud waves, GlassWorm and the Amazon Q extension incident — between them the most consequential events in this ecosystem, and the ones a runtime guard most needs indicators for. Filing them under `slopsquat-package` would be false: nothing was typosquatted. Dropping them would gut the feed. So the enum gained one value.

2. **An `application` indicator type.** The specified indicator types cover packages, MCP servers, skills, hashes, domains and URLs. Cursor and Copilot Chat are not published through any registry, so `{type: package, registry: vscode, name: "cursor"}` would have been a lie. `{type: application, name, vendor, version}` is machine-matchable and honest.

## Extracting Rapsheet into its own repository

Rapsheet is self-contained under `rapsheet/` and can be lifted out with:

```sh
git subtree split --prefix=rapsheet -b rapsheet-only
```

One thing does not travel with it. GitHub only reads workflows and issue templates from the repository root, so while Rapsheet shares this repository, `.github/workflows/rapsheet-ci.yml`, `.github/workflows/rapsheet-release.yml` and `.github/ISSUE_TEMPLATE/` live at the root rather than under `rapsheet/`. After a split, move them into the new repository's own `.github/` and drop the `working-directory: rapsheet` and `paths:` filters from the workflows.
