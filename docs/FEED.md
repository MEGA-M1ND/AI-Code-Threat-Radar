# Consuming the RADAR feed

## Files

Every release publishes the same set of files. The stable URLs are:

| File | URL |
| --- | --- |
| Full feed | `https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/feed.json` |
| Blocklist | `https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/blocklist.json` |
| Per category | `.../releases/latest/download/feed-<category>.json` |
| Deny rules | `.../releases/latest/download/radar-deny.json` |
| HOL Guard bundle | `.../releases/latest/download/hol-guard-threat-intel.json` |
| Checksums | `.../releases/latest/download/SHA256SUMS` |

`<category>` is one of `malicious-skill`, `slopsquat-package`, `malicious-mcp-server`, `malicious-package`, `compromised-package`, `platform-vuln`, `vibe-app-breach`.

Releases are cut by the `radar-release` workflow, which builds and tests the artifacts in CI from the commit being released; nothing is uploaded from a maintainer's machine. `SHA256SUMS` is generated in the same job, so verifying it tells you the files match what that build produced.

The `/releases/latest/download/` path is a redirect that GitHub maintains. It always resolves to the newest published release, so a consumer never has to know a tag. Pin to a tag (`/releases/download/radar-v0.1.0/feed.json`) if you want reproducibility instead.

## Envelope

Every file shares the same envelope:

```json
{
  "feed": "radar",
  "schema_version": "1.0.0",
  "homepage": "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/tree/main",
  "license": "CC-BY-4.0",
  "attribution": "RADAR (https://github.com/...), CC BY 4.0",
  "last_updated": "2026-08-25",
  "entry_count": 36,
  "entries": [ ... ]
}
```

`last_updated` is the newest `last_updated` across the entries in that file, not the time the build ran. The build takes nothing from the clock, so rebuilding unchanged data produces a byte-identical file. Use `last_updated` to decide whether to re-pull; use the checksum to confirm what you got.

## Entry fields

The authority is [`schema/entry.schema.json`](../schema/entry.schema.json), JSON Schema draft 2020-12, strict (`additionalProperties: false`). What the fields mean:

| Field | Meaning |
| --- | --- |
| `id` | `RS-YYYY-NNNN`. Stable forever. The year is the year of first public disclosure, not the year the entry was written. Ids are never reused and never renumbered. |
| `category` | Exactly one of the seven above. |
| `title` | Short human-readable name, leading with the artifact name where there is one. |
| `summary` | At most two factual sentences. Enforced by the validator. |
| `indicators` | Typed, machine-matchable. See below. |
| `severity` | `critical`, `high`, `medium` or `low`. Rubric in [METHODOLOGY.md](METHODOLOGY.md). |
| `severity_rationale` | One line explaining that choice, so you can disagree with it on the evidence. |
| `status` | `active` (still reachable or unremediated), `remediated` (removed, patched or revoked), `disputed` (contested by an involved party). |
| `first_seen` | ISO date of first public disclosure. |
| `last_updated` | ISO date the entry last changed materially. |
| `sources` | One or more `{url, publisher, type}`. At least one has `type: primary`; the schema rejects the entry otherwise. |
| `affected_tools` | Which agent tooling is exposed: `claude-code`, `cursor`, `codex-cli`, `gemini-cli`, `copilot`, `generic-mcp`, `other`. |
| `related` | Optional external identifiers — `CVE-…`, `GHSA-…`, `OSV-…`, `MAL-…`. RADAR cites them; it does not restate their content. |

## Indicator types

```json
{"type": "package",    "registry": "npm|pypi|crates|vscode", "name": "...", "version": "..."}
{"type": "application","name": "cursor", "vendor": "Anysphere", "version": "<1.3.9"}
{"type": "mcp-server", "name": "...", "url": "...", "repo": "..."}
{"type": "skill",      "slug": "author/skill-name", "marketplace": "clawhub.ai"}
{"type": "hash",       "algo": "md5|sha1|sha256|sha512", "value": "..."}
{"type": "domain",     "value": "example.com"}
{"type": "ip",         "value": "203.0.113.10", "port": 4433}
{"type": "url",        "value": "https://..."}
```

A `package` or `application` indicator may also carry `affected`, a machine-comparable form of `version`:

```json
{"type": "package", "registry": "npm", "name": "mcp-remote", "version": "0.0.5 - 0.1.15",
 "affected": {"ranges": [{"introduced": "0.0.5", "last_affected": "0.1.15"}]}}
```

`affected` holds `versions` (an exact list) and/or `ranges` (objects with `introduced`, `fixed` — the first version that is *not* affected — and `last_affected`). It is derived, optional, and present only where the source states the scope unambiguously. **`version` stays authoritative**: it is copied verbatim from the source, and where the two ever disagree the verbatim string is the one that was published.

For `registry: vscode`, `name` is the marketplace identifier (`publisher.extension`). `version` is copied verbatim from the source and may be a single version, a comma-separated list, a range like `0.0.5 - 0.1.15`, or a bound like `<1.3.9`; it is a human-readable string, not a semver range expression, so parse it defensively. `version` is absent when the whole artifact is malicious at every version.

Indicators are stored live, not defanged. There is no `[.]` or `hxxp` in this feed. A guard matches on the real string, and a test enforces it.

## blocklist.json

`blocklist.json` flattens every indicator on every entry into one array. Each row is the indicator's own fields plus five more:

```json
{
  "type": "package", "registry": "npm", "name": "claud-code", "version": "0.2.1",
  "id": "RADAR-2026-0001",
  "severity": "critical",
  "category": "slopsquat-package",
  "status": "remediated",
  "source": "https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning"
}
```

`category` and `status` are not decoration. **Do not block on an indicator without reading its category.** A `platform-vuln` row names a legitimate package or application that had a vulnerability — `@modelcontextprotocol/inspector`, `cursor`, `@google/gemini-cli`. Blocking those outright takes out software the developer is entitled to run. For those rows, match the `version` field or treat the row as a warning. Rows in `malicious-skill`, `slopsquat-package`, `malicious-mcp-server` and `compromised-package` name artifacts that are malicious, and are safe to block on directly — subject to `version` where present, since `compromised-package` rows usually name a legitimate package that was malicious only in specific versions.

Rows are sorted deterministically by type, registry, name, version and entry id. One entry produces as many rows as it has indicators, so `id` repeats.

## Update cadence and stability

Entries are added as incidents are verified, not on a schedule. A release is cut when the data has changed enough to be worth pulling; there is no promise of a fixed interval, and a consumer polling `last_updated` daily will not miss anything.

Within a `schema_version` major number, these hold:

- No field is removed or renamed.
- No existing enum value changes meaning.
- `id` values are permanent. An entry that turns out to be wrong is corrected in place or marked `disputed`; it is not deleted and its id is not reused.
- New optional fields, new enum values, new indicator types and new categories may appear in a minor version. Parse unknown values by ignoring them rather than failing.

A change that breaks any of the above increments the major number of `schema_version` and is announced in the release notes.

## Attribution

Use of this data requires attribution under CC BY 4.0. Every file carries the exact string in its `attribution` field, so you can surface it without hard-coding anything:

> RADAR (https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/tree/main), CC BY 4.0

Commercial and closed-source use is fine. See [`data/LICENSE`](../data/LICENSE).
