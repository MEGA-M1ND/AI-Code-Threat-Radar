# Contributing

Read [docs/METHODOLOGY.md](docs/METHODOLOGY.md) first. It defines what qualifies, what the primary-source rule means and how severity is chosen. This file is the mechanics.

## Adding an entry

1. Find the primary source and read it in full. Not a summary of it, not a news article about it.
2. Pick the next free id. The year is the year of **first public disclosure**, the number is the next unused one in that year: `RADAR-2026-0007`.
3. Write `data/entries/RADAR-2026-0007.json`. Copy an existing entry for the shape, or [`examples/valid-entry.json`](examples/valid-entry.json).
4. Copy indicator values character-for-character out of the source. Do not defang them. Where a registry is reachable, check the name against it.
5. Run the checks:

   ```sh
   pip install -e ".[dev]"
   python scripts/validate.py
   python -m pytest tests/
   ```

6. Open a pull request. Say in the description which source you treated as primary and why it qualifies.

If you have an incident but not a primary source, do not write an entry. Add it to [`triage/unverified.md`](triage/unverified.md) with a note on exactly what is missing, and it will move into the feed when someone finds the missing piece. The feed is never padded to reach a number.

## Correcting an indicator

A wrong indicator is a bug that shows up as a false positive in someone else's tool. Open a pull request with the corrected value and a link to the source that proves it. These are merged as fast as they can be verified. Move `last_updated`; do not change the `id`.

## What the validator enforces

`scripts/validate.py` runs the JSON Schema plus rules the schema cannot express:

- the `id` field matches the filename, and its year matches `first_seen`;
- ids are unique across the whole data set;
- `summary` is at most two sentences and avoids a small list of banned adjectives;
- `severity_rationale` is one line;
- `first_seen` is not after `last_updated`;
- no duplicate indicators, no repeated source URLs.

The schema itself enforces the rest, including that at least one source is `primary`.

## Style

- Summaries are factual and at most two sentences. No adjectives of praise or alarm — the validator rejects a short list of them and a reviewer will catch the rest.
- Write in RADAR's own words. Do not quote the source.
- `severity_rationale` explains the choice against the [rubric](docs/METHODOLOGY.md#severity-rubric) in one line, so a reader can disagree on the evidence.
- Scale belongs in the rationale, not in the severity label.

## Changing the schema

Schema changes need a reason written down in the pull request and, if they change what a consumer sees, an entry in [docs/FEED.md](docs/FEED.md) under stability. Additive changes — a new optional field, a new enum value, a new indicator type — are a minor version. Anything that removes or renames a field, or changes what an existing value means, is a major version and gets announced in the release notes.

## Cutting a release

Two routes, one code path. Either way the artifacts are built and tested in CI from the commit being released — nothing is ever uploaded from a contributor's machine.

**From the Actions UI.** Run the `radar-release` workflow and give it a tag name (`radar-v0.1.0`). It creates the tag at the commit it ran from, builds, tests, and publishes. This is the route to use when your credential cannot push to `refs/tags/*`, which is the case for agent sessions and for tokens scoped to `refs/heads/*`.

**By pushing a tag.**

```sh
git tag -a radar-v0.1.0 origin/main -m "RADAR v0.1.0"
git push origin radar-v0.1.0
```

The workflow attaches `feed.json`, the six `feed-<category>.json` files, `blocklist.json` and `SHA256SUMS`, and holds `contents: write` and nothing else. Every action it uses is pinned by commit SHA; if you bump one, resolve the new SHA with `git ls-remote https://github.com/actions/<name> refs/tags/vN` and keep the version in the trailing comment.
