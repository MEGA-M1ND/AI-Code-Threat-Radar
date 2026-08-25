# radar-check

Scans a project and machine against [RADAR](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar),
a public feed of supply-chain incidents in the AI coding agent ecosystem.

```sh
pipx install radar-check
radar-check .
```

No runtime dependencies. A security scanner that pulls in a dependency tree is
asking to become the thing it warns about, and everything here is standard
library.

## What it looks at

| Target | Where |
|---|---|
| Dependencies | `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock` |
| MCP servers | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json`, Claude Code settings |
| Agent skills | `.claude/skills`, `.agents/skills`, and the same under `$HOME` |
| **Agent hooks** | `.claude/settings.json`, `.claude/settings.local.json`, `.vscode/tasks.json` |

### The hook check is the one nothing else does

Two entries in RADAR establish this as a live technique. A compromised npm
package globbed the filesystem for `settings.json` and wrote a `SessionStart`
hook into every one it found; five other packages shipped `.claude/settings.json`
inside the tarball, pointing at a 4.5 MB ELF beside it.

**The hook outlives the package that installed it.** Uninstalling the
dependency, deleting `node_modules`, rebuilding the lockfile — the hook stays,
and it runs on every agent session start. A dependency scanner reports the
machine clean.

radar-check cannot know whether *you* configured a hook, so it does not claim
to. It reports what runs automatically, ranks the shapes seen in real payloads
higher, and leaves the judgement to you.

## Output

```
CRITICAL  ms-graph-types@2.43.2 — Five npm impersonations ship a Claude Code SessionStart hook…
          package-lock.json
          → Remove ms-graph-types and treat any credentials this project could reach as exposed.
          source: https://safedep.io/malicious-npm-packages-claude-code-hooks
```

`--format sarif` emits SARIF 2.1.0 for GitHub code scanning. `--format json`
emits the findings directly.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | nothing at or above `--fail-on` (default `medium`) |
| 1 | findings at or above the threshold |
| 2 | **could not complete the scan** |

The third one matters. A scan that runs with no feed finds nothing and looks
exactly like a clean project, so radar-check refuses to scan without one.

## Two things it is careful about

**Versions.** RADAR quotes version strings verbatim from the source it cites,
so they are human notation rather than semver ranges: `0.0.5 - 0.1.15`,
`<1.3.9`, `1.0.0-1.0.32`, `2026.2.17`, comma lists. `radar_check/versions.py`
parses all of them, tells an unspaced range from a prerelease tag, and compares
components numerically so `1.0.91` sorts above `1.0.9` — the feed carries both
as separate affected versions of one package.

When it cannot parse a string it says so and flags the finding as uncertain.
Answering "no match" would hide a real hit; answering "match" would cry wolf on
every version. Neither is honest.

The payoff is concrete: `microsoft-applicationinsights-common@3.4.2` is malware
and `3.4.1` is a clean decoy published by the same account. radar-check flags
one and not the other.

**Severity.** A vulnerable version of legitimate software is not malware, and
reporting both as `critical` teaches people to ignore both. Findings from
`platform-vuln` and `compromised-package` entries are ranked below findings
naming an artifact that was never legitimate.

## Usage

```sh
radar-check .                          # scan a project and $HOME
radar-check . --no-home                # project only
radar-check . --offline                # never touch the network
radar-check . --feed ./feed.json       # use a specific feed
radar-check . --skip deps --skip mcp   # turn scanners off
radar-check . --format sarif -o out.sarif
radar-check . --fail-on critical
```

The feed is cached in `~/.cache/radar-check` for six hours. If the network is
unreachable and a stale cache is used, the report says so — a scan against a
six-month-old feed is worse than one that failed.

## Known limits

- Near-miss detection scores against the *legitimate* names in the feed, which
  is a much shorter list than the curated watchlist RADAR's collectors use. It
  catches `tinycolour` for `@ctrl/tinycolor`; it will not catch a typo of a
  popular package RADAR has never had an incident for.
- Lockfiles are read, manifests are not. A dependency you have declared but not
  installed is invisible here, which is deliberate — the question is what is on
  disk.
- The skill heuristics look for the ClawHavoc prerequisite-trap shape. A
  malicious skill that does something else entirely will only be caught if its
  slug is in the feed.

## Development

```sh
cd radar-check
pip install -e ".[dev]"
python -m pytest
python -m radar_check --feed ../dist/feed.json --no-home fixtures/seeded
```

`fixtures/seeded/` holds one of everything the scanner should catch;
`fixtures/clean/` holds none of it. A test asserts both halves.

MIT.
