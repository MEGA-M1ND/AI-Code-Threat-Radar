# Consumers

Guards enforce. None of them owns the data. RADAR is trying to be the data, so
this document is about what the guards can actually read — written by cloning
each one and reading its code, not from its README.

Two artifacts come out of every build and every release:

| File | For |
|---|---|
| [`radar-deny.json`](#radar-denyjson) | any guard; the generic format, and the only one that carries an action |
| [`hol-guard-threat-intel.json`](#hol-guard) | HOL Guard's native `ThreatIntelBundle` |

Both are pure functions of `feed.json`: same feed in, byte-identical bytes out,
no clock and no network. Timestamps are derived from the feed's own
`last_updated`, so rebuilding an unchanged feed next year produces the same
file. Verify either by its digest in the release `SHA256SUMS`.

---

## The decision that matters more than the format

The hard part of exporting this feed is not serialisation. It is deciding what
a guard should *do* with each indicator, and that cannot be read off the
indicator alone.

- A **`platform-vuln`** entry names software the developer is entitled to run.
  `@anthropic-ai/claude-code` is in this feed because a version of it had a bug.
  Blocking that name would be worse than the bug.
- A **`compromised-package`** entry names a package that was trustworthy before
  the incident and is trustworthy after it. Only the listed versions are bad.
- A **`slopsquat-package`**, **`malicious-package`**, **`malicious-mcp-server`**
  or **`malicious-skill`** entry names something that was never legitimate. The
  name itself is the indicator.

So the action comes from category, status and whether versions are pinned —
never from severity. A `critical` platform vulnerability still resolves to
`warn`, because the severity describes the bug and the action describes the
artifact. The logic is in [`exporters/common.py`](../exporters/common.py),
deliberately in one place so it can be argued with.

| Action | Meaning |
|---|---|
| `block` | do not install or load this artifact |
| `warn` | match it, report it, let the user decide |
| `monitor` | record a match; removed from its registry, not a live threat |

---

## `radar-deny.json`

One flat rule per indicator, sorted, with the action attached. This is the
format RADAR proposes for other feeds to emit and other guards to read; nothing
in it is specific to RADAR's internals.

```json
{
  "action": "block",
  "action_reason": "malicious as published and still reachable",
  "type": "package",
  "value": "ms-graph-types",
  "ecosystem": "npm",
  "surface": "dependency manifests and lockfiles",
  "versions": ["2.43.2"],
  "all_versions": false,
  "severity": "critical",
  "category": "slopsquat-package",
  "status": "active",
  "radar_id": "RADAR-2026-0015",
  "source": "https://safedep.io/malicious-npm-packages-claude-code-hooks"
}
```

Three fields exist because leaving them out causes false positives:

- **`all_versions`** is explicit. A scanner must never have to infer "every
  version is affected" from a missing key. `ms-graph-types@2.43.1` is clean and
  `2.43.2` is not; blocking the name takes out both.
- **`surface`** says where to look, so a guard scanning lockfiles can skip the
  domain rules without parsing the type vocabulary.
- **`action_reason`** is there so a user who sees a block can be told why in
  the guard's own UI without a round trip to the website.

---

## HOL Guard

[`hashgraph-online/hol-guard`](https://github.com/hashgraph-online/hol-guard) —
"open-source antivirus for AI agents". The Python package is
`codex_plugin_scanner`, so the plugin scanner and the guard are one tool.

**What it reads.** `guard/runtime/threat_intel.py` defines a
`ThreatIntelBundle`: `{version, generated_at, expires_at, source, signature,
advisories[]}`, where each advisory is `{advisory_id, source, severity, title,
affected_type, matcher, recommendation}`. Advisories dispatch through a matcher
registry in `guard/runtime/advisory_matchers.py`.

**Why a native export is worth it.** Those matcher keys line up with RADAR's
indicator types:

| RADAR indicator | HOL Guard matcher | Matches against |
|---|---|---|
| `package` (npm) | `npm` | `package_name` where ecosystem is npm |
| `package` (pypi) | `pypi` | `package_name` where ecosystem is pypi |
| `mcp-server` with a `name` | `mcp_server` | `mcp_server` name, exact |
| `domain` | `malicious_domain` | `network_hosts`, exact or subdomain |
| `hash` on a skill entry | `skill_hash` | `skill_hash` content hash |
| `hash` elsewhere | `malicious_package_hash` | `package_hash` |

Each of those was tested by running HOL Guard's own matcher functions against
the exported advisories: every one fires on a match and stays silent on a
near-miss.

### Four limits, stated plainly

**It is unsigned.** `verify_bundle_signature()` checks RSA-PSS against HOL
Guard's public key. RADAR does not hold that key. The `signature` field carries
the literal string `unsigned` — a required non-empty string, so the bundle
parses, and one that fails verification loudly rather than quietly. Verify this
artifact by its release digest instead.

**It carries only artifacts that should be blocked.** A `ThreatAdvisory` has a
severity and no action field, so there is no way to say "match this and do not
block it". Shipping `@anthropic-ai/claude-code` at `severity: high` into a
format that cannot qualify it invites a guard to block software the developer
is entitled to run. Those 117 indicators are withheld and counted under
`radar.skipped_indicators.legitimate-artifact`. `radar-deny.json` carries them.

**It carries no agent skills, which is most of what RADAR knows.** The only
skill matcher is `skill_hash`, and it compares a *content hash*. RADAR's skill
indicators are marketplace slugs — `clawhub-6yr3b`, `google-qx4`. Emitting 344
slugs under `skill_hash` would produce a bundle that looks 344 advisories
richer and matches nothing, so they are counted as skipped.

**There is no `SupplyChainBundle`.** The richer format — risk scores, policy
rules, purls, emergency denylist — requires `workspaceId`, `keyId` and a
signature, and is issued by HOL Guard's cloud. A third party cannot
meaningfully produce one.

### The contribution that would help

A `skill_slug` matcher — five lines beside `match_mcp_server`, comparing
`target["skill_slug"]` to `advisory.matcher` — would let this export carry
RADAR's largest indicator class. There are 344 confirmed-malicious slugs ready
to populate it. That, and an `action` field on `ThreatAdvisory`, would close
both of the gaps above.

---

## LlamaFirewall

[`meta-llama/PurpleLlama/LlamaFirewall`](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall)
— Meta's guardrail framework: PromptGuard, AlignmentCheck, CodeShield, and a
regex scanner.

**RADAR cannot feed it, and it is worth being clear about why.** LlamaFirewall
scans *messages* — prompts, tool outputs, chain-of-thought — for injection and
PII. It does not scan dependency manifests, MCP configuration or installed
skills. A package name has nothing to match against in that pipeline.

The documentation describes "customizable regex filters", but
`scanners/regex_scanner.py` compiles a module-level `DEFAULT_REGEX_PATTERNS`
dict in `__init__`, and the constructor takes only `scanner_name` and
`block_threshold`. There is no parameter for supplying patterns and no loader
for an external rule file. Injecting RADAR data today means subclassing
`RegexScanner` or mutating the module global.

**Plausible contribution:** a `patterns: Dict[str, str] | None = None`
constructor argument, which is a two-line change and would make the documented
extensibility real. A RADAR-derived pattern set is only useful afterwards, and
only for the indicator types that appear in message text — domains, IPs and
URLs, which is 21 of 605 rules. This is the weakest of the three fits and
should not be oversold.

---

## Vexscan

[`edimuj/vexscan-claude-code`](https://github.com/edimuj/vexscan-claude-code) —
a Claude Code plugin that scans plugins, skills, MCP servers and hooks, on
`SessionStart` and on demand via `/vexscan:vet`.

**It has no rule format at all.** The plugin is a `hooks.json`, a shell script
and two command markdown files. `/vexscan:vet` spawns a general-purpose
subagent and asks it to reason about a plugin, returning `SAFE`, `CAUTION`,
`RISKY` or `DANGEROUS`. There is no blocklist, no pattern file, nothing to
generate.

That makes it the closest fit for RADAR conceptually and the furthest from a
data integration. An LLM reasoning about whether a skill is malicious has no
way to know that `clawhub-6yr3b` is one of 334 slugs from a documented
campaign — unless something tells it.

**Plausible contribution:** one step in the `vet` prompt that fetches
`radar-deny.json` and checks the artifact's name, slug or MCP server name
against it before reasoning. A confirmed hit is a `DANGEROUS` verdict with a
citation rather than a judgement call. This is a prompt change, not a code
change, which makes it the cheapest of the three to land.

---

## Using the feed directly

```sh
curl -sL https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/radar-deny.json
```

Pin a release tag rather than `latest` if you need reproducibility, and check
the digest against that release's `SHA256SUMS`. Everything is CC BY 4.0; the
attribution string travels inside each file.

If you maintain a guard and the shape here does not fit, open an issue. The
generic format is a proposal, and a second implementer is worth more to it than
another field.
