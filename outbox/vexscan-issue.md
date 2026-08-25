**To:** github.com/edimuj/vexscan-claude-code · issue
**Title:** Check artifacts against a known-bad list before the subagent reasons

---

`/vexscan:vet` spawns a subagent to reason about a plugin and return SAFE /
CAUTION / RISKY / DANGEROUS. That handles the novel cases well, which is the
hard part. It also means an already-documented malicious artifact gets
re-evaluated from scratch every time, and the verdict depends on whether the
reasoning happens to land.

Suggestion: one step before the reasoning, checking the artifact's name, skill
slug or MCP server name against a known-bad list. A hit becomes DANGEROUS with
a citation instead of a judgement call.

I maintain a feed that would work for this: RADAR, CC BY 4.0, 38 entries and
605 indicators covering malicious skills, slopsquatted packages, malicious MCP
servers and compromised packages. Every entry cites a primary source that was
read; indicator values are taken character-exact and checked against the
registry. It publishes `radar-deny.json`, a flat list where each row carries an
action — `block`, `warn` or `monitor` — because some entries name legitimate
software that merely had a vulnerable version, and those must not be blocked.

Relevant to vexscan specifically: 344 of those indicators are ClawHub skill
slugs — 334 of them from the ClawHavoc campaign alone — and 10 are MCP servers.

```
curl -sL https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/releases/latest/download/radar-deny.json
```

This is a prompt change, not a code change — no dependency, no build step. Use
it, fork the data, or use a different list entirely; the suggestion is the
lookup step, not the source. Happy to send a PR against `commands/vet.md` if
it's welcome.

Feed: https://github.com/MEGA-M1ND/AI-Code-Threat-Radar
