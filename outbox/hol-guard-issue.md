**To:** github.com/hashgraph-online/hol-guard · issue
**Title:** Add a skill-slug matcher, and: would a third-party ThreatIntelBundle be useful?

---

I maintain RADAR, a public feed of supply-chain incidents in the AI coding
agent ecosystem: 38 entries, 605 indicators, CC BY 4.0. Every entry cites a
primary source that was read, and indicator values are taken character-exact
from that source — a wrong package name in a blocklist is a false positive on
someone's machine, so that part is checked against the registry rather than
transcribed. Releases are tagged and digest-listed.

I've built an export in your `ThreatIntelBundle` shape and tested it against
your own `advisory_matchers.py`: 65 advisories across `npm`, `pypi`,
`mcp_server`, `malicious_domain`, `malicious_package_hash` and `skill_hash`,
each firing on a match and silent on a near-miss.

Two things I ran into that may interest you regardless of whether you want the
data:

**`skill_hash` compares a content hash.** RADAR holds 344 confirmed-malicious
ClawHub slugs — `clawhub-6yr3b`, `google-qx4` — and there's no matcher that
takes a slug, so I dropped all 344 rather than emit advisories that can't fire.
A `match_skill_slug` beside `match_mcp_server` would be about five lines, and
I have the slugs.

**`ThreatAdvisory` has no action field.** Some of what RADAR knows is
"`@anthropic-ai/claude-code` had a vulnerable version" — match it, don't block
it. With only severity to work with I withheld 117 such indicators rather than
risk a guard blocking legitimate software.

Happy to open a PR for the matcher, to publish the bundle at a stable URL, or
to do neither if this isn't a direction you want. It's unsigned — I can't sign
for your key — so it'd need your pipeline or digest pinning.

Feed: https://github.com/MEGA-M1ND/AI-Code-Threat-Radar
