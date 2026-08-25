# Methodology

## What qualifies

An incident belongs in Rapsheet when it is a supply-chain threat to people using AI coding agents, and when it leaves behind at least one artifact a machine can match on. The six categories:

- **`malicious-skill`** — an agent skill, published to a skill marketplace, that carries instructions or code intended to harm the person who installs it.
- **`slopsquat-package`** — a package published under a name chosen to be mistaken for a real one, whether typosquatted from an existing package or squatted on a name that language models hallucinate.
- **`malicious-mcp-server`** — an MCP server that was malicious as published, or a legitimate one taken over and republished with a backdoor.
- **`compromised-package`** — a legitimate package or editor extension in this ecosystem that was compromised and republished carrying malware.
- **`platform-vuln`** — a vulnerability in agent tooling itself: the CLI, the IDE, the extension, the MCP reference implementations, the marketplace.
- **`vibe-app-breach`** — a breach or exposure in an application that was AI-generated or built on a vibe-coding platform, where the failure traces to how the application was produced.

## What does not qualify

- **A technique with no artifact.** Rules File Backdoor and similar prompt-injection classes are real and important, and they have no package name, hash or domain to match on. They are recorded in [`../triage/unverified.md`](../triage/unverified.md) under "no machine-matchable indicator" rather than in the feed, because an entry with no indicator gives a consumer nothing.
- **A CVE in agent tooling, catalogued as a CVE.** Rapsheet cites CVE, GHSA and OSV identifiers in `related`. Cataloguing them is [Georgia Tech SSLab's Vibe Security Radar](https://vibe-radar-ten.vercel.app/) lane. A `platform-vuln` entry exists here only when the incident matters as a supply-chain event and there is something to match on; it summarises in Rapsheet's own words and points at the CVE for the rest.
- **A supply-chain attack with no connection to AI coding tooling.** A malicious VS Code extension aimed at Ethereum developers is a real attack and is somebody else's database.
- **Anything that cannot be traced to a primary source.** See below.

## The primary-source rule

Every entry ships with at least one source of `type: primary`, meaning one of:

- a vendor advisory (`AWS-2025-015`, an MSRC advisory, a GitHub Security Advisory);
- a registry takedown notice or the registry's own record;
- a maintainer disclosure or postmortem (`nx.dev/blog/s1ngularity-postmortem`);
- the original researcher writeup — the people who found it, not the people who reported on it.

A news article about any of those is `type: secondary`. Secondary sources are welcome and often clearer, but an entry cannot rest on them alone. The schema enforces this with a `contains` constraint on `sources`, so an entry without a primary source fails validation and never reaches a build.

Every primary source is read in full before the entry is written. Nothing is quoted; entries are summarised in Rapsheet's own words.

## Indicator accuracy

This is the part that can hurt somebody. An indicator in this feed may end up in a runtime guard that blocks installs, so a wrong package name becomes a false positive in a tool Rapsheet does not control and cannot fix.

The rules:

1. Indicator values are copied character-for-character from the source. Not retyped from memory, not normalised, not corrected.
2. Where the registry is reachable, the name is checked against it. A malicious package that was removed usually leaves a name-holding record with zero versions and a creation timestamp, and that timestamp is a useful independent check on the disclosure date.
3. Indicators are stored live, never defanged. A test rejects `[.]`, `hxxp` and similar.
4. `version` is copied verbatim from the source. When the source does not scope the damage to particular versions, the field is omitted rather than guessed.
5. When a campaign's indicators were not published in a citable form — a vendor names a count but not the artifacts — the incident goes to triage. A count is not an indicator.

## Severity rubric

Severity describes what an affected party loses, not how interesting the research is. Every entry states its reasoning in one line, so you can disagree on the evidence rather than on the label.

| Severity | Means |
| --- | --- |
| `critical` | Credential theft, code execution or full data exposure that needs no meaningful user action, or a self-propagating compromise. The blast radius reaches beyond the machine that ran it. |
| `high` | Code execution, sandbox escape or private-data exfiltration that needs a plausible precondition — the developer installs the thing, opens the repository, or has the tool running. Contained to the affected host or tenant. |
| `medium` | Real compromise with a narrow reach: short exposure window, low install count, or the payload needs conditions most targets will not meet. |
| `low` | Confirmed malicious or vulnerable, but the practical loss is small or the artifact never reached an install path. |

Scale moves severity within a band, it does not set it. A package with 4 million weekly downloads and one with 1,600 can both be `high` if what they do is the same; the download count belongs in the rationale.

## Status

- `active` — the artifact is still reachable, or the underlying problem is unfixed.
- `remediated` — removed from the registry, patched, revoked, or otherwise no longer reachable.
- `disputed` — an involved party contests the entry and the question is not settled.

Status describes the artifact. It never describes confidence in the evidence; that is what the primary-source rule is for.

## Dispute process

1. Anyone can open a [dispute](https://github.com/MEGA-M1ND/AI-Code-Threat-Radar/issues/new?template=dispute-an-entry.yml) issue, or write privately using [SECURITY.md](../SECURITY.md).
2. The entry is set to `status: disputed` within the working week, and the dispute issue is linked from the discussion. The entry stays in the feed. Consumers see the contest rather than watching a record vanish.
3. The dispute is resolved against evidence, in public. A registry record, a vendor statement or a maintainer's own account settles most of them.
4. Outcome:
   - **Sustained** — the entry is corrected in place, or its indicators are narrowed. `last_updated` moves; the `id` does not change.
   - **Not sustained** — status returns to what it was, and the reasoning is written in the issue.
   - **Wrong entry** — the entry stays, with a summary saying what it got wrong and `status: disputed` retained. Rapsheet does not delete history, because a consumer that already ingested an indicator needs to see the retraction, not an absence.
5. Ids are never reused and never renumbered.

A single-indicator correction — a mistyped package name, a wrong version bound — does not need the full process. Open a pull request; that is a bug, and it gets fixed the same day it is proven.
