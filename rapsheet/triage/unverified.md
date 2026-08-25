# Triage

Candidates that were investigated and did **not** reach the feed, with exactly what is missing. Nothing here is in `dist/`. An item moves out of this file and into `data/entries/` the moment the missing piece is found — and the feed is never padded to hit a number, so this file existing is the system working.

Last reviewed: 2026-08-25.

---

## Failed sourcing

Real-looking incidents with no primary source that could be read.

### Asana MCP server cross-tenant data exposure (June 2025)

- **What:** Asana's hosted MCP server, launched 1 May 2025, had a flawed tenant-isolation check. Between 5 and 17 June 2025 users of one organisation could surface task, project and team data belonging to other organisations. Asana disabled MCP access while fixing it and estimates around 1,000 customers were affected.
- **Missing:** a primary source. Asana notified affected customers directly and there is no public advisory page to cite. Everything reachable — BleepingComputer, The Register, CSO Online, SANS NewsBites — is reporting on that private notice.
- **Would need:** a public Asana security advisory or status-page entry, or the customer notice published in full by a recipient.
- **Indicator that would be used:** `{"type": "mcp-server", "url": "https://mcp.asana.com/sse"}` with a `platform-vuln` category. Verified before use.

### OpenClaw skills used to push 400+ malware packages (February 2026)

- **What:** reporting that over 230 malicious OpenClaw packages were uploaded in a matter of days, using MoltBot skills to spread password stealers, with a total in the 400s.
- **Missing:** the original research. The reachable write-up is SecurityAffairs summarising someone else's count, and it is unclear whether this is a distinct campaign or a re-count of ClawHavoc (`RS-2026-0002`).
- **Would need:** the researcher write-up behind the number, and skill or package names.
- **Note:** a count is not an indicator. This does not ship on a number alone.

---

## Verified, but no machine-matchable indicator

Well-sourced and squarely in scope, but with nothing a guard can match on. An entry with no indicator gives a consumer nothing, and the schema requires at least one.

### Rules File Backdoor (Pillar Security, 18 March 2025)

- **What:** invisible Unicode characters embedded in AI coding-assistant configuration files — `.cursorrules`, `.cursor/rules/`, `.github/copilot-instructions.md` — carry instructions that the model reads and a human reviewer cannot see. The instruction survives forking and pull-request review, so one poisoned rules file propagates.
- **Primary source:** https://www.pillar.security/blog/new-vulnerability-in-github-copilot-and-cursor-how-hackers-can-weaponize-code-agents
- **Missing:** any artifact. No package, no hash, no domain, no named rules file in the wild. It is a technique, not an incident, and Pillar published it as one.
- **Also notable:** both vendors declined to treat it as a vulnerability on their side — Cursor on 8 March 2025, GitHub on 12 March 2025. If a real-world poisoned rules file is ever attributed, this becomes an entry with `status: disputed`.
- **What would unblock it:** a repository or rules file observed carrying it, or a file-path indicator type if one is ever added to the schema.

### Kaspersky "Solidity Language" extension on Open VSX (July 2025)

- **What:** an extension published to Open VSX — the registry Cursor installs from — impersonating the legitimate `juanblanco/solidity` extension, with its description copied verbatim. It had 54,000 downloads against the real extension's 61,000 and ranked above it in a search for "solidity". A blockchain developer who installed it lost roughly $500,000. When it was removed, the attackers published a replacement under the exact name `solidity`.
- **Primary source:** https://securelist.com/open-source-package-for-cursor-ai-turned-into-a-crypto-heist/116908/
- **Missing:** the malicious extension's Open VSX namespace identifier. Kaspersky names the *display* name ("Solidity Language") and the legitimate extension it copied, but not the `publisher.name` of the malicious one, and the extension is gone from the registry.
- **What would unblock it:** the Open VSX identifier from Kaspersky's IOC list, Open VSX's own removal record, or an archived listing page.
- **Note:** this one is painful to leave out. Guessing the identifier would be exactly the kind of mistake that puts a false positive in someone's guard, so it waits.

---

## Out of scope

Real attacks, correctly sourced, that belong in somebody else's database.

### ETHcode VS Code extension compromise (June–July 2025)

A throwaway GitHub account landed a 43-commit pull request on the ETHcode extension whose 4,000 changed lines hid a dependency on `keythereum-utils`, which spawned a PowerShell downloader. ReversingLabs found it, Microsoft removed the extension on 26 June 2025, and 0.5.1 restored it clean. Primary source: https://www.reversinglabs.com/blog/malicious-pull-request-infects-vscode-extension — **out of scope** because ETHcode is an Ethereum development extension with no connection to AI coding tooling. A general VS Code supply-chain incident, not an agent-ecosystem one.

### "Solidity Pro" extensions (August 2026)

`helper-beeps.solidity-pro` and `web3devtoolsx.solidity-pro` stole browser profiles, wallets, source-control tokens, API keys and SSH keys, exfiltrating over Telegram; Open VSX added both to its malicious-extension control list on 6–7 August 2026. Primary source: SlowMist. **Out of scope** for the same reason as ETHcode — the target is Web3 developers, not users of AI coding agents. Reconsider if a variant is found to target agent tooling specifically.

### Package-hallucination research (USENIX Security 2025)

Spracklen et al., "We Have a Package for You!", measured 205,474 unique hallucinated package names across 576,000 code samples, at 5.2% of outputs for commercial models and 21.7% for open-source ones. It is the study that gave slopsquatting its shape, and it is **research, not an incident**. Its example names — `react-codeshift`, a conflation of `jscodeshift` and `react-codemod` — are names a model invents, not packages anyone published. Treating one as a published attack is precisely the error the earlier version of this project made; see [docs/MIGRATION.md](../docs/MIGRATION.md). Cite the paper, do not catalogue it.

### Tea app data exposure (July 2025)

Widely described as a vibe-coded application whose storage bucket was left unauthenticated. **Not entered** because the vibe-coded attribution is repeated everywhere and sourced nowhere; without it this is an ordinary cloud misconfiguration and does not meet the `vibe-app-breach` bar, which requires the failure to trace to how the application was produced.

---

## Open leads

Not yet investigated, listed so the next session does not start from nothing.

- `CVE-2025-58444` — a second MCP Inspector advisory, seen referenced alongside `CVE-2025-49596`. Not researched.
- GlassWorm wave 5 (2026) — reported as the first malicious MCP server using invisible Unicode, plus 72+ new Open VSX extensions and 150+ GitHub repositories with AI-generated cover commits. Needs the extension identifiers.
- The `atool` campaign (19 May 2026) — 643 malicious versions across 323 packages, reported to persist via `.claude/settings.json` SessionStart hooks and `.vscode/tasks.json` folderOpen tasks. Same persistence technique as `RS-2026-0005`, different actor. Needs a primary source; the description above comes from a detection-tool changelog.
- Mini Shai-Hulud's CVE (`CVE-2026-45321`) — seen attached to the TanStack compromise. `RS-2026-0006` covers the campaign but does not yet cite this identifier or the TanStack package list. Socket published an affected-versions feed that would supply exact package and version pairs.
- "ChainDrop" — an alternative name in circulation for the August 2026 keyv/cacheable wave catalogued as `RS-2026-0005`, with claims that its C2 list is held in an Ethereum contract. Not in the JFrog write-up the entry rests on. Worth confirming before the entry mentions either.
- Smithery and other MCP registries — no incident found yet, but nothing suggests they have been looked at properly.
- Codex CLI — no platform incident found. Its absence from the feed reflects a gap in searching, not a clean record.

### Checked and closed

- "AI coding-agent hijack, August 2026" — a scanner project lists this as a distinct campaign of daemons spawning `claude`, `codex` and `gemini` with `--dangerously-skip-permissions`. Searching turns up only re-reporting of s1ngularity (`RS-2025-0008`) and SANDWORM_MODE (`RS-2026-0001`), both already catalogued. Not a separate incident on the evidence available.
