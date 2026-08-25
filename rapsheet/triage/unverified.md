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

Not yet investigated or blocked on one specific fact, listed so the next session does not start from nothing. The three thin categories — `malicious-skill`, `slopsquat-package`, `malicious-mcp-server` — are the only acceptable destination for new entries until they reach parity with `platform-vuln`.

### Blocked on one fact

- **`omnicogg` (ClawHub skill, JFrog, March 2026).** A base64 curl-pipe-bash dropper delivering AMOS from `91.92.242.30`, hidden behind a README.md whose payload sits at the top followed by 22 MB of padding — enough to push the file past the size threshold at which many content-analysis pipelines stop reading. ClawScan had it in review and VirusTotal returned clean while it stayed downloadable. Primary source: https://research.jfrog.com/post/omnicogg-malicious-skill/ — corroborated by Unit 42. **Missing:** the day of the JFrog post. Every source reached says only "March 2026", and `first_seen` takes a full ISO date. One look at the post header fixes this and it ships as a `malicious-skill` entry with a skill slug and a C2 address already in hand.

### Needs a category decision

- **`mouse5212-super-formatter` (npm, OX Security, 27 May 2026).** Stole files from Claude Code's `/mnt/user-data` workspace and exfiltrated them through GitHub; described by the researchers as AI-generated "malware-slop". Unpublished from npm — the name now resolves with zero versions, which matches the reported takedown. Primary source: OX Security via https://thehackernews.com/2026/05/malicious-npm-package-stole-files-from.html. **Blocked because** it fits no current category: it was never legitimate, so not `compromised-package`, and the name squats nothing, so not `slopsquat-package`. It wants a seventh category along the lines of `malicious-package` — a package malicious from its first version, where a guard should block the name outright rather than a version range. `codexui-android` (`RS-2026-0010`) was filed as `compromised-package` because it genuinely had a clean early window; this one does not.

### Rejected on indicator quality

- **ClawHavoc skill names from Snyk.** https://snyk.io/articles/skill-md-shell-access/ says the campaign "deployed Skills with names like `solana-wallet-tracker`, `polymarket-trader`, and `uniswap-sniper`". "Names like" is illustrative phrasing, and all three are names a legitimate skill would plausibly use — blocklisting them on that wording is exactly the false positive this project exists to avoid. `polymarket-traiding-bot` **was** added to `RS-2026-0003`, because Snyk lists it in an explicit IOC line beside `clawhud` and `clawhub1` and the misspelling makes it distinctive. Needs the campaign's actual slug list to go further.

### Not yet chased

- **GlassWorm C2 addresses.** Koi's wave-4 post lists `45.32.151.157` (primary C2, shared with wave 3), `45.32.150.251` (exfiltration) and `217.69.11.60` (earlier C2, 27 November 2025), plus the Solana C2 wallet `BjVeAjPrSKFiingBn4vZvghsGj9KCE8AJVtbc9S8o8SC`. These belong to waves 3 and 4, not to wave 1 (`RS-2025-0011`) or wave 5 (`RS-2026-0008`, `RS-2026-0009`), so they need their own entry rather than being attached to an existing one. The schema now has an `ip` indicator type for them. There is no indicator type for a blockchain wallet address.
- **GlassWorm waves 2, 3 and 4** — Koi published all three (`glassworm-returns-new-wave-openvsx-malware-expose-attacker-infrastructure`, `glassworm-goes-native-same-infrastructure-hardened-delivery`, `glassworm-goes-mac-fresh-infrastructure-new-tricks`). Wave 4 pivoted to macOS with hardware-wallet trojans and included a Prettier Pro impersonation on Open VSX. Each has its own extension list.
- **`openclaw-yahoo-stock-news`** — a ClawHub skill whose SKILL.md tells the agent to install an npm package of that name and run its `init`. A skill-to-npm handoff, which is a distinct delivery shape worth its own entry. Seen in Snyk's threat-modelling write-up; needs confirmation that the npm package was actually published and malicious.
- **`CVE-2025-58444`** — a second MCP Inspector advisory, seen referenced alongside `CVE-2025-49596`. Not researched.
- **arXiv 2602.06547, "Detecting and Understanding Malicious Agent Skills"** — a systematic analysis of 98,380 skills across two registries. Unlikely to yield blocklistable indicators, but the taxonomy would sharpen `docs/METHODOLOGY.md`.
- **Smithery and other MCP registries** — no incident found yet, but nothing suggests they have been looked at properly.

### Closed

- The `atool` / AntV campaign (19 May 2026) is now `RS-2026-0007`.
- `CVE-2026-45321` and the TanStack package list are folded into `RS-2026-0006`, from TanStack's own postmortem and maintainer issue.
- GlassWorm wave 5's MCP server is now `RS-2026-0008`, and its 72 Open VSX impersonation extensions are `RS-2026-0009`. `RS-2025-0011` was upgraded from a four-extension partial list to Koi's full fifteen-entry wave-1 IOC list.
- The Kaspersky Open VSX "Solidity Language" case stays open above — still no published registry identifier.

### Checked and closed

- "AI coding-agent hijack, August 2026" — a scanner project lists this as a distinct campaign of daemons spawning `claude`, `codex` and `gemini` with `--dangerously-skip-permissions`. Searching turns up only re-reporting of s1ngularity (`RS-2025-0008`) and SANDWORM_MODE (`RS-2026-0001`), both already catalogued. Not a separate incident on the evidence available.
