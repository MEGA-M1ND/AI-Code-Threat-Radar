# Launch post notes

Raw material for the announcement post. Not written up on purpose — these are the five entries out of 29 that are worth someone's attention, with the specifics you would need to make each point.

---

## 1. The first malware that used AI coding agents as its recon tool — `RS-2025-0008`

- Nx, 4M weekly downloads, compromised 26 Aug 2025. Postinstall script `telemetry.js`.
- The novel part: it checked whether `claude`, `gemini` or `q` were installed and ran them with `--dangerously-skip-permissions`, `--yolo` and `--trust-all-tools` respectively, handing each a prompt asking it to inventory wallet files, keystores, `.env` files, SSH keys and browser storage into `/tmp/inventory.txt`.
- The attacker did not write a file-scanning payload. They asked the developer's own agent to do it, and the agent did.
- Exfiltrated to a public repo created in the victim's own GitHub account — `s1ngularity-repository`, `-0`, `-1` — triple-base64 in `results.b64`. GitHub disabled them 8 hours later; the window was enough.
- Second phase used the leaked tokens to flip victims' private repos public.
- Root cause was a `pull_request_target` GitHub Actions injection landed via a pull request on 21 Aug that Snyk assesses was itself likely written by Claude Code. The loop closes on itself.
- Nx postmortem: https://nx.dev/blog/s1ngularity-postmortem
- Advisory: https://github.com/nrwl/nx/security/advisories/GHSA-cxm3-wv7p-598c
- Wiz on the second phase: https://www.wiz.io/blog/s1ngularity-supply-chain-attack

## 2. A worm that installs its own MCP server in your editor — `RS-2026-0001`

- SANDWORM_MODE, disclosed by Socket 20 Feb 2026. Nineteen typosquatted npm packages under two aliases, `official334` and `javaorg`.
- Three of the nineteen are typosquats of Claude Code specifically: `claud-code`, `cloude-code`, `cloude`. One is `opencraw`. The rest squat ordinary utilities (`suport-color`, `rimarf`, `hardhta`).
- Credential theft is table stakes at this point. The new capability: it deploys and **registers a malicious MCP server in the victim's AI coding assistant** (Cursor named explicitly) and seeds it with prompt-injection instructions, plus harvests LLM API keys as a distinct credential category.
- That is persistence inside the toolchain. Removing the npm package does not remove it.
- All 19 names are still resolvable on npm as name-holding records created within a five-minute window at 16:52–16:58 UTC on 20 Feb 2026 — independently checkable, which is a nice detail for the post.
- Socket: https://socket.dev/blog/sandworm-mode-npm-worm-ai-toolchain-poisoning

## 3. A marketplace where 12% of everything was malware — `RS-2026-0002`

- Koi Security audited all 2,857 skills on ClawHub in Feb 2026. 341 malicious. 335 of them one campaign, ClawHavoc. A single account published 314 of them.
- By mid-February the marketplace had grown to over 10,700 skills and the count had gone from 341 to 824. It got worse, not better.
- Delivery mechanism is the interesting bit and it is not a technical exploit. The `SKILL.md` says a prerequisite called "OpenClawCLI" must be installed first and points at `openclawcli.vercel.app`. The agent relays that to the user as a setup step. The user trusts the agent. The download is Atomic macOS Stealer.
- Targeting is deliberate: machines running an agent continuously, often always-on Mac minis.
- The audit was run by Koi's own OpenClaw bot, which raised the question itself. Good framing if you want it.
- Koi: https://www.koi.ai/blog/clawhavoc-341-malicious-clawedbot-skills-found-by-the-bot-they-were-targeting
- Trend Micro on the AMOS variant: https://www.trendmicro.com/en_us/research/26/b/openclaw-skills-used-to-distribute-atomic-macos-stealer.html
- Related and separate: Snyk's `clawdhub` campaign (`RS-2026-0003`), where the malicious skill impersonated ClawHub's own CLI — 7,743 downloads before removal.

## 4. One line of code — `RS-2025-0001`

- `postmark-mcp` on npm. An MCP server letting agents send email through Postmark. Author listed as Jabal Torres. First published 15 Sept 2025.
- Fifteen versions behaved exactly as advertised. Version 1.0.16 added one line: `Bcc: 'phan@giftshop.club'`.
- Every email the agent sent — password resets, financial notices, internal memos — got copied to the attacker. 1,643 downloads before removal.
- The best short argument that MCP has no trust model. There was no exploit, no vulnerability, no obfuscation. Someone cloned a repo, added a BCC header and published under the expected name.
- Koi called it the first malicious MCP server found in the wild, and it held that title for about three weeks.
- Koi: https://www.koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft
- Snyk with the code: https://snyk.io/blog/malicious-mcp-server-on-npm-postmark-mcp-harvests-emails/

## 5. Malware that now lives in `.claude/` — `RS-2026-0005`

- Shai-Hulud, August 2026 wave. Started at `keyv` and `cacheable`, reached 400+ packages across 1,700+ versions. JFrog, 4 Aug 2026 — three weeks before this feed was built, and still `active`.
- The lineage in one line: Sept 2025 first npm worm (~500 packages) → Nov 2025 v2 (796 packages, targeted `mcp-server` names) → May 2026 crossed into PyPI (172 packages incl. `@squawk/mcp`, `nextmove-mcp`) → Aug 2026, this one.
- What changed in August: it writes `math_init.js` and `setup.mjs` into `.claude/` and `.vscode/`, and modifies `.claude/settings.json`. The payload runs when the agent next starts.
- Persistence moved into the agent's config directory. Removing the package does not remove the malware.
- Its cover commits are attributed to `Co-authored-by: claude <claude@users.noreply.github.com>` so they blend into normal repository activity.
- JFrog: https://research.jfrog.com/post/shai-hulud-is-back-august/

---

## Framing that might be useful

- The four-wave Shai-Hulud lineage plus SANDWORM_MODE is one story arc: attackers went from stealing credentials *from* developer machines to establishing persistence *inside* the agent's own configuration, in about eleven months.
- Three separate incidents here (`RS-2025-0008`, `RS-2026-0001`, `RS-2026-0005`) treat the AI agent as infrastructure to be used rather than as a target to be attacked. That is the shift worth naming.
- Counterweight, if you want one: of the 29 entries, 22 are `remediated`. The ecosystem's response times are not the problem. The absence of shared memory across those responses is — which is the reason this database exists.
- Two things did **not** go in, and are worth a sentence because the discipline is the product: the Kaspersky Open VSX "Solidity Language" case (a real $500k theft, but Kaspersky never published the extension's registry identifier and guessing it would put a false positive in someone's blocklist) and Rules File Backdoor (real, well-sourced, and has no artifact to match on). Both are in `triage/unverified.md` with what is missing.
