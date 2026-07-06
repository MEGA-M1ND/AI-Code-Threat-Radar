# AI Code Threat Radar — PRD

## Original Problem Statement
Build the application described in the user's uploaded spec ("Emergent Prompt — AI Code Threat Radar Web App"), themed around cybersecurity, with 3D visuals to make it intuitive and visually striking.

A follow-up "Emergent Update Prompt — Reposition AI Code Threat Radar" was received before any build existed in this session, repositioning the app to own the layer that Georgia Tech SSLab's "Vibe Security Radar" does NOT cover (malicious agent skills, MCP threats, slopsquatting, platform vulns) rather than competing on AI-generated-code CVE tracking, and adding an India-specific angle. Since no prior build existed, both the original spec and the repositioning update were implemented together as a single first build.

## User Choices (gathered via ask_human)
- Feed data: realistic mock data (15 entries), not a real GitHub RAW_FEED_URL.
- Newsletter: skipped entirely.
- 3D visual: rotating radar sweep + 3D network/particle globe (combined), hero only.
- Architecture: thin backend proxy (GET /api/feed reads a static JSON file fresh per request — zero DB usage) instead of fully static frontend-only fetch, to avoid CORS.
- GitHub CONTRIBUTING.md / DISPUTES.md links: placeholder repo (github.com/ai-code-threat-radar/feed).

## Architecture
- **Frontend**: React 19 + React Router 7 + Tailwind + shadcn/ui. 3D hero via @react-three/fiber v9 + three + @react-three/drei v10.
- **Backend**: FastAPI thin proxy. `GET /api/feed` reads `/app/backend/data/feed.json` fresh on every call (no caching, no DB usage, `Cache-Control: no-store`). Pre-existing `/api/status` boilerplate untouched/unused by this app.
- **No auth, no accounts, no database usage for this feature.**

## Pages
- `/` Home — 3D hero, 4 lead category stats (malicious skills / MCP threats / slopsquatting / platform vulns), total-entries footnote, Latest Threats strip (5 newest), India Radar callout, Check-your-exposure CTA.
- `/database` — filterable/searchable table (desktop) / card list (mobile) of all 15 entries. Filters: Type (category, ordered: Malicious Skills, MCP Threats, Slopsquatting, Platform Vulnerabilities, Incidents, Agent-Tool CVEs), Status, Ecosystem, Tags (multi-select), free-text search, sort toggle (date_disclosed / last_updated).
- `/database/:id` — full entry detail with numbered Sources list, source-attribution badge for agent-tool-cves entries.
- `/check` — client-side-only Exposure Checker: paste text → token extraction, indicator matching against feed, heuristic checks (AWS keys, generic secrets, private keys, curl|bash, raw-IP URLs, non-HTTPS). Zero network calls on submit (verified).
- `/methodology` — evidence standard, status definitions, dispute process, Related Projects section crediting Georgia Tech SSLab's Vibe Security Radar.

## Data Model
`/app/backend/data/feed.json` — 15 entries across `_category`: malicious-skills(3), mcp-threats(3), slopsquatting(3), platform-vulns(2), incidents(2), agent-tool-cves(2, each with `source_attribution: {name, url}` pointing to https://vibe-radar-ten.vercel.app/).

## What's Been Implemented (2026-02-01, first build)
- Full 6-page app (Home, Database, Entry Detail, Checker, Methodology, 404) with dark cybersecurity-intel theme (Chivo/IBM Plex Sans/JetBrains Mono, red/amber/emerald/gray status colors).
- 3D radar/network globe hero visual (react-three-fiber, lightweight, no post-processing).
- Repositioning copy fully applied: supply-chain-first headline, category-led homepage stats, India Radar callout (proportionate), Related Projects cross-reference (Methodology + Footer), source-attribution badges distinguishing agent-tool-cves entries.
- Client-side-only Exposure Checker with verified zero-network-call guarantee.
- Security hardening: strict CSP meta tag, SafeLink component (only renders http(s) as real anchors), no dangerouslySetInnerHTML anywhere, all external links use rel=noopener noreferrer + target=_blank.
- SEO: per-page title/meta/OG via lightweight custom `Seo` component, robots.txt, sitemap.xml.
- Tested via `testing_agent_v3`: backend 100% (8 pytest tests passing), frontend ~95% (1 medium nested-anchor bug found and fixed post-test).

## Prioritized Backlog
- **P1**: Wire up a real `RAW_FEED_URL` when the user has an actual GitHub repo (swap `/app/backend/data/feed.json` source or point frontend directly at raw.githubusercontent.com).
- **P1**: Real Beehiiv newsletter embed (currently skipped entirely per user request).
- **P2**: Real GitHub repo for CONTRIBUTING.md/DISPUTES.md/feed source (currently placeholder URLs).
- **P2**: Lighthouse audit pass (performance/accessibility/SEO ≥ 90) — not yet formally measured.
- **P3**: Expand heuristic checker patterns (more secret formats, GitHub/GitLab tokens, private key variants).

## Next Action Items
- If/when the user has a real GitHub feed repo, swap the mock `feed.json` for the live `RAW_FEED_URL`.
- Provide real Beehiiv embed code if newsletter capture is wanted later.
