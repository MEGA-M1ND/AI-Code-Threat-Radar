# AI Code Threat Radar

> Threat intelligence for the **AI agent supply chain** — malicious agent skills, poisoned MCP servers, slopsquatted packages, and insecure‑by‑default AI coding platforms.

AI Code Threat Radar is a dark, high‑contrast "threat‑intel console" web app that catalogs security threats emerging from the way AI coding agents actually work: the skills they install, the tool servers (MCP) they connect to, the packages they hallucinate, and the platforms they run inside. It is deliberately positioned to cover the layer that Georgia Tech SSLab's **[Vibe Security Radar](https://vibe-radar-ten.vercel.app/)** does *not* — instead of competing on AI‑generated‑code CVE tracking, it owns malicious skills, MCP threats, slopsquatting, and platform vulnerabilities, and it cites Vibe Security Radar for the CVE‑style entries it does include.

The app ships with a curated set of realistic mock threat entries, a filterable database, per‑entry detail pages, a fully client‑side "exposure checker," and a methodology page describing the evidence standard and dispute process.

---

## Table of Contents

- [What this project is](#what-this-project-is)
- [Feature overview](#feature-overview)
- [Architecture](#architecture)
- [Tech stack](#tech-stack)
- [Repository layout](#repository-layout)
- [The threat feed data model](#the-threat-feed-data-model)
- [Threat categories](#threat-categories)
- [Frontend deep dive](#frontend-deep-dive)
- [Backend deep dive](#backend-deep-dive)
- [The Exposure Checker](#the-exposure-checker)
- [Security posture](#security-posture)
- [Design system](#design-system)
- [Environment variables](#environment-variables)
- [Running locally](#running-locally)
- [Testing](#testing)
- [Roadmap / backlog](#roadmap--backlog)
- [Credits & attribution](#credits--attribution)

---

## What this project is

Modern software is increasingly written *with* AI agents, not just by humans. That shifts the supply‑chain attack surface in ways traditional vulnerability databases don't track:

- Agents install **"skills"** from marketplaces and chat groups that can run postinstall hooks or smuggle prompt‑injection payloads.
- Agents connect to **MCP (Model Context Protocol) servers** that may leak OAuth tokens, run unsanitized shell commands, or concatenate SQL.
- Agents **hallucinate package names** ("slopsquatting"), which attackers pre‑register and weaponize.
- Agent‑running **platforms / IDEs** ship insecure defaults (workspace‑trust bypasses, sandbox escapes).
- Real‑world **incidents** occur when agent‑generated infrastructure or endpoints go unreviewed.

AI Code Threat Radar is a curated, structured feed of exactly these threats, with a UI built for analysts: dense, scannable, monospaced IDs/CVEs, and clear status semantics (Confirmed / Reported / Remediated / Disputed).

It also carries a deliberate **India‑specific angle** — several entries document India‑originating distribution vectors or incidents (a "productivity pack" spread via WhatsApp/Telegram, a Bengaluru fintech S3 exposure), surfaced through a dedicated "India Radar" callout.

> **Note:** The current dataset is **realistic mock data** (15 entries), not a live feed. See the [Roadmap](#roadmap--backlog) for how to wire a real feed.

---

## Feature overview

| Route | Page | What it does |
|-------|------|--------------|
| `/` | **Home** | 3D radar/network globe hero, four lead‑category stat cards (Malicious Skills / MCP Threats / Slopsquatting / Platform Vulns), total‑entries footnote, a "Latest Threats" strip (5 newest), the India Radar callout, and a "Check your exposure" CTA. |
| `/database` | **Database** | Filterable/searchable list of all entries — a dense table on desktop, cards on mobile. Filters: Type (category), Status, Ecosystem, Tags (multi‑select), free‑text search, and a sort toggle between `date_disclosed` and `last_updated`. |
| `/database/:id` | **Entry Detail** | Full entry view: description, impact, root cause, indicators, tags, a numbered Sources list, and a source‑attribution badge for entries sourced from Vibe Security Radar. |
| `/check` | **Exposure Checker** | Paste a `package.json`, dependency list, agent skill file, or MCP config → get known‑indicator matches + heuristic warnings. **100% client‑side**, zero network calls on submit. |
| `/methodology` | **Methodology** | Evidence standard, status definitions, dispute process, and a "Related Projects" section crediting Georgia Tech SSLab's Vibe Security Radar. |
| `*` | **404 / NotFound** | Themed not‑found page. |

---

## Architecture

The app uses a **thin backend proxy** pattern rather than a fully static frontend fetch, chosen to avoid CORS issues while keeping the backend stateless:

```
┌──────────────────────────────────────────────────────────────┐
│                         Browser (SPA)                        │
│                                                              │
│  React 19 + React Router 7                                   │
│  ┌────────────┐   FeedContext (loads once, shared globally)  │
│  │ Home       │        │                                     │
│  │ Database   │        ▼                                     │
│  │ EntryDetail│   fetchFeed()  ──►  GET /api/feed?t=<ts>     │
│  │ Checker    │   (cache: no-store)                          │
│  │ Methodology│                                              │
│  └────────────┘                                              │
└───────────────────────────────┬──────────────────────────────┘
                                 │  REACT_APP_BACKEND_URL
                                 ▼
┌──────────────────────────────────────────────────────────────┐
│                    FastAPI backend (server.py)               │
│                                                              │
│  GET /api/feed  ──►  reads backend/data/feed.json fresh      │
│                      on every request (no cache, no DB)      │
│                      Cache-Control: no-store                 │
│                                                              │
│  (boilerplate, unused by this feature:)                      │
│  GET  /api/           → {"message": "Hello World"}           │
│  POST /api/status     → writes StatusCheck to MongoDB        │
│  GET  /api/status     → lists StatusChecks from MongoDB      │
└──────────────────────────────────────────────────────────────┘
```

Key decisions (from `memory/PRD.md`):

- **`GET /api/feed` reads the JSON file fresh on every request** and returns it with `Cache-Control: no-store`. There is **zero database usage** for the threat‑radar feature — the frontend always sees the latest data with no redeploy and no caching.
- **No auth, no accounts, no DB** for the core feature. The `/api/status` MongoDB routes are pre‑existing scaffold from the base image and are untouched/unused by this app.
- The backend proxy stands in for a future `RAW_FEED_URL` (e.g. `raw.githubusercontent.com`); swapping the data source later requires touching only `feed.json` or the `get_feed` handler.

---

## Tech stack

**Frontend**
- **React 19** + **React Router 7** (`react-router-dom`), SPA.
- **Create React App** tooling via **CRACO** (`@craco/craco`) for config overrides (webpack alias `@ → src`, ESLint rules, optional health‑check plugin, Emergent visual‑edits in dev).
- **Tailwind CSS 3** + **shadcn/ui** (Radix UI primitives) — the full `src/components/ui/*` component library is vendored in.
- **3D hero:** `@react-three/fiber` v9 + `three` + `@react-three/drei` v10.
- Supporting libs: `framer-motion`, `lucide-react` (icons), `date-fns`/`dayjs`, `recharts`, `sonner`/toast, `zod` + `react-hook-form`, `swr`/`@tanstack/react-query` (available; core feed uses a hand‑rolled context).

**Backend**
- **FastAPI** + **Uvicorn**.
- **Motor** (async MongoDB driver) — present for the boilerplate `/api/status` routes only.
- **Pydantic v2** models.
- **pytest** + **pytest-xdist** for the API test suite.

**Platform**
- Built on Emergent's `fastapi_react_mongo_shadcn_base_image_cloud_arm` base image (see `.emergent/emergent.yml`).
- **PostHog** analytics and a "Made with Emergent" badge are injected in `frontend/public/index.html`.

---

## Repository layout

```
AI-Code-Threat-Radar/
├── README.md                      ← this file
├── design_guidelines.json         ← the full design system spec (colors, type, layout)
├── test_result.md                 ← build/test log & agent protocol notes
├── .emergent/emergent.yml         ← base image + job metadata
├── memory/
│   └── PRD.md                     ← product requirements / build history (great context)
├── tests/                         ← top-level test package placeholder
├── test_reports/                  ← pytest XML + iteration JSON reports
│
├── backend/
│   ├── server.py                  ← FastAPI app: /api/feed proxy + /api/status boilerplate
│   ├── requirements.txt           ← Python deps
│   ├── pytest.ini                 ← pinned xdist config (-n 2 --dist loadscope)
│   ├── data/
│   │   └── feed.json              ← THE threat feed (15 entries + indicator_index)
│   └── tests/
│       └── test_feed_api.py       ← 8 API tests (structure, counts, headers, attribution)
│
└── frontend/
    ├── package.json               ← deps, scripts (craco start/build/test)
    ├── craco.config.js            ← webpack/eslint overrides, @ alias, visual-edits
    ├── tailwind.config.js         ← theme tokens, fonts, status colors
    ├── postcss.config.js
    ├── components.json            ← shadcn/ui config
    ├── jsconfig.json
    ├── plugins/health-check/      ← optional dev-server health endpoints (opt-in)
    ├── public/
    │   ├── index.html             ← CSP meta, Google Fonts, PostHog, OG tags
    │   ├── robots.txt
    │   └── sitemap.xml
    └── src/
        ├── index.js               ← React entry
        ├── App.js                 ← router + FeedProvider + Navbar/Footer/Toaster
        ├── index.css / App.css    ← Tailwind layers + base theme
        ├── context/
        │   └── FeedContext.jsx     ← loads the feed once, shares { feed, loading, error, refetch }
        ├── lib/
        │   ├── feed.js             ← fetchFeed() + derived stats (counts, sorts, unique values)
        │   ├── checker.js          ← client-side token extraction + heuristic patterns
        │   ├── links.js            ← isSafeExternalUrl() URL guard
        │   └── utils.js            ← cn() classname helper
        ├── constants/
        │   ├── categories.js       ← category order/labels, status colors, external URLs
        │   └── testIds/            ← kebab-case data-testid registries per page
        ├── components/
        │   ├── HeroRadar3D.jsx      ← the react-three-fiber globe + radar sweep
        │   ├── ThreatCard.jsx, StatCard.jsx, FilterBar.jsx,
        │   ├── StatusBadge.jsx, CategoryBadge.jsx, SourceAttributionBadge.jsx,
        │   ├── IndiaRadarCallout.jsx, RelatedProjectsCard.jsx,
        │   ├── SafeLink.jsx, Seo.jsx, Navbar.jsx, Footer.jsx, FeedErrorState.jsx
        │   └── ui/                  ← full shadcn/ui primitive library
        └── pages/
            ├── Home.jsx, Database.jsx, EntryDetail.jsx,
            ├── Checker.jsx, Methodology.jsx, NotFound.jsx
```

---

## The threat feed data model

The single source of truth is **`backend/data/feed.json`**. Top‑level shape:

```jsonc
{
  "name": "AI Code Threat Radar",
  "generated": "2026-02-01",
  "entry_count": 15,
  "indicator_index": {
    // indicator string → array of entry IDs that reference it.
    // Used by the Exposure Checker for O(1)-ish lookups.
    "react-codeshift": ["2026-01-react-codeshift"],
    "numpyy": ["sl-002-numpyy"],
    ...
  },
  "entries": [ /* 15 entry objects */ ]
}
```

Each **entry** object:

| Field | Type | Meaning |
|-------|------|---------|
| `id` | string | Unique, human‑readable slug (also the `/database/:id` route param). |
| `title` | string | Display title, often with a parenthetical threat type. |
| `type` | string | Fine‑grained type (`malicious-agent-skill`, `compromised-mcp-server`, `slopsquatting`, `platform-vulnerability`, `incident`, `agent-tool-cve`). |
| `_category` | string | Coarse category used for grouping/filtering — see [Threat categories](#threat-categories). |
| `status` | string | `confirmed` \| `reported` \| `remediated` \| `disputed`. Drives badge color. |
| `date_disclosed` | ISO date | Public disclosure date (default sort key). |
| `added` / `last_updated` | ISO date | Feed bookkeeping; `last_updated` is the alternate sort key. |
| `description` | string | What the threat is. |
| `impact` | string | Blast radius / consequences. |
| `root_cause` | string | Why it happened. |
| `ecosystem` | string | e.g. `npm`, `pypi`, `mcp`, `agent-skill-marketplace`, `ide-platform`, `cloud-infrastructure`. |
| `indicators` | string[] | Matchable IOCs (package names, server names, etc.). |
| `tags` | string[] | Free‑form tags (`credential-theft`, `prompt-injection`, `india`, `rce`, …). |
| `cve` | string | CVE ID when applicable (else empty/absent). |
| `references` | string[] | Source URLs. |
| `notes` | string | Analyst notes. |
| `source_attribution` | object | **Only on `agent-tool-cves` entries** — `{ name, url }` crediting Vibe Security Radar. |

The feed's integrity is enforced by the backend test suite (counts per category, presence/absence of `source_attribution`, indicator‑index lookups, no Mongo `_id` leakage).

---

## Threat categories

Categories are defined and **ordered** in `frontend/src/constants/categories.js`. Order is intentional: the categories this project *owns* come first; `agent-tool-cves` (cited from Vibe Security Radar) comes last.

| Category key | Label | Count |
|--------------|-------|:-----:|
| `malicious-skills` | Malicious Skills | 3 |
| `mcp-threats` | MCP Threats | 3 |
| `slopsquatting` | Slopsquatting | 3 |
| `platform-vulns` | Platform Vulnerabilities | 2 |
| `incidents` | Incidents | 2 |
| `agent-tool-cves` | Agent‑Tool CVEs *(cited from Vibe Security Radar)* | 2 |

**Status semantics** (with their design‑system colors):

| Status | Color | Meaning |
|--------|-------|---------|
| `confirmed` | 🔴 `#ef4444` | Independently verified. |
| `reported` | 🟠 `#f59e0b` | Disclosed, awaiting remediation/confirmation. |
| `remediated` | 🟢 `#10b981` | Fixed / patched. |
| `disputed` | ⚪ `#71717a` | Contested; retained for tracking. |

---

## Frontend deep dive

### App shell & routing
`src/App.js` wraps everything in a forced‑dark container, mounts `FeedProvider` (so the feed loads once and is shared), and sets up the six routes plus a global `Navbar`, `Footer`, and toast `Toaster`.

### Feed loading
- `src/context/FeedContext.jsx` calls `fetchFeed()` on mount and exposes `{ feed, loading, error, refetch }` via `useFeed()`.
- `src/lib/feed.js` handles the actual fetch (`GET ${REACT_APP_BACKEND_URL}/api/feed?t=<timestamp>` with `cache: 'no-store'`) and provides pure helpers used across pages:
  - `sortEntriesByDate(entries, field)` — descending sort by date string.
  - `computeCategoryCounts(entries)` — map of `_category → count`.
  - `computeHomeStats(feed)` — totals, critical (`confirmed`) count, most‑recent date, and the four lead‑category counts for the homepage stat cards.
  - `getUniqueValues(entries, field)` — powers the Database filter dropdowns (handles both scalar and array fields like `tags`).

### The 3D hero (`HeroRadar3D.jsx`)
A deliberately lightweight `@react-three/fiber` scene (no post‑processing/bloom, for performance):
- **NetworkGlobe** — 64 points distributed on a sphere via a Fibonacci‑style spiral (`generateSpherePoints`), connected with line segments wherever two points are within a distance threshold, forming a wireframe "supply chain" mesh.
- **Threat blips** — 7 deterministically chosen nodes (seeded LCG) rendered larger and red with a translucent glow sphere.
- Two thin `torus` rings and an ambient + two colored point lights (red/amber) complete the look.
- **RadarSweep** — a translucent amber `ShapeGeometry` sector that rotates continuously, evoking a radar sweep.

### Reusable components
- **`StatusBadge` / `CategoryBadge`** — colored, bordered badges using the status/category tokens.
- **`StatCard`** — homepage KPI tiles.
- **`ThreatCard`** — entry summary card (mobile list + latest‑threats strip).
- **`FilterBar`** — the Database page's type/status/ecosystem/tag/search/sort controls.
- **`IndiaRadarCallout`** — surfaces India‑tagged entries.
- **`SourceAttributionBadge`** — shown on Vibe‑Security‑Radar‑sourced CVE entries.
- **`RelatedProjectsCard`** — cross‑references Vibe Security Radar on the Methodology page + Footer.
- **`SafeLink`** — renders a real anchor **only** for `http(s)` URLs (via `isSafeExternalUrl`), otherwise inert text; always adds `rel="noopener noreferrer" target="_blank"`.
- **`Seo`** — a lightweight custom component that sets per‑page `<title>`/meta/OG tags (no heavy SEO library).
- **`FeedErrorState`** — retry UI when the feed fails to load.

### Test IDs
`src/constants/testIds/` centralizes **kebab‑case, role‑based `data-testid` values** so automated tests can target interactive elements deterministically.

---

## Backend deep dive

`backend/server.py` is small and intentionally stateless for the feed:

- **`GET /api/feed`** — opens `backend/data/feed.json`, parses it, and returns it as JSON with `Cache-Control: no-store, no-cache, must-revalidate`. Reading fresh from disk each call means editing `feed.json` updates the live app immediately, with no cache to bust and no DB migration.
- **`GET /api/`** — returns `{"message": "Hello World"}` (scaffold).
- **`POST /api/status` / `GET /api/status`** — pre‑existing MongoDB‑backed `StatusCheck` CRUD from the base image. **Not used by the threat‑radar feature**; they exist because the base image wires up Mongo (`MONGO_URL`, `DB_NAME`) and are kept for compatibility.
- **CORS** is enabled via `CORS_ORIGINS` (comma‑separated, defaults to `*`).
- All routes are mounted under an `/api` prefix router.

> Because the app initializes a Mongo client at import time (`os.environ['MONGO_URL']`), the backend expects `MONGO_URL` and `DB_NAME` to be set even though the feed endpoint never touches the database.

---

## The Exposure Checker

`/check` is a **privacy‑first, entirely client‑side** analyzer. The logic lives in `src/lib/checker.js` and makes **zero network calls on submit** — your paste never leaves the browser. It does two things:

**1. Known‑indicator matching.** It tokenizes your input (`extractTokens` — package names, scoped `@org/pkg` names, and URLs), then matches those tokens against the feed's `indicator_index`, returning the matching entries (linked to their detail pages) via `matchIndicators`.

**2. Heuristic scanning** (`runHeuristics`) against regex patterns for common footguns:

| ID | Detects | Severity |
|----|---------|:--------:|
| `aws-key` | Hardcoded AWS access key (`AKIA…`) | high |
| `private-key` | Embedded PEM private‑key header | high |
| `generic-secret` | `api_key`/`secret`/`token`/`password = "…"` assignments | medium |
| `curl-bash` | `curl … \| bash` (or `wget … \| sh`) remote‑exec pattern | high |
| `raw-ip-url` | URL pointing at a raw IP address | medium |
| `non-https` | Plain‑`http://` URL | low |

`analyzePaste(text, feed)` combines both into `{ knownMatches, heuristicWarnings }`, which the page renders as collapsible accordions with severity dots. A built‑in `EXAMPLE_PASTE` (a booby‑trapped `package.json`) is available via the "Load example" button. The UI prominently states this is a *lite check against known indicators, not a full security audit*.

---

## Security posture

Security hardening is a first‑class concern (this *is* a security app):

- **Strict Content‑Security‑Policy** meta tag in `public/index.html` (`default-src 'self'`, tightly allowlisted script/style/font/connect sources for fonts + PostHog + the Emergent badge, `frame-src 'none'`, `object-src 'none'`, `base-uri 'self'`).
- **No `dangerouslySetInnerHTML` anywhere.**
- **`SafeLink` + `isSafeExternalUrl`** ensure only `http(s)` URLs from feed data ever become clickable anchors; everything else renders as inert text — defending against `javascript:`/`data:` link injection through feed content.
- All external links use `rel="noopener noreferrer"` + `target="_blank"`.
- The Exposure Checker's **zero‑network guarantee** is explicit and was verified during testing.
- Backend feed endpoint is read‑only and sends `no-store` headers.

---

## Design system

The complete spec lives in **`design_guidelines.json`**. Highlights:

- **Theme:** "Archetype 4 (Swiss & High‑Contrast) adapted for Threat Intelligence" — professional, dense, credible, restrained.
- **Fonts:** **Chivo** (headings), **IBM Plex Sans** (body), **JetBrains Mono** (all IDs, IPs, CVEs, code) — loaded from Google Fonts. *No Inter.*
- **Palette:** near‑black backgrounds (`#09090b` / `#121214`), zinc text ramp, and pure **red / amber / emerald / gray** reserved strictly for threat status. No teal, no purple, no new colors.
- **Surfaces:** flat 1px‑bordered cards, `rounded-none`/`rounded-sm`, **no shadows**, no glowing gradients (except the 3D radar blips). "Control Room Grid" — tight gaps, rigid columns, `tabular-nums` for numbers.
- **Motion:** very restrained; quick hover micro‑interactions only.

---

## Environment variables

**Frontend** (build‑time, `REACT_APP_*`):

| Variable | Purpose |
|----------|---------|
| `REACT_APP_BACKEND_URL` | Base URL of the FastAPI backend. `fetchFeed()` calls `${REACT_APP_BACKEND_URL}/api/feed`. **Required.** |
| `ENABLE_HEALTH_CHECK` | If `"true"`, enables the optional dev‑server health endpoints/plugin (`craco.config.js`). |

**Backend** (`backend/.env`, loaded via `python-dotenv`):

| Variable | Purpose |
|----------|---------|
| `MONGO_URL` | Mongo connection string. **Required at import time** even though the feed endpoint doesn't use the DB. |
| `DB_NAME` | Mongo database name. Required at import time. |
| `CORS_ORIGINS` | Comma‑separated allowed origins (default `*`). |

> `.env` files are git‑ignored (see `.gitignore`) and are **not** committed. Provide your own when running locally.

---

## Running locally

> The project is designed to run on the Emergent platform base image, but the pieces are standard FastAPI + CRA and run locally with the right env vars.

**Backend**

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Provide the env the app expects (Mongo is required at import even for the feed):
export MONGO_URL="mongodb://localhost:27017"
export DB_NAME="threat_radar"
export CORS_ORIGINS="*"

uvicorn server:app --reload --host 0.0.0.0 --port 8001
# Feed:   http://localhost:8001/api/feed
```

**Frontend**

```bash
cd frontend
yarn install                      # (packageManager pins yarn 1.22)

# Point the SPA at your backend:
echo 'REACT_APP_BACKEND_URL=http://localhost:8001' > .env

yarn start                        # craco start → http://localhost:3000
# yarn build                      # production bundle
```

---

## Testing

**Backend** — `backend/tests/test_feed_api.py` (8 tests, run with pytest + xdist as pinned in `pytest.ini`):

```bash
cd backend
export REACT_APP_BACKEND_URL="http://localhost:8001"   # tests hit the live endpoint
pytest
```

Coverage includes: `200` status, response structure, exactly **15 entries**, `no-store` cache header, per‑category counts, that **only** `agent-tool-cves` entries carry `source_attribution` (pointing at `vibe-radar-ten.vercel.app`), indicator‑index lookups, and that no Mongo `_id` field leaks into the feed.

> `pytest.ini` pins `-n 2 --dist loadscope` — do not change it; tests share one preview backend and rely on that layout.

**Frontend** — `yarn test` (CRACO/Jest). Per the PRD, the app was validated end‑to‑end via the platform's testing agent (backend 100%, frontend ~95%, with one nested‑anchor bug found and fixed post‑test). See `test_result.md` and `test_reports/` for the recorded run.

---

## Roadmap / backlog

From `memory/PRD.md`:

- **P1 — Live feed:** replace the mock `feed.json` with a real `RAW_FEED_URL` (e.g. a GitHub `raw.githubusercontent.com` feed), by swapping the file source in `get_feed` or pointing the frontend directly at the raw URL.
- **P1 — Newsletter:** real Beehiiv embed (currently skipped entirely).
- **P2 — Real repo:** stand up an actual repo for `CONTRIBUTING.md` / `DISPUTES.md` / feed source (currently placeholder URLs under `github.com/ai-code-threat-radar/feed`).
- **P2 — Lighthouse:** formal performance/accessibility/SEO audit (target ≥ 90).
- **P3 — Checker patterns:** expand heuristic coverage (more secret formats, GitHub/GitLab tokens, private‑key variants).

---

## Credits & attribution

- **Related project — [Vibe Security Radar](https://vibe-radar-ten.vercel.app/)** by **Georgia Tech SSLab** ([GitHub](https://github.com/HQ1995/vibe-security-radar)). AI Code Threat Radar intentionally covers the layer Vibe Security Radar does *not*, and cites it for all `agent-tool-cves` entries (each carries an explicit `source_attribution`). Cross‑referenced on the Methodology page and in the Footer.
- Built on the **Emergent** platform (`fastapi_react_mongo_shadcn_base_image_cloud_arm` base image).

---

*The threat data currently shipped is realistic **mock** data for demonstration. Do not treat entries as live advisories.*
