# Collector notes

What Session 2 built, what it found, and the parts worth writing about. Same
purpose as `session1-post-notes.md` — raw material, not a written-up post.

---

## The line worth taking

Every "AI supply chain threat feed" is a list. This one has a pipeline behind it
that can tell you *why* it isn't longer. That's the differentiator, and it's
provable: the collector run prints `SKIPPED` with a reason when it couldn't
reach a source, separately from `ok, 0 new` when it looked and found nothing.
Most feeds cannot distinguish "quiet week" from "broken for a month".

## 1. Threshold tuning is the whole job, and nobody shows their work

Worth a short post on its own. The first version of the name matcher, swept
against the real PyPI index (877,858 names), returned **952 hits**. Reading
them showed three separate failures:

- **`mcp`, `agent-sdk`, `mcp-client` in the watchlist.** Category words, not
  product names. Several hundred unrelated legitimate packages sit within two
  edits of them. `nx` — two characters — matched `6x` and `9x`.
- **Affix matching.** `claude-code-sdk`, `langchain-cli`, `mcp-server-py`,
  `crewai-tools`. This is how ecosystems name legitimate companion packages.
  138 of the 952 hits, roughly 5% precision.
- **Edit distance 2.** `langchain-cohere` and `langchain-forge` are two edits
  from `langchain-core` and entirely legitimate. Meanwhile `x-transformers`,
  `pytransformers` and `vtransformer` all sat two edits from `transformers`.

952 → 41 after fixing those → **15** after gating on package creation date.

The Damerau detail is the satisfying bit: counting a transposition as one edit
instead of two means `langchian` — the single most common real typo shape for
`langchain` — is still caught at distance 1, so the threshold could be tightened
without losing the case it exists for.

## 2. npm does not delete malware, and reading that wrong is a 20-alarm mistake

The best bug of the session and a genuinely useful public fact.

When npm removes a package for malware it does **not** unpublish it. It
substitutes a `0.0.1-security` stub, so the registry document still carries a
version, a `dist-tags.latest`, and a recent `modified` timestamp. A naive
"does this name resolve with versions?" check reads that as *live*.

That check turned all 20 SANDWORM_MODE typosquats in the feed — correctly
removed by npm — into 20 high-confidence "republished!" alarms. There are four
distinct states and only one of them means live code:

| State | What the document looks like |
|---|---|
| `absent` | 404, or no `versions` at all |
| `unpublished` | `time.unpublished` present, no `versions` — e.g. `postmark-mcp` |
| `security-holding` | only `X.Y.Z-security` versions — npm's malware removal |
| `live` | at least one version that isn't a `-security` stub |

The census across all 28 names the feed documents as malicious: 6 gone, 20
security-held, 2 unpublished, **0 live**. That number is now recorded in
`collectors/state/slopsquat.json` on every run, which makes it a continuous
verification of the feed's own remediation claims rather than a one-time check.

## 3. The signal that sounded great and wasn't

Worth including because the honest version is more interesting than a win.

The MCP registry namespace `io.github.alice` is verified by the registry against
GitHub. The repository URL in the same record is not. So a listing by
`io.github.alice` pointing at `github.com/bob/…` is claiming an association it
hasn't proven — that sounds like a strong impersonation signal.

Across 2,500 live records it fired **21 times**, and every single one was a
person publishing under their personal GitHub account with the code in their
company's org: `hassaanali723` → `giggal-ai`, `dvcoolarun` → `docuqueue`,
`atef-ataya` → `depwire`. Benign, all of it.

What survived is the narrow version: fire only when the repository belongs to
an owner whose name carries weight — `anthropics`, `modelcontextprotocol`,
`openai`, `stripe`. Borrowing *reputation* is the threat; a mismatch on its own
is a normal Tuesday. The general case is recorded as evidence on candidates that
qualified some other way.

Same shape as the affix finding. The general lesson, which is the actual post:
**a queue with a bad signal in it is worse than a smaller queue**, because a
triager who learns the queue is mostly noise stops reading it. Measure a rule
against real data before trusting it, and demote it to evidence when it doesn't
earn a candidate.

## 4. Smaller things

- **PyPI publishes its entire name index** (43 MB, ETag-cached) so the sweep is
  exhaustive rather than sampled — every name on PyPI scored against the
  watchlist in about seven seconds, locally. npm has no equivalent, which is why
  that pass has to be targeted and rotating. Worth a sentence for anyone
  building something similar.
- **Search results lie about age.** npm's search API returns `date`, which is
  the *last* publish. An actively maintained ten-year-old package reads as 27
  days old. The packument's `time.created` is the only honest answer, and the
  age gate is what turns 41 hits into 15.
- **The watchlist had to be split in two.** Names already in the feed as
  malicious cannot sit alongside legitimate names: `claud-code` in the
  watchlist would score a fresh copy of itself as a zero-distance match on a
  *legitimate* name — the exact opposite of what it is. An assertion in
  `collectors/watchlist.py` enforces the separation.
- **Reconfirming a candidate doesn't rewrite its file.** A daily triage PR whose
  diff is forty unchanged candidates with a refreshed timestamp is a PR nobody
  reads.

## What's in the queue right now

14 candidates, all medium confidence. They are leads, not findings, and two of
them are good illustrations of why the human step exists:

- `langchaint` (PyPI, 39 days old, 25 releases). One edit from `langchain`. Its
  own summary field reads *"It ain't langchain."* Not a squat — a joke.
- `router-cli` (PyPI). Scope-drop match against `@tanstack/router-cli`. It is a
  management tool for a D-Link DSL-2750U.

Both are one-glance dismissals. That is the design working: the collector's job
is to be worth reading for thirty seconds, not to be right.

The ones actually worth a primary-source read: `codei-cli` / `codet-cli` /
`codey-cli` / `xodex-cli` (four separate one-edit neighbours of `codex-cli`,
which is a suspicious amount of coincidence), and `clawbot` / `clawdboz` /
`clawdbot2` around `clawdbot`.

## Not built, and why

- **`advisories`** (GitHub Security Advisories, OSV). Would feed `platform-vuln`
  and `compromised-package` — the two categories that are already the deepest,
  and the ones Georgia Tech's Vibe Security Radar already covers. Building it
  now would deepen the feed exactly where it should not.
- **`skills`** (ClawHub and skill marketplaces). Targets `malicious-skill`,
  which is the thinnest category and therefore the highest-value collector to
  build next. Deferred only because ClawHub is unreachable from this sandbox
  and shipping a collector whose live path has never executed is how you get a
  pipeline that has been broken since the day it was written.
