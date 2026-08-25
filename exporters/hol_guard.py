"""HOL Guard native export — a ThreatIntelBundle built from the RADAR feed.

Written against the code, not the docs. HOL Guard
(github.com/hashgraph-online/hol-guard, package `codex_plugin_scanner`) reads
threat intelligence as a `ThreatIntelBundle`:

    {version:int, generated_at:float, expires_at:float, source:str,
     signature:str, advisories:[{advisory_id, source, severity, title,
                                 affected_type, matcher, recommendation}]}

Each advisory is dispatched by a `matcher` key against a registry in
`guard/runtime/advisory_matchers.py`, and several of those keys line up with
RADAR's indicator types — `npm`, `pypi`, `mcp_server`, `malicious_domain`,
`malicious_package_hash`. That correspondence is why a native export is worth
having rather than asking them to parse our schema.

**It carries only artifacts that should be blocked.** A `ThreatAdvisory` has a
severity and a free-text recommendation, and no action field. There is no way
to say "match this name and do *not* block it", which is precisely what a
`platform-vuln` entry means: `@anthropic-ai/claude-code` appears in this feed
because a version of it had a bug, and shipping that name at `severity: high`
into a format that cannot qualify it invites a guard to block software the
developer is entitled to run. Those advisories are withheld rather than
softened by wording nothing is obliged to read. `radar-deny.json` carries them,
because that format has an action.

Three further things this export cannot do, stated here because a consumer
needs to know before they trust it:

**It is unsigned.** `verify_bundle_signature()` checks an RSA-PSS signature
against HOL Guard's own public key. RADAR does not hold that key and will not
pretend to: the `signature` field carries the literal string `unsigned`, which
is a required non-empty string so the bundle parses, and which fails
verification loudly rather than quietly. A deployment that verifies signatures
must obtain this feed through HOL Guard's own signing pipeline; this file is
for deployments that pin the artifact digest instead.

**It carries no agent skills, which is most of what RADAR knows.** HOL Guard's
only skill matcher is `skill_hash`, and reading it settles the question: it
compares against `target["skill_hash"]`, a content hash. RADAR's skill
indicators are marketplace slugs — `clawhub-6yr3b`, `google-qx4` — and there is
no matcher that takes one. Emitting 344 slugs under `skill_hash` would produce
a bundle that looks 344 advisories richer and matches nothing, so they are
counted as skipped instead. A `skill_slug` matcher is the single change that
would let this export carry RADAR's largest indicator class; see
docs/consumers.md.

**It has no `packages` bundle.** The richer `SupplyChainBundle` — risk scores,
policy rules, purls — is a signed, workspace-scoped, cloud-issued artifact with
`workspaceId` and `keyId`. That one cannot meaningfully be produced by a third
party at all, so this export targets the advisory bundle, which can.
"""
from __future__ import annotations

from .common import decide_action, feed_epoch, feed_version, indicator_value

# Freshness window. `check_bundle_freshness()` rejects a bundle past expires_at,
# so this has to outlast a realistic release cadence without being unbounded.
VALIDITY_DAYS = 90

BUNDLE_SOURCE = "radar"
UNSIGNED = "unsigned"

# RADAR indicator type -> HOL Guard matcher key, from _MATCHER_REGISTRY.
# `skill` is deliberately absent: see the module docstring.
MATCHER_FOR_TYPE = {
    "mcp-server": "mcp_server",
    "domain": "malicious_domain",
    "hash": "malicious_package_hash",
}
# Package indicators dispatch on their registry instead of their type.
MATCHER_FOR_REGISTRY = {"npm": "npm", "pypi": "pypi"}

# HOL Guard ranks severity as info|low|medium|high|critical. RADAR has no
# `info`, and every RADAR severity maps straight through.
SEVERITIES = {"critical", "high", "medium", "low"}


def matcher_key(entry: dict, indicator: dict) -> str | None:
    """The HOL Guard matcher that would dispatch this indicator, if any.

    Returns None where HOL Guard has no matcher that could ever fire — skill
    slugs, `ip`, `url`, `application`, and VS Code extensions. Dropping those
    silently would overstate coverage, so callers count what was skipped.
    """
    kind = indicator["type"]
    if kind == "package":
        return MATCHER_FOR_REGISTRY.get(indicator.get("registry", ""))
    if kind == "mcp-server":
        # match_mcp_server compares against a server *name*. An indicator that
        # only carries a repo or endpoint URL has nothing that would match.
        return "mcp_server" if indicator.get("name") else None
    if kind == "hash":
        # A hash on a skill entry is a skill's content hash, which is exactly
        # what skill_hash wants; anywhere else it is a package artifact.
        return "skill_hash" if entry["category"] == "malicious-skill" else "malicious_package_hash"
    return MATCHER_FOR_TYPE.get(kind)


def _advisory(entry: dict, indicator: dict, key: str, ordinal: int) -> dict:
    action, why = decide_action(entry, indicator)
    value = indicator_value(indicator)
    versions = (indicator.get("affected") or {}).get("versions") or []
    version_note = indicator.get("version") or ", ".join(versions)

    if action == "block":
        recommendation = f"Block {value}. {why.capitalize()}."
    elif action == "warn":
        scope = f" Affected: {version_note}." if version_note else ""
        recommendation = f"Do not block the name {value}; it is legitimate.{scope} {why.capitalize()}."
    else:
        recommendation = f"Record a match on {value}. {why.capitalize()}."

    return {
        "advisory_id": f"{entry['id']}-{ordinal:03d}",
        "source": f"radar/{entry['category']}",
        "severity": entry["severity"] if entry["severity"] in SEVERITIES else "low",
        "title": entry["title"],
        "affected_type": indicator["type"],
        "matcher": value,
        "recommendation": recommendation,
    }


def build_hol_guard_bundle(feed: dict) -> dict:
    """Render the feed as a ThreatIntelBundle. Pure function of `feed`.

    Timestamps come from the feed's own `last_updated`, never from the clock,
    so an unchanged feed rebuilds byte-identically.
    """
    generated_at = feed_epoch(feed["last_updated"])
    advisories: list[dict] = []
    skipped: dict[str, int] = {}

    for entry in feed["entries"]:
        ordinal = 0
        for indicator in entry["indicators"]:
            action, _ = decide_action(entry, indicator)
            if action == "warn":
                # The format cannot express "match but do not block". See above.
                skipped["legitimate-artifact"] = skipped.get("legitimate-artifact", 0) + 1
                continue
            key = matcher_key(entry, indicator)
            if key is None:
                label = indicator["type"]
                if indicator["type"] == "package":
                    label = f"package/{indicator.get('registry', '?')}"
                elif indicator["type"] == "mcp-server":
                    label = "mcp-server/no-name"
                skipped[label] = skipped.get(label, 0) + 1
                continue
            ordinal += 1
            advisory = _advisory(entry, indicator, key, ordinal)
            # The matcher registry is keyed separately from the record; HOL
            # Guard reads `matcher` as the value and picks the function by the
            # advisory's source. Both are carried so neither has to be guessed.
            advisory["matcher_key"] = key
            advisories.append(advisory)

    advisories.sort(key=lambda a: (a["matcher_key"], a["affected_type"], a["matcher"], a["advisory_id"]))

    return {
        "version": feed_version(feed["last_updated"]),
        "generated_at": generated_at,
        "expires_at": generated_at + VALIDITY_DAYS * 86400,
        "source": BUNDLE_SOURCE,
        # Not a signature and not shaped like one. See the module docstring.
        "signature": UNSIGNED,
        "advisories": advisories,
        # Everything below is additive; HOL Guard's parser ignores unknown keys.
        "radar": {
            "homepage": feed["homepage"],
            "license": feed["license"],
            "attribution": feed["attribution"],
            "last_updated": feed["last_updated"],
            "entry_count": feed["entry_count"],
            "advisory_count": len(advisories),
            "unsigned": True,
            "unsigned_note": (
                "RADAR cannot sign for HOL Guard's key. Verify this artifact by "
                "its release SHA256SUMS digest, not by verify_bundle_signature()."
            ),
            "skipped_indicators": dict(sorted(skipped.items())),
            "skipped_note": (
                "Indicators this bundle cannot carry: types HOL Guard has no "
                "matcher for, plus legitimate artifacts that only radar-deny.json "
                "can qualify with an action. Counted rather than dropped "
                "silently, so coverage is not overstated."
            ),
        },
    }
