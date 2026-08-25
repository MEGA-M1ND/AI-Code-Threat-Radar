"""Name-similarity scoring for the slopsquat detector.

The question this answers: *is this package name trying to be mistaken for one
of ours?* Being wrong in either direction has a cost — a miss lets a squat
through, a false positive burns a human's triage time — so every match carries
the rule that produced it and the target it hit.

The thresholds here were not guessed. Each was set by scanning the full PyPI
index (878k names) against the watchlist and reading what came back:

* Generic targets (`mcp`, `agent-sdk`, `mcp-client`) matched several hundred
  unrelated legitimate packages. Category words earn no fuzzy protection.
* Affix matching (`claude-code-sdk`, `langchain-cli`) is how ecosystems name
  legitimate companion packages — near-useless on a full sweep, useful when a
  human is already reading one brand's results. It is opt-in per call site.
* Edit distance 2 is where precision collapses: `langchain-cohere` is two
  edits from `langchain-core` and entirely legitimate. The sweep uses 1.

Kept separate from the collector because the matching is the part worth
testing without a network.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Tokens that describe a *category*, not a product. A name built only from
# these is a phrase anyone might reach for independently.
GENERIC_TOKENS = {
    "mcp", "agent", "agents", "sdk", "api", "cli", "client", "server", "core",
    "tools", "tool", "utils", "lib", "use", "proxy", "inspector", "scan", "md",
    "skill", "skills", "kit", "app", "ai", "llm", "chat", "bot", "py", "js",
    "node", "code", "dev", "hub", "run", "cloud", "web", "data", "model",
}

# Suffixes and prefixes squatters bolt onto a real name.
AFFIX_SUFFIXES = (
    "js", "cli", "sdk", "api", "py", "python", "node", "mcp", "server",
    "client", "tools", "plugin", "official", "latest", "new", "2", "3", "x",
    "beta", "pro", "plus", "core", "utils", "helper", "agent",
)
AFFIX_PREFIXES = (
    "node", "py", "python", "js", "npm", "lib", "the", "my", "get", "install",
    "official", "real", "new", "open", "free",
)

# Character swaps that survive a glance in a terminal font.
HOMOGLYPHS = {
    "l": "1", "1": "l", "i": "j", "o": "0", "0": "o", "e": "3", "a": "4",
    "s": "5", "z": "s", "c": "k", "k": "c", "u": "v", "v": "u", "m": "rn",
    "n": "m", "b": "6", "g": "9", "q": "g", "w": "vv",
}

# Below this length an edit is most of the name: two-thirds of `mcp` is one
# character. Short targets are matched by the exact-form rules only.
MIN_EDIT_LEN = 7
# A single short word — `scale`, `eslint`, `history`, `deluge` — is a word
# before it is a brand. Protecting it produces hits on packages that simply
# share the English language with us.
MIN_SINGLE_TOKEN_LEN = 8
BLOCK = 4

ALL_RULES = ("scope-drop", "separator", "homoglyph", "edit", "affix")
# What a full-index sweep uses. Affix is excluded by measurement, not taste.
SWEEP_RULES = ("scope-drop", "separator", "homoglyph", "edit")

_SEPARATORS_RE = re.compile(r"[-_.]+")


def normalize_pypi(name: str) -> str:
    """PEP 503 normalization. On PyPI `claude_code` and `claude-code` are one project."""
    return _SEPARATORS_RE.sub("-", name).lower()


def strip_separators(name: str) -> str:
    return _SEPARATORS_RE.sub("", name.lower())


def bare(name: str) -> str:
    """The unscoped part of an npm name: `@anthropic-ai/claude-code` -> `claude-code`."""
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def is_distinctive(name: str) -> bool:
    """True if the name identifies a product rather than describing a category."""
    text = bare(name).lower()
    tokens = [t for t in _SEPARATORS_RE.split(text) if t]
    if not tokens or all(t in GENERIC_TOKENS for t in tokens):
        return False
    if len(tokens) == 1 and len(text) < MIN_SINGLE_TOKEN_LEN:
        return False
    return True


def levenshtein(a: str, b: str, max_distance: int = 2) -> int:
    """Damerau-Levenshtein (optimal string alignment), bounded.

    Transposition counts as one edit, not two: `langchian` for `langchain` is
    the most common real typo shape, and treating it as distance 1 lets the
    sweep threshold stay at 1 without missing it.
    """
    if a == b:
        return 0
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    if len(a) > len(b):
        a, b = b, a

    before = None                      # row j-2, needed for transpositions
    previous = list(range(len(a) + 1))
    for j, cb in enumerate(b, start=1):
        current = [j]
        best = j
        for i, ca in enumerate(a, start=1):
            cost = 0 if ca == cb else 1
            value = min(previous[i] + 1, current[i - 1] + 1, previous[i - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                value = min(value, before[i - 2] + 1)
            current.append(value)
            best = min(best, value)
        before, previous = previous, current
        if best > max_distance:
            return max_distance + 1
    return previous[-1]


@dataclass(frozen=True)
class Match:
    """One reason a name looks like an impersonation of `target`."""

    name: str
    target: str
    rule: str          # scope-drop | separator | homoglyph | edit | affix
    distance: int

    @property
    def confidence(self) -> str:
        if self.rule in ("scope-drop", "separator", "homoglyph"):
            return "medium"
        if self.rule == "edit" and self.distance == 1:
            return "medium"
        return "low"

    def why(self) -> str:
        return {
            "edit": f"{self.distance} character edit from {self.target}",
            "separator": f"identical to {self.target} once separators are removed",
            "affix": f"{self.target} with a plausible-looking affix attached",
            "scope-drop": f"the unscoped form of the scoped package {self.target}",
            "homoglyph": f"a look-alike character substitution on {self.target}",
        }[self.rule]


class SquatMatcher:
    """Scores a registry name against a watchlist of legitimate names.

    Scanning a 878k-name index against 150 targets needs a prefilter. One edit
    cannot spoil every disjoint 4-character block of a name, so a name within
    edit distance 1 of a target must share one of that target's blocks; at
    distance 2 the guarantee needs three blocks, which every target long enough
    to be matched at that distance has.
    """

    def __init__(self, watchlist, max_distance: int = 1, rules=SWEEP_RULES):
        self.max_distance = max_distance
        self.rules = tuple(rules)
        self.targets = {t.lower() for t in watchlist}

        # A target only earns fuzzy matching if it names a product and is long
        # enough that one changed character is a slip rather than a new word.
        def fuzzy_ok(t: str) -> bool:
            return len(bare(t)) >= MIN_EDIT_LEN and is_distinctive(t)

        # `@scope/name` also protects the bare `name` — publishing the unscoped
        # form is the cheapest impersonation of a scoped package there is.
        self.scoped_bare: dict[str, str] = {}
        for t in sorted(self.targets):
            if t.startswith("@") and "/" in t and fuzzy_ok(t):
                self.scoped_bare.setdefault(bare(t), t)

        self.plain = {t for t in self.targets if not t.startswith("@")}
        self.fuzzy = {t for t in self.plain if fuzzy_ok(t)}

        self.blocks: dict[str, set[str]] = {}
        for t in self.fuzzy:
            for start in range(0, len(t) - BLOCK + 1, BLOCK):
                self.blocks.setdefault(t[start:start + BLOCK], set()).add(t)

        self.squashed: dict[str, str] = {}
        for t in sorted(self.fuzzy):
            self.squashed.setdefault(strip_separators(t), t)

    # ------------------------------------------------------------------
    def _affix_target(self, name: str) -> str | None:
        for suffix in AFFIX_SUFFIXES:
            for sep in ("-", "_", "."):
                if name.endswith(sep + suffix):
                    stem = name[: -(len(suffix) + len(sep))]
                    if stem in self.targets:
                        return stem
            if name.endswith(suffix) and name[: -len(suffix)] in self.targets:
                return name[: -len(suffix)]
        for prefix in AFFIX_PREFIXES:
            for sep in ("-", "_", "."):
                if name.startswith(prefix + sep) and name[len(prefix) + len(sep):] in self.targets:
                    return name[len(prefix) + len(sep):]
        return None

    def _homoglyph_target(self, name: str) -> str | None:
        for original, swap in HOMOGLYPHS.items():
            start = 0
            while (i := name.find(swap, start)) != -1:
                candidate = name[:i] + original + name[i + len(swap):]
                if candidate in self.fuzzy:
                    return candidate
                start = i + 1
        return None

    def _nearest_edit(self, name: str) -> tuple[str, int] | None:
        best: tuple[str, int] | None = None
        seen: set[str] = set()
        for start in range(len(name) - BLOCK + 1):
            for target in self.blocks.get(name[start:start + BLOCK], ()):
                if target in seen:
                    continue
                seen.add(target)
                distance = levenshtein(name, target, self.max_distance)
                if distance <= self.max_distance and (best is None or distance < best[1]):
                    best = (target, distance)
        return best

    # ------------------------------------------------------------------
    def match(self, name: str) -> Match | None:
        """The single strongest reason this name looks like a squat, or None.

        A name that *is* on the watchlist is never a match against itself.
        """
        lowered = name.lower()
        if lowered in self.targets:
            return None

        if "scope-drop" in self.rules:
            scoped = self.scoped_bare.get(lowered)
            if scoped:
                return Match(name, scoped, "scope-drop", 0)

        if "separator" in self.rules:
            squashed = self.squashed.get(strip_separators(lowered))
            if squashed and squashed != lowered:
                return Match(name, squashed, "separator", 0)

        if "homoglyph" in self.rules:
            homoglyph = self._homoglyph_target(lowered)
            if homoglyph:
                return Match(name, homoglyph, "homoglyph", 1)

        nearest = self._nearest_edit(lowered) if "edit" in self.rules else None
        if nearest and nearest[1] <= 1:
            return Match(name, nearest[0], "edit", nearest[1])

        if "affix" in self.rules:
            affix = self._affix_target(lowered)
            if affix:
                return Match(name, affix, "affix", 0)

        if nearest:
            return Match(name, nearest[0], "edit", nearest[1])
        return None
