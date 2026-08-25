"""Near-miss detection: a dependency whose name resembles a real one.

Same lineage as RADAR's collector-side matcher, and the same thresholds, which
were set by sweeping the full PyPI index and reading the 952 hits that came
back. Two of the three lessons apply directly here:

* A name built only from category words (`mcp`, `agent-sdk`) matches hundreds of
  unrelated legitimate packages, so it earns no fuzzy matching.
* Edit distance 2 is where precision collapses — `langchain-cohere` is two edits
  from `langchain-core` and entirely legitimate — so this uses distance 1, with
  transposition counted as one edit so `langchian` is still caught.

The third lesson does not apply: the collector gates on package age, and a
scanner has no age to gate on. Instead it only reports a near miss when the
name is *not* itself in the feed as legitimate, and it says "check this" rather
than "this is malicious", because that is all it knows.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace

from .findings import Finding

GENERIC_TOKENS = {
    "mcp", "agent", "agents", "sdk", "api", "cli", "client", "server", "core",
    "tools", "tool", "utils", "lib", "use", "proxy", "inspector", "scan", "md",
    "skill", "skills", "kit", "app", "ai", "llm", "chat", "bot", "py", "js",
    "node", "code", "dev", "hub", "run", "cloud", "web", "data", "model",
}
MIN_LEN = 7
MIN_SINGLE_TOKEN_LEN = 8
BLOCK = 4
_SEPARATORS = re.compile(r"[-_.]+")


def bare(name: str) -> str:
    return name.split("/", 1)[1] if name.startswith("@") and "/" in name else name


def is_distinctive(name: str) -> bool:
    text = bare(name).lower()
    tokens = [t for t in _SEPARATORS.split(text) if t]
    if not tokens or all(t in GENERIC_TOKENS for t in tokens):
        return False
    return not (len(tokens) == 1 and len(text) < MIN_SINGLE_TOKEN_LEN)


def distance(a: str, b: str, limit: int = 1) -> int:
    """Damerau-Levenshtein (OSA), bounded. Transposition counts as one edit."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    if len(a) > len(b):
        a, b = b, a
    before, previous = None, list(range(len(a) + 1))
    for j, cb in enumerate(b, 1):
        current, best = [j], j
        for i, ca in enumerate(a, 1):
            value = min(previous[i] + 1, current[i - 1] + 1,
                        previous[i - 1] + (0 if ca == cb else 1))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                value = min(value, before[i - 2] + 1)
            current.append(value)
            best = min(best, value)
        before, previous = previous, current
        if best > limit:
            return limit + 1
    return previous[-1]


@dataclass(frozen=True)
class NearMiss:
    name: str
    target: str
    ecosystem: str

    def _replace_location(self, location: str, version: str) -> Finding:
        return Finding(
            kind="near-miss", severity="medium",
            title=f"{self.name} closely resembles {self.target}",
            detail=(
                f"`{self.name}` is one character away from `{self.target}`, a "
                f"package RADAR tracks. That is the shape of a typosquat, and it "
                f"is also the shape of two unrelated projects with similar names."
            ),
            location=location, artifact=self.name, installed_version=version,
            remediation=(
                f"Confirm you meant `{self.name}` and not `{self.target}`. Check "
                f"the registry page: publish date, download count, repository link."
            ),
            uncertainty="a resemblance is not evidence of anything on its own",
        )


class NearMissChecker:
    """Scores installed names against the legitimate names in the feed."""

    def __init__(self, index):
        self.blocks: dict[str, dict[str, set[str]]] = {}
        self.targets: dict[str, set[str]] = {}
        for ecosystem in ("npm", "pypi"):
            names = {n for n in index.legitimate_names(ecosystem) if is_distinctive(n)}
            self.targets[ecosystem] = names
            table: dict[str, set[str]] = {}
            for name in names:
                text = bare(name).lower()
                for start in range(0, len(text) - BLOCK + 1, BLOCK):
                    table.setdefault(text[start:start + BLOCK], set()).add(name)
            self.blocks[ecosystem] = table
        # Everything the feed knows about, legitimate or not. A name already
        # reported as a direct hit must not also be reported as a near miss.
        self.known = {
            ecosystem: {n for (reg, n) in index.packages if reg == ecosystem}
            for ecosystem in ("npm", "pypi")
        }

    def __call__(self, ecosystem: str, name: str) -> NearMiss | None:
        lowered = name.lower()
        if ecosystem not in self.targets:
            return None
        if lowered in self.known.get(ecosystem, ()):
            return None
        text = bare(lowered)
        if len(text) < MIN_LEN:
            return None
        seen: set[str] = set()
        for start in range(len(text) - BLOCK + 1):
            for target in self.blocks[ecosystem].get(text[start:start + BLOCK], ()):
                if target in seen:
                    continue
                seen.add(target)
                if distance(text, bare(target).lower(), 1) == 1:
                    return NearMiss(name, target, ecosystem)
        return None
