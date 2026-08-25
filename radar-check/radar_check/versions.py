"""Parsing the version strings RADAR actually publishes.

RADAR keeps `version` verbatim from the source it cites, because a feed that
silently normalises what a researcher wrote is a feed you cannot check against
the article. The cost lands here: these are human notation, not semver ranges.
Every shape below is one that appears in the published feed today.

    1.0.4                    a single version
    0.0.16, 0.0.17           a comma list
    0.0.5 - 0.1.15           a range, spaced
    1.0.0-1.0.32             a range, unspaced — ambiguous with a prerelease tag
    1.0.0-1.0.22+            a range whose upper bound is "at least this"
    <1.3.9  <=0.6.2  >=1.0.16   comparators
    2026.2.17                calendar versioning, not semver
    1.161.10                 four-digit minors; nothing here fits in a byte

The rule that matters more than any of the parsing: **an unparseable string is
reported, never guessed at**. Returning "no match" on a string we did not
understand hides a real hit; returning "match" hides nothing but cries wolf on
every version of the package. Both are wrong, so `parse` raises and the caller
surfaces the finding as needing a human. That is the whole reason this module
exists rather than a call to `packaging.specifiers`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# A version is a dotted run of digits with an optional trailing tag. Deliberately
# looser than semver: 2026.2.17 and 1.161.10 are both real, and neither is
# semver-compliant in the way a strict parser wants.
_VERSION_RE = re.compile(r"^\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?$")
_NUMERIC_RE = re.compile(r"^\d+(?:\.\d+)*$")
_COMPARATOR_RE = re.compile(r"^(<=|>=|<|>|=|==)\s*(.+)$")
_SPACED_RANGE_RE = re.compile(r"^(.+?)\s+-\s+(.+)$")


class UnparseableVersion(ValueError):
    """The version string is not a shape this module recognises.

    Raised rather than swallowed. A caller that cannot compare versions must
    say so in its output, not quietly decide.
    """


def normalize(text: str) -> str:
    return text.strip().lstrip("vV").strip()


def key(version: str) -> tuple:
    """Comparison key for a dotted numeric version.

    Compares component by component as integers, so 1.0.91 sorts above 1.0.9 —
    which string comparison gets wrong, and which matters: the feed carries both
    `1.0.9` and `1.0.91` as separate affected versions of the same package.

    A prerelease tag sorts below the same version without one, as semver
    requires; the tag itself is compared as text, which is enough to order
    `1.0.0-alpha` under `1.0.0-beta` without pretending to implement semver's
    full precedence rules.
    """
    text = normalize(version)
    tag = ""
    for separator in ("-", "+"):
        if separator in text:
            head, _, tail = text.partition(separator)
            if _NUMERIC_RE.match(head):
                text, tag = head, tail
                break
    if not _NUMERIC_RE.match(text):
        raise UnparseableVersion(f"not a dotted numeric version: {version!r}")
    parts = tuple(int(p) for p in text.split("."))
    # (0, ...) for a prerelease so it sorts below (1,) for the release.
    return (parts, 0 if tag else 1, tag)


def is_version(text: str) -> bool:
    return bool(_VERSION_RE.match(normalize(text)))


@dataclass(frozen=True)
class Constraint:
    """One clause of an affected-version expression."""

    kind: str                    # exact | range | lt | lte | gt | gte
    value: str | None = None     # for exact and comparators
    low: str | None = None       # for range
    high: str | None = None      # None means unbounded above
    # `fixed` in the schema names the first version that is NOT affected, so its
    # range is half-open. This has to be one constraint rather than a range plus
    # a separate `lt`: constraints are ORed, so two clauses would let the
    # unbounded half match the very version the other half excludes.
    high_exclusive: bool = False

    def matches(self, version: str) -> bool:
        try:
            target = key(version)
        except UnparseableVersion:
            return False
        if self.kind == "exact":
            return target == key(self.value)
        if self.kind == "range":
            if self.low and target < key(self.low):
                return False
            if self.high:
                bound = key(self.high)
                if target > bound or (self.high_exclusive and target == bound):
                    return False
            return True
        bound = key(self.value)
        return {
            "lt": target < bound, "lte": target <= bound,
            "gt": target > bound, "gte": target >= bound,
        }[self.kind]

    def describe(self) -> str:
        if self.kind == "exact":
            return self.value
        if self.kind == "range":
            if self.high and self.high_exclusive:
                return f"{self.low or '*'} up to but not including {self.high}"
            return f"{self.low or '*'} to {self.high or 'any later version'}"
        return {"lt": "<", "lte": "<=", "gt": ">", "gte": ">="}[self.kind] + self.value


def _split_unspaced_range(text: str) -> tuple[str, str] | None:
    """Tell `1.0.0-1.0.32` (a range) from `1.0.0-alpha` (a prerelease).

    The feed contains both shapes and a hyphen means different things in each.
    The test that separates them: what follows the hyphen is an upper bound only
    if it is itself a dotted numeric version with at least one dot. `alpha`,
    `rc.1` and `security` all fail that; `1.0.32` passes.
    """
    head, separator, tail = text.partition("-")
    if not separator:
        return None
    tail = tail.rstrip("+")
    if not _NUMERIC_RE.match(head) or not _NUMERIC_RE.match(tail):
        return None
    if "." not in tail:
        return None
    return head, tail


def parse(spec: str) -> list[Constraint]:
    """Parse one RADAR `version` string into constraints, or raise.

    A comma list becomes several constraints; a match against any one of them
    is a match. Raises UnparseableVersion on anything not recognised, so the
    caller reports rather than guesses.
    """
    text = normalize(spec)
    if not text:
        raise UnparseableVersion("empty version string")

    if "," in text:
        clauses = [c.strip() for c in text.split(",") if c.strip()]
        out: list[Constraint] = []
        for clause in clauses:
            out.extend(parse(clause))
        return out

    spaced = _SPACED_RANGE_RE.match(text)
    if spaced:
        low, high = normalize(spaced.group(1)), normalize(spaced.group(2))
        open_ended = high.endswith("+")
        high = high.rstrip("+")
        if not (_NUMERIC_RE.match(low) and _NUMERIC_RE.match(high)):
            raise UnparseableVersion(f"range bounds are not versions: {spec!r}")
        return [Constraint("range", low=low, high=None if open_ended else high)]

    comparator = _COMPARATOR_RE.match(text)
    if comparator:
        op, value = comparator.group(1), normalize(comparator.group(2))
        if not is_version(value):
            raise UnparseableVersion(f"comparator bound is not a version: {spec!r}")
        kind = {"<": "lt", "<=": "lte", ">": "gt", ">=": "gte",
                "=": "exact", "==": "exact"}[op]
        return [Constraint(kind, value=value)]

    unspaced = _split_unspaced_range(text)
    if unspaced:
        low, high = unspaced
        return [Constraint("range", low=low, high=None if text.endswith("+") else high)]

    if is_version(text):
        return [Constraint("exact", value=text)]

    raise UnparseableVersion(f"unrecognised version syntax: {spec!r}")


def parse_affected(affected: dict) -> list[Constraint]:
    """Constraints from the schema's structured `affected` object.

    Preferred over `parse()` when present: it is the machine-comparable form the
    entry author wrote deliberately, where the `version` string is prose that
    happens to be parseable most of the time.
    """
    out: list[Constraint] = []
    for version in affected.get("versions") or []:
        out.append(Constraint("exact", value=version))
    for span in affected.get("ranges") or []:
        introduced = span.get("introduced")
        fixed = span.get("fixed")
        last = span.get("last_affected")
        if fixed and not last:
            # `fixed` is the first version that is NOT affected. Treating it as
            # the last affected version would flag a user who has already
            # upgraded to the fix — the one action the finding asked them to take.
            out.append(Constraint("range", low=introduced, high=fixed,
                                  high_exclusive=True))
        else:
            out.append(Constraint("range", low=introduced, high=last))
    return out


def constraints_for(indicator: dict) -> tuple[list[Constraint], str | None]:
    """Every constraint for one feed indicator, and any parse error.

    Returns ([], None) when the indicator pins nothing — meaning every version
    is affected. Returns ([], reason) when a version string was present but
    could not be understood, which the caller must surface rather than ignore.
    """
    affected = indicator.get("affected")
    if affected:
        parsed = parse_affected(affected)
        if parsed:
            return parsed, None

    spec = indicator.get("version")
    if not spec:
        return [], None
    try:
        return parse(spec), None
    except UnparseableVersion as error:
        return [], str(error)


def matches(indicator: dict, installed: str) -> tuple[bool, str | None]:
    """Does `installed` fall inside this indicator's affected versions?

    Returns (matched, uncertainty). An uncertainty string means the answer is a
    guess and the caller should say so — that is the whole contract of this
    module.
    """
    constraints, error = constraints_for(indicator)
    if error:
        return True, f"could not parse the affected versions ({error})"
    if not constraints:
        return True, None
    try:
        key(installed)
    except UnparseableVersion:
        return True, f"could not parse the installed version {installed!r}"
    return any(c.matches(installed) for c in constraints), None
