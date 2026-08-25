"""What a scan reports.

A finding is not always "this is malware". It can be "this is a legitimate
package with an affected version", "this looks like a name someone squatted",
or "there is a hook here that runs code on every session and I cannot tell you
whether you put it there". Those need different words, so `kind` carries the
distinction and the CLI never flattens them into one alarm.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# What the finding is, which is not the same as how bad it is.
KINDS = (
    "malicious",     # the feed says this artifact is malicious
    "affected",      # legitimate artifact, version inside an affected range
    "near-miss",     # name resembles something legitimate; possibly a squat
    "hook",          # code configured to run automatically
    "uncertain",     # matched, but something could not be determined
)


@dataclass
class Finding:
    kind: str
    severity: str
    title: str
    detail: str
    location: str                 # file path, or a description of where
    artifact: str = ""            # package name, slug, server name
    installed_version: str = ""
    radar_id: str = ""
    source: str = ""
    remediation: str = ""
    uncertainty: str = ""         # set when the result is not certain
    line: int = 1

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"{self.kind!r} is not a finding kind: {KINDS}")
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"{self.severity!r} is not a severity")

    @property
    def rule_id(self) -> str:
        return f"radar/{self.kind}"

    def sort_key(self) -> tuple:
        return (SEVERITY_RANK[self.severity], self.kind, self.location,
                self.artifact, self.title)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    findings: list[Finding] = field(default_factory=list)
    scanned: dict[str, int] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)
    feed_origin: str = ""
    feed_last_updated: str = ""
    entry_count: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def note_scanned(self, what: str, count: int = 1) -> None:
        self.scanned[what] = self.scanned.get(what, 0) + count

    def sorted(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.sort_key)

    @property
    def worst(self) -> str | None:
        return self.sorted()[0].severity if self.findings else None

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for finding in self.findings:
            out[finding.severity] = out.get(finding.severity, 0) + 1
        return out
