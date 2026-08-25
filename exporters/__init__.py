"""Exporters — the feed rendered into what other tools can actually consume.

Every exporter is a pure function of the feed: same entries in, byte-identical
bytes out, no clock and no network. That is what lets a consumer diff two
releases and see only what changed in the data.
"""
from .radar_deny import build_radar_deny
from .hol_guard import build_hol_guard_bundle

EXPORTERS = {
    "radar-deny": build_radar_deny,
    "hol-guard-threat-intel": build_hol_guard_bundle,
}

__all__ = ["EXPORTERS", "build_radar_deny", "build_hol_guard_bundle"]
