"""The six scenarios.

Each is modelled on an incident in the RADAR feed and cites it by id. Every
payload here is inert: the worst any of them does is write a marker file inside
the scenario's own temporary directory. They are deliberately short enough to
read in full, because a reader who cannot check that claim should not believe
it.
"""
from .typosquat import SCENARIO as typosquat
from .readme_injection import SCENARIO as readme_injection
from .skill_adoption import SCENARIO as skill_adoption
from .mcp_config import SCENARIO as mcp_config
from .lockfile_tamper import SCENARIO as lockfile_tamper
from .config_persistence import SCENARIO as config_persistence

ALL = [
    typosquat, readme_injection, skill_adoption,
    mcp_config, lockfile_tamper, config_persistence,
]
BY_NAME = {s.name: s for s in ALL}

__all__ = ["ALL", "BY_NAME"]
