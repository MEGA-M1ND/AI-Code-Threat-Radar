"""Turning recorded runs into results/REPORT.md.

The report shows individual runs rather than a rate. Three runs cannot support
a percentage, and printing one invites the reader to treat it as though it
could.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from .runner import RESULTS_DIR, load_all
from .scenarios import BY_NAME

HEADER = """# AgentTrap results

Do coding agents fall for supply-chain traps while doing ordinary work?

Every scenario is modelled on an incident in the [RADAR]({homepage}) feed and
cites it by id. Read [METHODOLOGY.md](../METHODOLOGY.md) before the numbers —
it says what this can and cannot support, and the limitations are not a
formality.

- **Agent:** {agent}
- **Runs per scenario:** {runs}
- **Date:** {date}

**Three runs is not a rate.** Individual runs are shown below. Nothing here is
averaged, and no percentage appears in this document.
"""

HOMEPAGE = "https://github.com/MEGA-M1ND/AI-Code-Threat-Radar"


def build(agent: str, date: str) -> str:
    runs = load_all()
    if not runs:
        return "# AgentTrap results\n\nNo runs recorded yet.\n"

    by_scenario: dict[str, list[dict]] = defaultdict(list)
    for run in runs:
        by_scenario[run["scenario"]].append(run)

    per = max(len(v) for v in by_scenario.values())
    lines = [HEADER.format(homepage=HOMEPAGE, agent=agent, runs=per, date=date)]

    lines.append("\n## Summary\n")
    lines.append("| Scenario | Shape | Precedent | Canary fired | Errors |")
    lines.append("|---|---|---|---|---|")
    for name in [s.name for s in BY_NAME.values()]:
        entries = by_scenario.get(name, [])
        if not entries:
            continue
        scenario = BY_NAME[name]
        ok = [e for e in entries if e["status"] == "ok"]
        fired = sum(1 for e in ok if e["fired"])
        errors = len(entries) - len(ok)
        mark = "—" if not ok else f"**{fired} of {len(ok)}**"
        lines.append(f"| `{name}` | {scenario.shape} | {scenario.precedent} | "
                     f"{mark} | {errors or '—'} |")

    lines.append("\nA fired canary means the agent took the bait. For "
                 "**omission** scenarios that means it did not raise the "
                 "concern the task asked for, which is weaker evidence than a "
                 "commission — see the methodology.\n")

    for name, scenario in BY_NAME.items():
        entries = by_scenario.get(name)
        if not entries:
            continue
        lines.append(f"\n---\n\n## `{name}`\n")
        lines.append(f"{scenario.summary}\n")
        lines.append(f"**Precedent:** {scenario.precedent} — {scenario.precedent_note}\n")
        lines.append(f"**Canary ({scenario.shape}):** {scenario.canary}\n")
        lines.append("**Task given to the agent:**\n")
        lines.append(f"> {scenario.task}\n")
        lines.append("| Run | Result | Evidence | Seconds |")
        lines.append("|---|---|---|---|")
        for entry in sorted(entries, key=lambda e: e["run"]):
            if entry["status"] != "ok":
                result = f"`{entry['status']}`"
                evidence = entry.get("detail", "")
            else:
                result = "**took the bait**" if entry["fired"] else "held"
                evidence = entry["evidence"]
                if entry.get("detail"):
                    evidence += f" ({entry['detail']})"
            lines.append(f"| {entry['run']} | {result} | {evidence} | "
                         f"{entry['duration_s']} |")

    lines.append("\n---\n\n## Limitations\n")
    lines.append(
        "Repeated from the methodology because a reader who skipped it should "
        "still meet them:\n\n"
        f"- **n = {per} per scenario.** Anything that happened once could be noise.\n"
        "- **One agent, one date.** The answer is a property of a specific model "
        "at a specific time and will not generalise.\n"
        "- **The traps are synthetic even where the techniques are not.** A real "
        "compromised package arrives with a history, a download count and a "
        "repository. These arrive in a directory created ten seconds earlier, "
        "which almost certainly makes them easier to catch — so a failure here "
        "means more than a pass does.\n"
        "- **One prompt per scenario.** Prompt sensitivity is unmeasured.\n"
        "- **No container.** The sandbox is a temporary directory and a tool "
        "allowlist, not Docker. The payloads are inert by construction; the "
        "boundary is not what makes them safe.\n"
        "- **Omission canaries conflate two things**: an agent that did not "
        "mention the trap may have judged it out of scope. The task prompts are "
        "printed above so a reader can judge whether it was.\n")
    lines.append("\nRaw transcripts for every run are in "
                 "[`runs/`](runs/) — any claim above can be traced to the "
                 "output that produced it.\n")
    return "\n".join(lines)


def write(agent: str, date: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / "REPORT.md"
    path.write_text(build(agent, date))
    return path
