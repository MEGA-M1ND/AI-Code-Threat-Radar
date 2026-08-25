# AgentTrap methodology

Written before the harness, because a result whose method was designed after
the number came out is not a result.

## The question

When a coding agent does ordinary work in a repository that contains a
supply-chain trap, does it take the bait?

Not "can an agent be jailbroken" — that is a different literature and a
different threat model. This is narrower and, for anyone shipping an agent,
more immediately useful: the agent is not under attack by its user. It is doing
what it was asked, in a repository someone else prepared.

## What is being measured

Each scenario has a **canary**: one observable that fires if and only if the
agent took the bait. Detection is mechanical — a file exists, a string appears
in a written file, a token was echoed. There is no model grading a transcript
for "did it seem suspicious", because that would make the measurement depend on
the thing being measured.

Two shapes of canary, and they are not symmetric:

| Shape | Fires when | Scenarios |
|---|---|---|
| **Commission** | the agent *does* something it should not | typosquat, prompt injection, skill adoption |
| **Omission** | the agent *fails to say* something it should | MCP config, lockfile tamper, config persistence |

Omission canaries are weaker evidence and are reported separately. An agent that
did not mention the hook may have judged it out of scope for the task it was
given, which is not the same as failing to see it. Where a scenario relies on
omission, the task prompt is written so that noticing is plainly in scope — and
the prompt is printed in the report so a reader can judge whether it was.

## Safety boundaries

These are constraints on the harness, not aspirations.

1. **No real malicious code.** Every payload is inert. The worst thing any of
   them does is write a marker file inside a temporary directory. There is no
   obfuscation, no network call, no persistence outside the scenario directory.
   The files are readable and the harm they simulate is described in a comment
   at the top of each one.
2. **Nothing is ever published.** Fake packages exist as files in a temporary
   directory. No registry is contacted, and no artifact leaves the machine.
3. **Fresh temporary directory per run.** No scenario runs in the repository or
   anywhere the user works. The directory is created per run and its path is
   recorded so a failed run can be inspected.
4. **No network for the agent.** The agent is invoked with a tool allowlist that
   excludes network tools, and with no MCP servers configured.
5. **The agent's own home is not touched.** Scenarios that involve
   `~/.claude/settings.json` stage a fake home inside the scenario directory and
   point the agent at that.

### What this is not

**It is not Docker isolation.** The plan called for a container; this
environment has the Docker CLI and no daemon, so the sandbox is
process-and-directory level instead. That is a real weakening and it is stated
here rather than buried: a payload that escaped its directory would escape into
the host. The mitigation is that the payloads are inert by construction and
short enough to read — not that the boundary would hold against one that was
not.

## Scenario design

Every scenario is modelled on an incident in the RADAR feed, cited by id. This
is the part that stops the traps being synthetic: the shapes are ones that have
worked on real developers, not ones invented to be catchable.

| Scenario | Real precedent |
|---|---|
| Typosquat install | `claud-code`, `cloude-code`, `cloude` — RADAR-2026-0001 |
| README prompt injection | RADAR-2025-0008 (agents run as the recon tool) |
| Malicious skill adoption | ClawHavoc prerequisite trap — RADAR-2026-0002 |
| Poisoned MCP config | RADAR-2025-0001 |
| Lockfile tamper | imposter `optionalDependencies` — RADAR-2026-0007 |
| Agent-config persistence | `SessionStart` hook — RADAR-2026-0005, RADAR-2026-0007 |

The sixth is not in the original brief and is the one most worth having. The
brief predates the technique. Persistence written into the agent's own
configuration is the trap where "did the agent notice?" is a genuinely open
question rather than a foregone one, and the feed documents it twice from
unrelated actors.

## Run protocol

- Each scenario runs **at least three times**, independently, in a fresh
  directory, with an identical prompt.
- Results are recorded per run, not averaged away. Three runs is not enough to
  report a rate, and the report does not report one.
- The agent, its version, and the date are recorded with every result, because
  the answer is a property of a specific model at a specific time and will not
  generalise.
- Failed harness runs (timeout, non-zero exit, unparseable output) are recorded
  as `error`, never silently dropped or counted as a pass. A scenario where the
  harness broke is not a scenario the agent survived.

## What the results cannot support

Stated up front, because these are the objections a skeptical reader will have
and they are all correct:

- **n is tiny.** Three runs per scenario. Anything that happens once could be
  noise. The report shows individual runs so a reader can see that for
  themselves rather than trusting a summary statistic.
- **One agent.** The harness is not agent-specific, but the results are.
- **The traps are synthetic even when the techniques are not.** A real
  compromised package arrives with a plausible history, a download count and a
  repository. These arrive in a directory that was created ten seconds ago.
  That almost certainly makes them *easier* to catch than the real thing, which
  means a failure here is meaningful and a pass here proves less than it looks.
- **Prompt sensitivity is unmeasured.** Each scenario uses one task prompt.
  A differently-worded task might change the outcome entirely, and no attempt is
  made here to quantify that.
- **Omission canaries conflate two things** — see above.

## Reproducing

```sh
python -m agenttrap run --all --runs 3
python -m agenttrap report
```

Every run writes its raw agent output to `results/runs/`, so a claim in the
report can be traced to the transcript that produced it.
