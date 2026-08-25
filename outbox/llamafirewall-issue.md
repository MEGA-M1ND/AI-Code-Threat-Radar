**To:** github.com/meta-llama/PurpleLlama · issue
**Title:** RegexScanner: allow patterns to be supplied to the constructor

---

The LlamaFirewall docs describe "customizable regex filters" as one of the
layered defences. Reading `scanners/regex_scanner.py`, `RegexScanner.__init__`
takes `scanner_name` and `block_threshold`, and compiles the module-level
`DEFAULT_REGEX_PATTERNS` dict. There's no parameter for supplying patterns and
no loader for an external rule file, so customising today means subclassing or
mutating the module global.

Proposal — one optional argument:

```python
def __init__(self, scanner_name="Regex Scanner", block_threshold=1.0,
             patterns: Dict[str, str] | None = None) -> None:
    ...
    for name, pattern in (patterns or DEFAULT_REGEX_PATTERNS).items():
```

Backwards compatible, and it makes the documented extensibility real.

My interest is concrete but small, and I'd rather say so than overstate it. I
maintain RADAR, a CC BY 4.0 feed of supply-chain incidents in the AI coding
agent ecosystem — 38 entries, 605 indicators, each from a primary source that
was read. Most of it is package names and skill slugs, which don't belong in a
message scanner. The part that does is the network indicators: 21 domains, IPs
and URLs that appear in exfiltration paths, which are the kind of string that
turns up in tool output an agent is about to act on.

That's a small pattern set and I'm not proposing you take a dependency on it.
The constructor argument is useful on its own merits — anyone with a
domain-specific pattern list hits the same wall. Glad to send the PR if you'd
take it.

Feed: https://github.com/MEGA-M1ND/AI-Code-Threat-Radar
