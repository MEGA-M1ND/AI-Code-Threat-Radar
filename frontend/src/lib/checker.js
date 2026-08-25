// Client-side only exposure-checker logic for the AI Code Threat Radar.
// Everything here runs entirely in the browser. Nothing pasted by the user
// is ever sent to any server — no fetch/XHR calls happen in this module.

const TOKEN_REGEX = /(@[a-z0-9-][a-z0-9-._]*\/[a-z0-9-][a-z0-9-._]*|[a-z0-9][a-z0-9-._]{2,63}|https?:\/\/[^\s'"<>]+)/gi;

const HEURISTIC_PATTERNS = [
  {
    id: 'aws-key',
    label: 'Hardcoded AWS access key',
    severity: 'high',
    regex: /AKIA[0-9A-Z]{16}/g,
  },
  {
    id: 'private-key',
    label: 'Embedded private key header',
    severity: 'high',
    regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g,
  },
  {
    id: 'generic-secret',
    label: 'Hardcoded secret / token / password assignment',
    severity: 'medium',
    regex: /(api[_-]?key|secret|access[_-]?token|auth[_-]?token|password|passwd|pwd)\s*[:=]\s*['"]?[A-Za-z0-9/+_\-]{8,}['"]?/gi,
  },
  {
    id: 'curl-bash',
    label: 'curl | bash (or wget | sh) remote execution pattern',
    severity: 'high',
    regex: /(curl|wget)\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh)\b/gi,
  },
  {
    id: 'raw-ip-url',
    label: 'URL pointing to a raw IP address',
    severity: 'medium',
    regex: /https?:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?[^\s'"<>]*/g,
  },
  {
    id: 'non-https',
    label: 'Non-HTTPS URL',
    severity: 'low',
    regex: /http:\/\/(?!(\d{1,3}\.){3}\d{1,3})[^\s'"<>]+/g,
  },
];

export function extractTokens(text) {
  const matches = text.match(TOKEN_REGEX) || [];
  return Array.from(new Set(matches.map((m) => m.trim().toLowerCase())));
}

// Indicators are typed objects in the published feed, so the index is built
// here rather than shipped as a top-level map. Matching is exact on the
// indicator value: substring matching produced false positives on short names.
export function buildIndicatorIndex(feed) {
  const index = new Map();
  for (const entry of feed?.entries || []) {
    for (const ind of entry.indicators || []) {
      const value = ind.name || ind.slug || ind.value || ind.url || ind.repo;
      if (!value) continue;
      const key = String(value).toLowerCase();
      if (!index.has(key)) index.set(key, []);
      index.get(key).push({ entry, indicator: ind });
    }
  }
  return index;
}

export function matchIndicators(tokens, index) {
  const results = [];
  const seen = new Set();
  for (const token of tokens) {
    const hits = index.get(token);
    if (!hits || seen.has(token)) continue;
    seen.add(token);
    for (const { entry, indicator } of hits) {
      results.push({
        indicator: token,
        indicatorType: indicator.type,
        version: indicator.version || null,
        entry,
        severity: entry.severity,
        category: entry.category,
        // A platform-vuln indicator names legitimate software that had a
        // vulnerability. Flagging it as malicious would be wrong, and the
        // version range is what actually decides whether it matters.
        advisory: entry.category === 'platform-vuln',
      });
    }
  }
  return results;
}

export function runHeuristics(text) {
  const findings = [];
  for (const pattern of HEURISTIC_PATTERNS) {
    const matches = text.match(pattern.regex) || [];
    if (matches.length > 0) {
      findings.push({
        id: pattern.id,
        label: pattern.label,
        severity: pattern.severity,
        count: matches.length,
        samples: Array.from(new Set(matches)).slice(0, 5),
      });
    }
  }
  return findings;
}

export function analyzePaste(text, feed) {
  const index = buildIndicatorIndex(feed);
  const tokens = extractTokens(text);
  const knownMatches = matchIndicators(tokens, index);
  const heuristicWarnings = runHeuristics(text);
  return { knownMatches, heuristicWarnings };
}

export const EXAMPLE_PASTE = `{
  "name": "my-agent-project",
  "dependencies": {
    "claud-code": "0.2.1",
    "express": "^4.18.2"
  },
  "mcpServers": {
    "postmark": { "command": "npx", "args": ["postmark-mcp"] }
  },
  "config": {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "api_endpoint": "http://192.168.1.50/api",
    "setup_script": "curl http://install.example.com/setup.sh | bash"
  }
}`;
