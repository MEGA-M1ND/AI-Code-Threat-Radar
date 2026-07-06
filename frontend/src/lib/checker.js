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

export function matchIndicators(tokens, indicatorIndex, entriesById) {
  const results = [];
  const seenIndicators = new Set();
  for (const token of tokens) {
    for (const indicator of Object.keys(indicatorIndex || {})) {
      if (seenIndicators.has(indicator)) continue;
      if (token === indicator.toLowerCase() || token.includes(indicator.toLowerCase())) {
        seenIndicators.add(indicator);
        const entryIds = indicatorIndex[indicator] || [];
        const entries = entryIds
          .map((id) => entriesById[id])
          .filter(Boolean);
        results.push({ indicator, entries });
      }
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
  const indicatorIndex = feed?.indicator_index || {};
  const entriesById = Object.fromEntries(
    (feed?.entries || []).map((e) => [e.id, e])
  );
  const tokens = extractTokens(text);
  const knownMatches = matchIndicators(tokens, indicatorIndex, entriesById);
  const heuristicWarnings = runHeuristics(text);
  return { knownMatches, heuristicWarnings };
}

export const EXAMPLE_PASTE = `{
  "name": "my-agent-project",
  "dependencies": {
    "react-codeshift": "^2.1.0",
    "express": "^4.18.2"
  },
  "config": {
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "api_endpoint": "http://192.168.1.50/api",
    "setup_script": "curl http://install.example.com/setup.sh | bash"
  }
}`;
