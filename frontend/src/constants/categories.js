// Category ordering & labels for the AI Code Threat Radar.
// Order matters: our owned categories come first, agent-tool-cves (the
// category we cite from Georgia Tech's Vibe Security Radar) comes last.

export const CATEGORY_ORDER = [
  'malicious-skills',
  'mcp-threats',
  'slopsquatting',
  'platform-vulns',
  'incidents',
  'agent-tool-cves',
];

export const CATEGORY_LABELS = {
  'malicious-skills': 'Malicious Skills',
  'mcp-threats': 'MCP Threats',
  'slopsquatting': 'Slopsquatting',
  'platform-vulns': 'Platform Vulnerabilities',
  'incidents': 'Incidents',
  'agent-tool-cves': 'Agent-Tool CVEs',
};

export const STATUS_ORDER = ['confirmed', 'reported', 'remediated', 'disputed'];

export const STATUS_LABELS = {
  confirmed: 'Confirmed',
  reported: 'Reported',
  remediated: 'Remediated',
  disputed: 'Disputed',
};

export const STATUS_COLORS = {
  confirmed: '#ef4444',
  reported: '#f59e0b',
  remediated: '#10b981',
  disputed: '#71717a',
};

export const VIBE_RADAR = {
  name: 'Vibe Security Radar (Georgia Tech SSLab)',
  url: 'https://vibe-radar-ten.vercel.app/',
  githubUrl: 'https://github.com/HQ1995/vibe-security-radar',
};

export const GITHUB_REPO_URL = 'https://github.com/ai-code-threat-radar/feed';
export const CONTRIBUTING_URL = `${GITHUB_REPO_URL}/blob/main/CONTRIBUTING.md`;
export const DISPUTES_URL = `${GITHUB_REPO_URL}/blob/main/DISPUTES.md`;
