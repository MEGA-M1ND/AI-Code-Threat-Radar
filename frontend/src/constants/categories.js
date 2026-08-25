// Category, status and severity vocabulary for the RADAR feed.
// These values mirror schema/entry.schema.json — when the schema gains a value,
// it has to be added here or the UI falls back to the raw string.

// RADAR's own lanes come first; platform-vuln is last because it is the lane
// shared with Georgia Tech's Vibe Security Radar.
export const CATEGORY_ORDER = [
  'malicious-skill',
  'malicious-mcp-server',
  'slopsquat-package',
  'malicious-package',
  'compromised-package',
  'vibe-app-breach',
  'platform-vuln',
];

export const CATEGORY_LABELS = {
  'malicious-skill': 'Malicious Skill',
  'malicious-mcp-server': 'Malicious MCP Server',
  'slopsquat-package': 'Slopsquat',
  'malicious-package': 'Malicious Package',
  'compromised-package': 'Compromised Package',
  'vibe-app-breach': 'Vibe-App Breach',
  'platform-vuln': 'Platform Vulnerability',
};

// Short gloss shown on the database page so the distinction between the two
// package categories is visible without opening the methodology.
export const CATEGORY_HINTS = {
  'malicious-skill': 'An agent skill built to harm whoever installs it.',
  'malicious-mcp-server': 'An MCP server malicious as published, or taken over and republished.',
  'slopsquat-package': 'A name chosen to be mistaken for a real one.',
  'malicious-package': 'Malicious from its first version — block the name.',
  'compromised-package': 'Was trustworthy, later shipped malware — only some versions.',
  'vibe-app-breach': 'A breach traceable to how the app was generated.',
  'platform-vuln': 'A flaw in the agent tooling itself.',
};

export const STATUS_ORDER = ['active', 'remediated', 'disputed'];

export const STATUS_LABELS = {
  active: 'Active',
  remediated: 'Remediated',
  disputed: 'Disputed',
};

export const STATUS_COLORS = {
  active: '#ef4444',
  remediated: '#10b981',
  disputed: '#a1a1aa',
};

// Severity is the primary ranking signal in the new feed.
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'];

export const SEVERITY_LABELS = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#64748b',
};

export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

export const AFFECTED_TOOL_LABELS = {
  'claude-code': 'Claude Code',
  cursor: 'Cursor',
  'codex-cli': 'Codex CLI',
  'gemini-cli': 'Gemini CLI',
  copilot: 'Copilot',
  'generic-mcp': 'Generic MCP',
  other: 'Other',
};

export const INDICATOR_TYPE_LABELS = {
  package: 'Package',
  application: 'Application',
  'mcp-server': 'MCP Server',
  skill: 'Skill',
  hash: 'Hash',
  domain: 'Domain',
  ip: 'IP',
  url: 'URL',
};

export const VIBE_RADAR = {
  name: 'Vibe Security Radar (Georgia Tech SSLab)',
  url: 'https://vibe-radar-ten.vercel.app/',
  githubUrl: 'https://github.com/HQ1995/vibe-security-radar',
};

export const GITHUB_REPO_URL = 'https://github.com/MEGA-M1ND/AI-Code-Threat-Radar';
export const CONTRIBUTING_URL = `${GITHUB_REPO_URL}/blob/main/CONTRIBUTING.md`;
export const DISPUTES_URL = `${GITHUB_REPO_URL}/blob/main/docs/METHODOLOGY.md#dispute-process`;
export const FEED_DOCS_URL = `${GITHUB_REPO_URL}/blob/main/docs/FEED.md`;
export const FEED_DOWNLOAD_URL = `${GITHUB_REPO_URL}/releases/latest/download/feed.json`;
