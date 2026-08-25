// Feed fetching + derived stats for RADAR.
// This is a thin proxy call to our own backend, which fetches the published
// release artifact and holds it briefly in memory. The shape here is the
// published feed shape — see docs/FEED.md.

import { SEVERITY_RANK } from '@/constants/categories';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

export async function fetchFeed() {
  const res = await fetch(`${API}/feed?t=${Date.now()}`, {
    cache: 'no-store',
  });
  if (!res.ok) {
    throw new Error(`Feed request failed with status ${res.status}`);
  }
  return res.json();
}

export function sortEntriesByDate(entries, field = 'first_seen') {
  return [...entries].sort((a, b) => {
    const da = a?.[field] || '';
    const db = b?.[field] || '';
    return db.localeCompare(da);
  });
}

export function sortEntriesBySeverity(entries) {
  return [...entries].sort((a, b) => {
    const ra = SEVERITY_RANK[a?.severity] ?? 99;
    const rb = SEVERITY_RANK[b?.severity] ?? 99;
    if (ra !== rb) return ra - rb;
    return (b?.first_seen || '').localeCompare(a?.first_seen || '');
  });
}

export function computeCategoryCounts(entries) {
  const counts = {};
  for (const entry of entries) {
    const cat = entry.category || 'uncategorized';
    counts[cat] = (counts[cat] || 0) + 1;
  }
  return counts;
}

export function computeSeverityCounts(entries) {
  const counts = {};
  for (const entry of entries) {
    const sev = entry.severity || 'unknown';
    counts[sev] = (counts[sev] || 0) + 1;
  }
  return counts;
}

export function computeHomeStats(feed) {
  const entries = feed?.entries || [];
  const counts = computeCategoryCounts(entries);
  const sorted = sortEntriesByDate(entries, 'first_seen');
  return {
    totalEntries: entries.length,
    // Severity is its own field now — this no longer piggybacks on status.
    criticalCount: entries.filter((e) => e.severity === 'critical').length,
    activeCount: entries.filter((e) => e.status === 'active').length,
    indicatorCount: entries.reduce((n, e) => n + (e.indicators?.length || 0), 0),
    mostRecentDate: sorted[0]?.first_seen || null,
    lastUpdated: feed?.last_updated || null,
    maliciousSkills: counts['malicious-skill'] || 0,
    mcpThreats: counts['malicious-mcp-server'] || 0,
    slopsquats: counts['slopsquat-package'] || 0,
    maliciousPackages: counts['malicious-package'] || 0,
    compromisedPackages: counts['compromised-package'] || 0,
    platformVulns: counts['platform-vuln'] || 0,
    vibeAppBreaches: counts['vibe-app-breach'] || 0,
  };
}

export function getUniqueValues(entries, field) {
  const set = new Set();
  for (const entry of entries) {
    const val = entry[field];
    if (Array.isArray(val)) {
      val.forEach((v) => v && set.add(v));
    } else if (val) {
      set.add(val);
    }
  }
  return Array.from(set).sort();
}

// Indicators are typed objects now. This is the one place that knows how to
// turn one into the string a human reads or a search matches against.
export function indicatorLabel(indicator) {
  if (!indicator) return '';
  switch (indicator.type) {
    case 'package':
      return indicator.version
        ? `${indicator.name} (${indicator.registry}) ${indicator.version}`
        : `${indicator.name} (${indicator.registry})`;
    case 'application':
      return indicator.version ? `${indicator.name} ${indicator.version}` : indicator.name;
    case 'mcp-server':
      return indicator.name || indicator.url || indicator.repo || '';
    case 'skill':
      return indicator.marketplace ? `${indicator.slug} (${indicator.marketplace})` : indicator.slug;
    case 'hash':
      return `${indicator.algo}:${indicator.value}`;
    case 'domain':
    case 'ip':
    case 'url':
      return indicator.value;
    default:
      return JSON.stringify(indicator);
  }
}

// The bare value a scanner would match on, without the decoration.
export function indicatorValue(indicator) {
  if (!indicator) return '';
  return (
    indicator.name || indicator.slug || indicator.value || indicator.url || indicator.repo || ''
  );
}

export function primarySource(entry) {
  const sources = entry?.sources || [];
  return sources.find((s) => s.type === 'primary') || sources[0] || null;
}
