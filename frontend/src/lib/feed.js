// Feed fetching + derived stats for the AI Code Threat Radar.
// This is a thin proxy call to our own backend (zero database usage on the
// backend side — it just reads a static JSON file fresh on every request),
// which stands in for a future `RAW_FEED_URL` on raw.githubusercontent.com.

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

export function sortEntriesByDate(entries, field = 'date_disclosed') {
  return [...entries].sort((a, b) => {
    const da = a?.[field] || '';
    const db = b?.[field] || '';
    return db.localeCompare(da);
  });
}

export function computeCategoryCounts(entries) {
  const counts = {};
  for (const entry of entries) {
    const cat = entry._category || 'uncategorized';
    counts[cat] = (counts[cat] || 0) + 1;
  }
  return counts;
}

export function computeHomeStats(feed) {
  const entries = feed?.entries || [];
  const counts = computeCategoryCounts(entries);
  const criticalCount = entries.filter(
    (e) => e.status === 'confirmed'
  ).length;
  const sorted = sortEntriesByDate(entries, 'date_disclosed');
  const mostRecentDate = sorted[0]?.date_disclosed || null;
  return {
    totalEntries: entries.length,
    criticalCount,
    mostRecentDate,
    maliciousSkills: counts['malicious-skills'] || 0,
    mcpThreats: counts['mcp-threats'] || 0,
    slopsquatting: counts['slopsquatting'] || 0,
    platformVulns: counts['platform-vulns'] || 0,
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
