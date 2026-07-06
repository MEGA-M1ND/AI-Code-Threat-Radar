// Test IDs for the AI Code Threat Radar app.
// Keys are camelCase, values are kebab-case `<feature>-<element>`.

export const NAV = {
  logo: 'nav-logo-link',
  home: 'nav-home-link',
  database: 'nav-database-link',
  checker: 'nav-checker-link',
  methodology: 'nav-methodology-link',
  mobileToggle: 'nav-mobile-toggle',
};

export const FOOTER = {
  githubLink: 'footer-github-link',
  relatedProjectsCompact: 'footer-related-projects-compact',
  vibeRadarLink: 'footer-vibe-radar-link',
};

export const HOME_PAGE = {
  hero3dCanvas: 'hero-3d-canvas',
  heroCheckCta: 'hero-check-exposure-cta',
  statMaliciousSkills: 'stat-malicious-skills',
  statMcpThreats: 'stat-mcp-threats',
  statSlopsquatting: 'stat-slopsquatting',
  statPlatformVulns: 'stat-platform-vulns',
  totalEntriesFootnote: 'total-entries-footnote',
  latestThreatsStrip: 'latest-threats-strip',
  latestThreatCard: (id) => `latest-threat-card-${id}`,
  indiaRadarSection: 'india-radar-section',
  feedErrorBanner: 'feed-error-banner',
  feedErrorGithubLink: 'feed-error-github-link',
};

export const DATABASE_PAGE = {
  searchInput: 'database-search-input',
  typeFilter: 'database-type-filter',
  statusFilter: 'database-status-filter',
  ecosystemFilter: 'database-ecosystem-filter',
  tagsFilter: 'database-tags-filter',
  sortToggle: 'database-sort-toggle',
  clearFilters: 'database-clear-filters',
  resultsCount: 'database-results-count',
  entryRow: (id) => `database-entry-row-${id}`,
  entryCard: (id) => `database-entry-card-${id}`,
  emptyState: 'database-empty-state',
};

export const ENTRY_DETAIL = {
  backLink: 'entry-detail-back-link',
  title: 'entry-detail-title',
  statusBadge: 'entry-detail-status-badge',
  typeBadge: 'entry-detail-type-badge',
  sourceAttribution: 'entry-detail-source-attribution',
  referencesList: 'entry-detail-references-list',
  referenceItem: (i) => `entry-detail-reference-${i}`,
  notFound: 'entry-detail-not-found',
};

export const CHECKER_PAGE = {
  textarea: 'checker-textarea',
  loadExampleBtn: 'checker-load-example-btn',
  submitBtn: 'checker-submit-btn',
  clearBtn: 'checker-clear-btn',
  privacyNotice: 'checker-privacy-notice',
  liteCheckNotice: 'checker-lite-check-notice',
  reportSummary: 'checker-report-summary',
  knownMatchItem: (i) => `checker-known-match-${i}`,
  heuristicWarningItem: (i) => `checker-heuristic-warning-${i}`,
  noFindings: 'checker-no-findings',
};

export const METHODOLOGY_PAGE = {
  relatedProjectsSection: 'methodology-related-projects-section',
  vibeRadarLink: 'methodology-vibe-radar-link',
  vibeRadarGithubLink: 'methodology-vibe-radar-github-link',
  contributingLink: 'methodology-contributing-link',
  disputesLink: 'methodology-disputes-link',
};
