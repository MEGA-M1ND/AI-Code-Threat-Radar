import { ExternalLink, ShieldCheck } from 'lucide-react';
import { VIBE_RADAR } from '@/constants/categories';

/**
 * Distinct visual badge for entries sourced from Georgia Tech SSLab's
 * Vibe Security Radar (the `agent-tool-cves` category). This is the ONLY
 * category that carries this badge — original curation (skills, MCP,
 * slopsquatting, platforms, incidents) never does.
 */
export default function SourceAttributionBadge({ source, testId }) {
  if (!source) return null;
  const url = source.url || VIBE_RADAR.url;
  const name = source.name || VIBE_RADAR.name;
  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      data-testid={testId}
      className="inline-flex items-center gap-1.5 px-2 py-1 rounded-sm border border-sky-500/40 bg-sky-500/10 text-sky-300 font-mono text-[11px] uppercase tracking-wider hover:bg-sky-500/20 transition-colors"
    >
      <ShieldCheck size={12} />
      Sourced via {name}
      <ExternalLink size={11} />
    </a>
  );
}
