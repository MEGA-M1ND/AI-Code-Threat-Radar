import { ExternalLink, Github } from 'lucide-react';
import { VIBE_RADAR } from '@/constants/categories';
import { METHODOLOGY_PAGE } from '@/constants/testIds';

/**
 * Full "Related Projects" card used on the Methodology page. Framed as a
 * genuine, respectful cross-reference to complementary work, not a
 * disclaimer or hedge.
 */
export default function RelatedProjectsCard() {
  return (
    <div
      data-testid={METHODOLOGY_PAGE.relatedProjectsSection}
      className="border border-white/10 bg-white/[0.03] rounded-sm p-6 sm:p-8"
    >
      <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-3">
        Related Project
      </p>
      <h3 className="font-heading text-xl font-semibold text-zinc-100 mb-3">
        Georgia Tech SSLab — Vibe Security Radar
      </h3>
      <p className="text-sm text-zinc-400 leading-relaxed max-w-3xl">
        This project focuses on the AI agent supply chain — skills, MCP
        servers, and packages — not on cataloguing every CVE introduced by
        AI-generated code. For rigorous, academically-verified tracking of
        AI-linked CVEs, see Georgia Tech SSLab's{' '}
        <span className="text-zinc-200 font-medium">Vibe Security Radar</span>.
        Where our database includes agent-tool CVEs, we cite them as a
        source rather than duplicating their research.
      </p>
      <div className="flex flex-wrap gap-3 mt-5">
        <a
          href={VIBE_RADAR.url}
          target="_blank"
          rel="noopener noreferrer"
          data-testid={METHODOLOGY_PAGE.vibeRadarLink}
          className="inline-flex items-center gap-2 px-4 py-2 border border-sky-500/40 bg-sky-500/10 text-sky-300 rounded-sm text-sm hover:bg-sky-500/20 transition-colors"
        >
          Visit Vibe Security Radar <ExternalLink size={14} />
        </a>
        <a
          href={VIBE_RADAR.githubUrl}
          target="_blank"
          rel="noopener noreferrer"
          data-testid={METHODOLOGY_PAGE.vibeRadarGithubLink}
          className="inline-flex items-center gap-2 px-4 py-2 border border-white/15 text-zinc-300 rounded-sm text-sm hover:border-white/30 transition-colors"
        >
          <Github size={14} /> View source
        </a>
      </div>
    </div>
  );
}
