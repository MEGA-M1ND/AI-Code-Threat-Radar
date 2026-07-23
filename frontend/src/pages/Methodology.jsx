import { Github, ExternalLink } from 'lucide-react';
import Seo from '@/components/Seo';
import RelatedProjectsCard from '@/components/RelatedProjectsCard';
import StatusBadge from '@/components/StatusBadge';
import { STATUS_ORDER } from '@/constants/categories';
import { GITHUB_REPO_URL, CONTRIBUTING_URL, DISPUTES_URL } from '@/constants/categories';
import { METHODOLOGY_PAGE } from '@/constants/testIds';

const STATUS_DEFINITIONS = {
  confirmed: 'Independently verified with corroborating public evidence (code, disclosure, vendor advisory, or reputable reporting).',
  reported: 'Disclosed with at least one public reference but not yet independently corroborated by this project.',
  remediated: 'Confirmed at disclosure and subsequently fixed by the responsible vendor or maintainer.',
  disputed: 'The named party disputes malicious intent or accuracy; entry retained for transparency pending further evidence.',
};

export default function Methodology() {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-10">
      <Seo
        title="Methodology"
        description="What qualifies for the AI Code Threat Radar database, our evidence standard, status definitions, and the dispute process."
      />

      <h1 className="font-heading text-3xl sm:text-4xl font-bold text-zinc-50 mb-6">Methodology</h1>

      <section className="mb-10">
        <h2 className="font-heading text-xl font-semibold text-zinc-100 mb-2">What qualifies</h2>
        <p className="text-sm text-zinc-400 leading-relaxed">
          The database tracks threats specific to the AI coding agent supply
          chain: malicious agent skills, compromised or malicious MCP
          servers, slopsquatted or hallucination-targeted packages,
          vibe-coding-platform vulnerabilities, and incidents traceable to
          this supply chain. Every entry requires at least one public
          reference before it is added.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="font-heading text-xl font-semibold text-zinc-100 mb-2">Evidence standard &amp; inclusion</h2>
        <p className="text-sm text-zinc-400 leading-relaxed mb-3">
          Every entry is a real, publicly documented event and links to its
          primary sources — a vendor disclosure, security-vendor advisory,
          researcher write-up, official alert (e.g. CISA), or reputable
          reporting. Where possible we cite the original research alongside
          independent corroboration, and we record specific figures (token
          counts, download volumes, version numbers) only as stated by those
          sources.
        </p>
        <p className="text-sm text-zinc-400 leading-relaxed">
          We do not fabricate details. When a fact — a date, a statistic, a
          CVE identifier — cannot be confirmed against a source, it is left
          out or flagged rather than smoothed over. Where a disclosure only
          pins an event to a month, the entry says so. Research findings that
          aggregate many apps or packages (rather than a single vendor
          disclosure) are labelled as such.
        </p>
      </section>

      <section className="mb-10">
        <h2 className="font-heading text-xl font-semibold text-zinc-100 mb-3">Status definitions</h2>
        <div className="space-y-3">
          {STATUS_ORDER.map((status) => (
            <div key={status} className="flex items-start gap-3">
              <StatusBadge status={status} />
              <p className="text-sm text-zinc-400 leading-relaxed flex-1">
                {STATUS_DEFINITIONS[status]}
              </p>
            </div>
          ))}
        </div>
      </section>

      <section className="mb-10">
        <h2 className="font-heading text-xl font-semibold text-zinc-100 mb-2">Dispute process</h2>
        <p className="text-sm text-zinc-400 leading-relaxed mb-3">
          Disagree with an entry? Submissions and disputes go through
          GitHub — there are no comment forms or accounts on this site.
        </p>
        <div className="flex flex-wrap gap-3">
          <a
            href={CONTRIBUTING_URL}
            target="_blank"
            rel="noopener noreferrer"
            data-testid={METHODOLOGY_PAGE.contributingLink}
            className="inline-flex items-center gap-2 px-3 py-1.5 border border-white/15 rounded-sm text-sm text-zinc-300 hover:border-white/30"
          >
            CONTRIBUTING.md <ExternalLink size={13} />
          </a>
          <a
            href={DISPUTES_URL}
            target="_blank"
            rel="noopener noreferrer"
            data-testid={METHODOLOGY_PAGE.disputesLink}
            className="inline-flex items-center gap-2 px-3 py-1.5 border border-white/15 rounded-sm text-sm text-zinc-300 hover:border-white/30"
          >
            DISPUTES.md <ExternalLink size={13} />
          </a>
        </div>
      </section>

      <section className="mb-10">
        <RelatedProjectsCard />
      </section>

      <section className="border-t border-white/10 pt-8">
        <h2 className="font-heading text-xl font-semibold text-zinc-100 mb-2">Maintained by</h2>
        <p className="text-sm text-zinc-400 leading-relaxed mb-3">
          An independent security researcher. Data lives in the open on
          GitHub; there is no backend, database, or user accounts on this
          site.
        </p>
        <a
          href={GITHUB_REPO_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-3 py-1.5 border border-white/15 rounded-sm text-sm text-zinc-300 hover:border-white/30"
        >
          <Github size={14} /> View the feed repository
        </a>
      </section>
    </div>
  );
}
