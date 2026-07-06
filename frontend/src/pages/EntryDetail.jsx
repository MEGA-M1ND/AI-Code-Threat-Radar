import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, FileText } from 'lucide-react';
import { useFeed } from '@/context/FeedContext';
import Seo from '@/components/Seo';
import StatusBadge from '@/components/StatusBadge';
import CategoryBadge from '@/components/CategoryBadge';
import SourceAttributionBadge from '@/components/SourceAttributionBadge';
import SafeLink from '@/components/SafeLink';
import FeedErrorState from '@/components/FeedErrorState';
import { CATEGORY_LABELS } from '@/constants/categories';
import { ENTRY_DETAIL } from '@/constants/testIds';

const FIELD_LABELS = {
  description: 'Description',
  impact: 'Impact',
  root_cause: 'Root Cause',
  notes: 'Notes',
};

export default function EntryDetail() {
  const { id } = useParams();
  const { feed, loading, error, refetch } = useFeed();

  const entry = useMemo(
    () => (feed?.entries || []).find((e) => e.id === id),
    [feed, id]
  );

  if (loading) {
    return <div className="max-w-4xl mx-auto px-4 sm:px-6 py-16 text-zinc-500">Loading entry…</div>;
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto px-4 sm:px-6 py-16">
        <FeedErrorState onRetry={refetch} />
      </div>
    );
  }

  if (!entry) {
    return (
      <div data-testid={ENTRY_DETAIL.notFound} className="max-w-4xl mx-auto px-4 sm:px-6 py-24 text-center">
        <p className="font-heading text-2xl text-zinc-200 mb-3">Entry not found</p>
        <p className="text-sm text-zinc-500 mb-6">
          This entry may have been removed, or the ID in the URL is incorrect.
        </p>
        <Link to="/database" className="text-sm text-red-400 hover:text-red-300">
          ← Back to database
        </Link>
      </div>
    );
  }

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10">
      <Seo title={entry.title} description={entry.description} />

      <Link
        to="/database"
        data-testid={ENTRY_DETAIL.backLink}
        className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-200 mb-6"
      >
        <ArrowLeft size={14} /> Back to database
      </Link>

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <CategoryBadge testId={ENTRY_DETAIL.typeBadge} label={CATEGORY_LABELS[entry._category] || entry._category} />
        <StatusBadge testId={ENTRY_DETAIL.statusBadge} status={entry.status} />
        {entry.source_attribution && (
          <SourceAttributionBadge testId={ENTRY_DETAIL.sourceAttribution} source={entry.source_attribution} />
        )}
      </div>

      <h1 data-testid={ENTRY_DETAIL.title} className="font-heading text-3xl sm:text-4xl font-bold text-zinc-50 leading-tight">
        {entry.title}
      </h1>

      <div className="flex flex-wrap gap-x-6 gap-y-1 mt-4 font-mono text-xs text-zinc-500">
        <span>ID: {entry.id}</span>
        {entry.type && <span>Type: {entry.type}</span>}
        {entry.ecosystem && <span>Ecosystem: {entry.ecosystem}</span>}
        {entry.cve && <span>CVE: {entry.cve}</span>}
        <span>Disclosed: {entry.date_disclosed || '—'}</span>
        {entry.last_updated && <span>Updated: {entry.last_updated}</span>}
      </div>

      <div className="mt-8 space-y-6">
        {['description', 'impact', 'root_cause', 'notes'].map((field) =>
          entry[field] ? (
            <div key={field}>
              <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-1.5">
                {FIELD_LABELS[field]}
              </p>
              <p className="text-sm text-zinc-300 leading-relaxed">{entry[field]}</p>
            </div>
          ) : null
        )}

        {entry.indicators?.length > 0 && (
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Indicators</p>
            <div className="flex flex-wrap gap-2">
              {entry.indicators.map((ind) => (
                <span key={ind} className="font-mono text-xs px-2 py-1 border border-white/15 rounded-sm text-zinc-300">
                  {ind}
                </span>
              ))}
            </div>
          </div>
        )}

        {entry.tags?.length > 0 && (
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Tags</p>
            <div className="flex flex-wrap gap-2">
              {entry.tags.map((tag) => (
                <span key={tag} className="text-xs px-2 py-1 bg-white/5 rounded-sm text-zinc-400">
                  #{tag}
                </span>
              ))}
            </div>
          </div>
        )}

        {entry.references?.length > 0 && (
          <div className="border border-white/15 bg-white/[0.03] rounded-sm p-5">
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <FileText size={13} /> Sources ({entry.references.length})
            </p>
            <ol data-testid={ENTRY_DETAIL.referencesList} className="space-y-2 list-decimal list-inside">
              {entry.references.map((ref, i) => (
                <li key={i} className="text-sm">
                  <SafeLink
                    href={ref}
                    testId={ENTRY_DETAIL.referenceItem(i)}
                    className="text-sky-400 hover:text-sky-300 break-all"
                  >
                    {ref}
                  </SafeLink>
                </li>
              ))}
            </ol>
          </div>
        )}
      </div>
    </div>
  );
}
