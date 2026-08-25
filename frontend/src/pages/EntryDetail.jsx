import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ArrowLeft, FileText } from 'lucide-react';
import { useFeed } from '@/context/FeedContext';
import Seo from '@/components/Seo';
import StatusBadge from '@/components/StatusBadge';
import CategoryBadge from '@/components/CategoryBadge';
import SafeLink from '@/components/SafeLink';
import FeedErrorState from '@/components/FeedErrorState';
import { CATEGORY_LABELS, CATEGORY_HINTS, SEVERITY_COLORS, SEVERITY_LABELS,
         AFFECTED_TOOL_LABELS, INDICATOR_TYPE_LABELS } from '@/constants/categories';
import { indicatorLabel } from '@/lib/feed';
import { ENTRY_DETAIL } from '@/constants/testIds';

const FIELD_LABELS = {
  summary: 'Summary',
  severity_rationale: 'Why this severity',
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
      <Seo title={entry.title} description={entry.summary} />

      <Link
        to="/database"
        data-testid={ENTRY_DETAIL.backLink}
        className="inline-flex items-center gap-1.5 text-sm text-zinc-500 hover:text-zinc-200 mb-6"
      >
        <ArrowLeft size={14} /> Back to database
      </Link>

      <div className="flex flex-wrap items-center gap-2 mb-3">
        <CategoryBadge testId={ENTRY_DETAIL.typeBadge} label={CATEGORY_LABELS[entry.category] || entry.category} />
        <StatusBadge testId={ENTRY_DETAIL.statusBadge} status={entry.status} />
        {entry.severity && (
          <span
            className="font-mono text-[11px] uppercase tracking-wider px-2 py-0.5 rounded-sm border"
            style={{ color: SEVERITY_COLORS[entry.severity], borderColor: SEVERITY_COLORS[entry.severity] }}
          >
            {SEVERITY_LABELS[entry.severity] || entry.severity}
          </span>
        )}
      </div>

      <h1 data-testid={ENTRY_DETAIL.title} className="font-heading text-3xl sm:text-4xl font-bold text-zinc-50 leading-tight">
        {entry.title}
      </h1>

      <div className="flex flex-wrap gap-x-6 gap-y-1 mt-4 font-mono text-xs text-zinc-500">
        <span>ID: {entry.id}</span>
        {entry.affected_tools?.length > 0 && (
          <span>Affects: {entry.affected_tools.map((x) => AFFECTED_TOOL_LABELS[x] || x).join(', ')}</span>
        )}
        <span>First seen: {entry.first_seen || '—'}</span>
        {entry.last_updated && <span>Updated: {entry.last_updated}</span>}
      </div>

      <div className="mt-8 space-y-6">
        {['summary', 'severity_rationale'].map((field) =>
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
            <div className="flex flex-col gap-1.5">
              {entry.indicators.map((ind, i) => (
                <div key={i} className="flex items-baseline gap-2 flex-wrap">
                  <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-500 min-w-[5.5rem]">
                    {INDICATOR_TYPE_LABELS[ind.type] || ind.type}
                  </span>
                  <span className="font-mono text-xs px-2 py-1 border border-white/15 rounded-sm text-zinc-300 break-all">
                    {indicatorLabel(ind)}
                  </span>
                </div>
              ))}
            </div>
            {entry.category === 'platform-vuln' && (
              <p className="text-xs text-zinc-500 mt-2 max-w-prose">
                These name legitimate software that had a vulnerability. Match the version before treating one as malicious.
              </p>
            )}
          </div>
        )}

        {entry.related?.length > 0 && (
          <div>
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-2">Also tracked as</p>
            <div className="flex flex-wrap gap-2">
              {entry.related.map((rid) => (
                <span key={rid} className="font-mono text-xs px-2 py-1 bg-white/5 rounded-sm text-zinc-400">
                  {rid}
                </span>
              ))}
            </div>
          </div>
        )}

        {entry.sources?.length > 0 && (
          <div className="border border-white/15 bg-white/[0.03] rounded-sm p-5">
            <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <FileText size={13} /> Sources ({entry.sources.length})
            </p>
            <ol data-testid={ENTRY_DETAIL.referencesList} className="space-y-3 list-decimal list-inside">
              {entry.sources.map((src, i) => (
                <li key={i} className="text-sm">
                  <span
                    className={`font-mono text-[10px] uppercase tracking-wider mr-2 px-1.5 py-0.5 rounded-sm ${
                      src.type === 'primary'
                        ? 'text-emerald-300 border border-emerald-400/40'
                        : 'text-zinc-500 border border-white/10'
                    }`}
                  >
                    {src.type}
                  </span>
                  <span className="text-zinc-400">{src.publisher}</span>
                  <br />
                  <SafeLink
                    href={src.url}
                    testId={ENTRY_DETAIL.referenceItem(i)}
                    className="text-sky-400 hover:text-sky-300 break-all"
                  >
                    {src.url}
                  </SafeLink>
                </li>
              ))}
            </ol>
            <p className="text-xs text-zinc-500 mt-4">
              Every entry carries at least one primary source. See the sourcing standard in the methodology.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
