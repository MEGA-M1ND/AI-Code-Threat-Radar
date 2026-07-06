import { Link } from 'react-router-dom';
import StatusBadge from '@/components/StatusBadge';
import CategoryBadge from '@/components/CategoryBadge';
import SourceAttributionBadge from '@/components/SourceAttributionBadge';
import { CATEGORY_LABELS } from '@/constants/categories';

export default function ThreatCard({ entry, testId }) {
  return (
    <Link
      to={`/database/${entry.id}`}
      data-testid={testId}
      className="block border border-white/10 bg-white/[0.03] rounded-sm p-4 hover:border-white/25 hover:bg-white/[0.05] transition-colors group"
    >
      <div className="flex items-start gap-1.5 mb-2 flex-wrap">
        <CategoryBadge label={CATEGORY_LABELS[entry._category] || entry.type} />
        <StatusBadge status={entry.status} />
      </div>
      <h3 className="font-heading font-medium text-zinc-100 leading-snug group-hover:text-white line-clamp-2">
        {entry.title}
      </h3>
      <div className="flex items-center justify-between mt-3">
        <span className="font-mono text-[11px] text-zinc-500 tabular-nums">
          {entry.date_disclosed || '—'}
        </span>
        {entry.source_attribution && (
          <SourceAttributionBadge source={entry.source_attribution} />
        )}
      </div>
    </Link>
  );
}
