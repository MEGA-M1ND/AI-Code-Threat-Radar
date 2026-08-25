import { Link } from 'react-router-dom';
import StatusBadge from '@/components/StatusBadge';
import CategoryBadge from '@/components/CategoryBadge';
import { CATEGORY_LABELS, SEVERITY_COLORS, SEVERITY_LABELS } from '@/constants/categories';

export default function ThreatCard({ entry, testId }) {
  return (
    <Link
      to={`/database/${entry.id}`}
      data-testid={testId}
      className="block border border-white/10 bg-white/[0.03] rounded-sm p-4 hover:border-white/25 hover:bg-white/[0.05] transition-colors group"
    >
      <div className="flex items-start gap-1.5 mb-2 flex-wrap">
        <CategoryBadge label={CATEGORY_LABELS[entry.category] || entry.category} />
        <StatusBadge status={entry.status} />
      </div>
      <h3 className="font-heading font-medium text-zinc-100 leading-snug group-hover:text-white line-clamp-2">
        {entry.title}
      </h3>
      <div className="flex items-center justify-between mt-3">
        <span className="font-mono text-[11px] text-zinc-500 tabular-nums">
          {entry.first_seen || '—'}
        </span>
        {entry.severity && (
          <span
            className="font-mono text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded-sm"
            style={{ color: SEVERITY_COLORS[entry.severity], borderColor: SEVERITY_COLORS[entry.severity], borderWidth: 1 }}
          >
            {SEVERITY_LABELS[entry.severity] || entry.severity}
          </span>
        )}
      </div>
    </Link>
  );
}
