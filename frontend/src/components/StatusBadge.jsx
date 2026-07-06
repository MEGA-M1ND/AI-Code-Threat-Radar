import { STATUS_COLORS, STATUS_LABELS } from '@/constants/categories';

export default function StatusBadge({ status, testId }) {
  const color = STATUS_COLORS[status] || '#71717a';
  const label = STATUS_LABELS[status] || status;
  return (
    <span
      data-testid={testId}
      className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-sm border font-mono text-[11px] uppercase tracking-wider whitespace-nowrap"
      style={{
        color,
        borderColor: `${color}66`,
        backgroundColor: `${color}1a`,
      }}
    >
      <span
        className="w-1.5 h-1.5 rounded-full"
        style={{ backgroundColor: color }}
      />
      {label}
    </span>
  );
}
