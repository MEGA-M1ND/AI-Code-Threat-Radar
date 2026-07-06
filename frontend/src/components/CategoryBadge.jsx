export default function CategoryBadge({ label, testId }) {
  return (
    <span
      data-testid={testId}
      className="inline-flex items-center px-2 py-0.5 rounded-sm border border-white/15 text-zinc-300 font-mono text-[11px] uppercase tracking-wider whitespace-nowrap"
    >
      {label}
    </span>
  );
}
