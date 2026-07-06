export default function StatCard({ label, value, testId, accent = 'text-zinc-100' }) {
  return (
    <div
      data-testid={testId}
      className="border border-white/10 bg-white/[0.03] rounded-sm p-4 sm:p-5"
    >
      <p className={`font-heading text-3xl sm:text-4xl font-bold tabular-nums ${accent}`}>
        {value}
      </p>
      <p className="text-xs sm:text-sm text-zinc-500 mt-1">{label}</p>
    </div>
  );
}
