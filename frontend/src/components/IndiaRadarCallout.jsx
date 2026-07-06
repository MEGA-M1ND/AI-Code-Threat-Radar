import { MapPin } from 'lucide-react';
import { HOME_PAGE } from '@/constants/testIds';

/**
 * Compact, proportionate homepage callout — differentiation, not the
 * whole pitch. Deliberately short: 2-3 sentences plus a couple of stats.
 */
export default function IndiaRadarCallout() {
  return (
    <section
      data-testid={HOME_PAGE.indiaRadarSection}
      className="border border-white/10 bg-white/[0.03] rounded-sm p-6 sm:p-8"
    >
      <div className="flex items-start gap-3">
        <MapPin className="text-amber-500 mt-1 shrink-0" size={20} />
        <div>
          <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-2">
            India Radar
          </p>
          <p className="text-sm text-zinc-400 leading-relaxed max-w-3xl">
            India has one of the largest developer populations globally and
            among the fastest AI-coding-tool adoption rates worldwide —
            yet no dedicated public tracker currently covers this specific
            threat class for the region. This project keeps an explicit eye
            on that gap alongside the global feed.
          </p>
          <div className="flex flex-wrap gap-6 mt-4">
            <div>
              <p className="font-heading text-2xl font-bold text-zinc-100 tabular-nums">15M+</p>
              <p className="text-xs text-zinc-500">Est. active Indian developers</p>
            </div>
            <div>
              <p className="font-heading text-2xl font-bold text-zinc-100 tabular-nums">0</p>
              <p className="text-xs text-zinc-500">Dedicated public trackers, pre-2026</p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
