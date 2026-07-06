import { Link } from 'react-router-dom';
import { ShieldAlert, Radar as RadarIcon } from 'lucide-react';
import { useFeed } from '@/context/FeedContext';
import Seo from '@/components/Seo';
import HeroRadar3D from '@/components/HeroRadar3D';
import StatCard from '@/components/StatCard';
import ThreatCard from '@/components/ThreatCard';
import IndiaRadarCallout from '@/components/IndiaRadarCallout';
import FeedErrorState from '@/components/FeedErrorState';
import { Button } from '@/components/ui/button';
import { computeHomeStats, sortEntriesByDate } from '@/lib/feed';
import { HOME_PAGE } from '@/constants/testIds';

export default function Home() {
  const { feed, loading, error, refetch } = useFeed();

  const stats = feed ? computeHomeStats(feed) : null;
  const latest = feed ? sortEntriesByDate(feed.entries || []).slice(0, 5) : [];

  return (
    <div>
      <Seo
        title="Home"
        description="Tracking threats in the AI agent supply chain — malicious skills, poisoned MCP servers, slopsquatted packages, and the platforms that ship them insecure by default."
      />

      <section className="relative overflow-hidden border-b border-white/10">
        <div className="absolute inset-0 opacity-70">
          <HeroRadar3D />
        </div>
        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 py-20 sm:py-28">
          <div className="max-w-2xl animate-fade-up">
            <span className="inline-flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.2em] text-red-400 mb-4">
              <RadarIcon size={13} /> Live Threat Intelligence
            </span>
            <h1 className="font-heading text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-zinc-50 leading-[1.05]">
              Tracking threats in the<br />AI agent supply chain
            </h1>
            <p className="mt-5 text-base sm:text-lg text-zinc-400 leading-relaxed max-w-xl">
              Malicious skills, poisoned MCP servers, slopsquatted packages,
              and the platforms that ship them insecure by default — indexed,
              verified, and public.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button
                asChild
                size="lg"
                data-testid={HOME_PAGE.heroCheckCta}
                className="rounded-sm bg-white text-black hover:bg-zinc-200 font-mono uppercase text-xs tracking-wider gap-2"
              >
                <Link to="/check">
                  <ShieldAlert size={16} /> Check your exposure
                </Link>
              </Button>
              <Button
                asChild
                variant="outline"
                size="lg"
                className="rounded-sm border-white/20 bg-transparent text-zinc-200 hover:bg-white/5 font-mono uppercase text-xs tracking-wider"
              >
                <Link to="/database">Browse the database</Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 space-y-14">
        {error && <FeedErrorState onRetry={refetch} />}

        {!error && (
          <section>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <StatCard
                testId={HOME_PAGE.statMaliciousSkills}
                label="Malicious skills tracked"
                value={loading ? '—' : stats.maliciousSkills}
                accent="text-red-400"
              />
              <StatCard
                testId={HOME_PAGE.statMcpThreats}
                label="MCP threats tracked"
                value={loading ? '—' : stats.mcpThreats}
                accent="text-amber-400"
              />
              <StatCard
                testId={HOME_PAGE.statSlopsquatting}
                label="Slopsquatted packages tracked"
                value={loading ? '—' : stats.slopsquatting}
                accent="text-red-400"
              />
              <StatCard
                testId={HOME_PAGE.statPlatformVulns}
                label="Platform vulnerabilities tracked"
                value={loading ? '—' : stats.platformVulns}
                accent="text-amber-400"
              />
            </div>
            <p
              data-testid={HOME_PAGE.totalEntriesFootnote}
              className="mt-3 font-mono text-xs text-zinc-500"
            >
              {loading
                ? 'Loading feed…'
                : `${stats.totalEntries} entries total · most recent disclosure ${stats.mostRecentDate || 'n/a'} · updated live from the feed`}
            </p>
          </section>
        )}

        {!error && (
          <section data-testid={HOME_PAGE.latestThreatsStrip}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="font-heading text-2xl sm:text-3xl font-semibold text-zinc-100">
                Latest threats
              </h2>
              <Link to="/database" className="text-sm text-zinc-400 hover:text-zinc-100 font-mono">
                View all →
              </Link>
            </div>
            {loading ? (
              <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {[...Array(5)].map((_, i) => (
                  <div key={i} className="h-32 border border-white/10 bg-white/[0.02] rounded-sm animate-pulse" />
                ))}
              </div>
            ) : (
              <div className="grid sm:grid-cols-2 lg:grid-cols-5 gap-3">
                {latest.map((entry) => (
                  <ThreatCard
                    key={entry.id}
                    entry={entry}
                    testId={HOME_PAGE.latestThreatCard(entry.id)}
                  />
                ))}
              </div>
            )}
          </section>
        )}

        <IndiaRadarCallout />
      </div>
    </div>
  );
}
