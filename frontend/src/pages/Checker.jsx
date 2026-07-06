import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, Sparkles, Trash2, Search, Lock } from 'lucide-react';
import { useFeed } from '@/context/FeedContext';
import Seo from '@/components/Seo';
import StatusBadge from '@/components/StatusBadge';
import FeedErrorState from '@/components/FeedErrorState';
import { Textarea } from '@/components/ui/textarea';
import { Button } from '@/components/ui/button';
import {
  Accordion,
  AccordionItem,
  AccordionTrigger,
  AccordionContent,
} from '@/components/ui/accordion';
import { analyzePaste, EXAMPLE_PASTE } from '@/lib/checker';
import { CHECKER_PAGE } from '@/constants/testIds';

const SEVERITY_COLOR = {
  high: '#ef4444',
  medium: '#f59e0b',
  low: '#71717a',
};

export default function Checker() {
  const { feed, error, refetch } = useFeed();
  const [text, setText] = useState('');
  const [result, setResult] = useState(null);

  const handleSubmit = () => {
    if (!text.trim() || !feed) return;
    setResult(analyzePaste(text, feed));
  };

  const handleClear = () => {
    setText('');
    setResult(null);
  };

  const handleLoadExample = () => {
    setText(EXAMPLE_PASTE);
    setResult(null);
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 py-10">
      <Seo
        title="Exposure Checker"
        description="Paste a package name, dependency list, package.json, agent skill file, or MCP config to check it against known AI agent supply-chain threats — entirely client-side."
      />

      <h1 className="font-heading text-3xl sm:text-4xl font-bold text-zinc-50 mb-2">
        Exposure Checker
      </h1>
      <p className="text-sm text-zinc-500 mb-6 max-w-2xl">
        Paste a package name, a dependency list, a package.json, an agent
        skill file, or an MCP config below.
      </p>

      <div className="space-y-2 mb-4">
        <p
          data-testid={CHECKER_PAGE.privacyNotice}
          className="flex items-center gap-2 text-sm text-emerald-400 font-mono"
        >
          <Lock size={14} /> Your paste never leaves your browser — nothing is uploaded, logged, or stored.
        </p>
        <p data-testid={CHECKER_PAGE.liteCheckNotice} className="text-xs text-zinc-500">
          This is a lite check against known indicators, not a full security audit.
        </p>
      </div>

      {error && <div className="mb-4"><FeedErrorState onRetry={refetch} /></div>}

      <Textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        placeholder="Paste package.json, a dependency list, an agent skill file, or an MCP config here..."
        data-testid={CHECKER_PAGE.textarea}
        className="min-h-[220px] font-mono text-sm bg-black/40 border-white/15 rounded-sm focus-visible:ring-red-500/40"
      />

      <div className="flex flex-wrap gap-3 mt-4">
        <Button
          onClick={handleSubmit}
          disabled={!text.trim() || !feed}
          data-testid={CHECKER_PAGE.submitBtn}
          className="rounded-sm bg-white text-black hover:bg-zinc-200 font-mono uppercase text-xs tracking-wider gap-2"
        >
          <Search size={14} /> Run check
        </Button>
        <Button
          variant="outline"
          onClick={handleLoadExample}
          data-testid={CHECKER_PAGE.loadExampleBtn}
          className="rounded-sm border-white/20 bg-transparent text-zinc-200 hover:bg-white/5 font-mono uppercase text-xs tracking-wider gap-2"
        >
          <Sparkles size={14} /> Load example
        </Button>
        {(text || result) && (
          <Button
            variant="ghost"
            onClick={handleClear}
            data-testid={CHECKER_PAGE.clearBtn}
            className="text-zinc-500 hover:text-zinc-200 font-mono uppercase text-xs tracking-wider gap-2"
          >
            <Trash2 size={14} /> Clear
          </Button>
        )}
      </div>

      {result && (
        <div className="mt-10 border border-white/10 bg-white/[0.02] rounded-sm p-5 sm:p-6">
          <p data-testid={CHECKER_PAGE.reportSummary} className="font-heading text-lg text-zinc-100 mb-4 flex items-center gap-2">
            <ShieldCheck size={18} className="text-emerald-400" />
            {result.knownMatches.length} known-threat match{result.knownMatches.length === 1 ? '' : 'es'}, {result.heuristicWarnings.length} heuristic warning{result.heuristicWarnings.length === 1 ? '' : 's'}
          </p>

          {result.knownMatches.length === 0 && result.heuristicWarnings.length === 0 && (
            <p data-testid={CHECKER_PAGE.noFindings} className="text-sm text-zinc-500">
              No known indicators or heuristic warnings found in this paste.
            </p>
          )}

          {result.knownMatches.length > 0 && (
            <div className="mb-6">
              <p className="font-mono text-[11px] uppercase tracking-wider text-red-400 mb-2">
                Known-threat matches
              </p>
              <Accordion type="multiple" className="border-none">
                {result.knownMatches.map((match, i) => (
                  <AccordionItem
                    key={match.indicator}
                    value={`match-${i}`}
                    data-testid={CHECKER_PAGE.knownMatchItem(i)}
                    className="border-white/10"
                  >
                    <AccordionTrigger className="text-sm text-zinc-200 hover:no-underline">
                      <span className="font-mono">{match.indicator}</span>
                    </AccordionTrigger>
                    <AccordionContent>
                      {match.entries.map((entry) => (
                        <div key={entry.id} className="flex items-center justify-between gap-3 py-1.5">
                          <Link to={`/database/${entry.id}`} className="text-sm text-sky-400 hover:text-sky-300">
                            {entry.title}
                          </Link>
                          <StatusBadge status={entry.status} />
                        </div>
                      ))}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </div>
          )}

          {result.heuristicWarnings.length > 0 && (
            <div>
              <p className="font-mono text-[11px] uppercase tracking-wider text-amber-400 mb-2">
                Heuristic warnings
              </p>
              <Accordion type="multiple" className="border-none">
                {result.heuristicWarnings.map((warn, i) => (
                  <AccordionItem
                    key={warn.id}
                    value={`warn-${i}`}
                    data-testid={CHECKER_PAGE.heuristicWarningItem(i)}
                    className="border-white/10"
                  >
                    <AccordionTrigger className="text-sm text-zinc-200 hover:no-underline">
                      <span className="flex items-center gap-2">
                        <span
                          className="w-1.5 h-1.5 rounded-full"
                          style={{ backgroundColor: SEVERITY_COLOR[warn.severity] }}
                        />
                        {warn.label} ({warn.count})
                      </span>
                    </AccordionTrigger>
                    <AccordionContent>
                      <ul className="space-y-1">
                        {warn.samples.map((s, si) => (
                          <li key={si} className="font-mono text-xs text-zinc-400 break-all">
                            {s}
                          </li>
                        ))}
                      </ul>
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
