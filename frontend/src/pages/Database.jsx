import { useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useFeed } from '@/context/FeedContext';
import Seo from '@/components/Seo';
import FilterBar from '@/components/FilterBar';
import StatusBadge from '@/components/StatusBadge';
import CategoryBadge from '@/components/CategoryBadge';
import SourceAttributionBadge from '@/components/SourceAttributionBadge';
import FeedErrorState from '@/components/FeedErrorState';
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from '@/components/ui/table';
import { getUniqueValues, sortEntriesByDate } from '@/lib/feed';
import { CATEGORY_ORDER, CATEGORY_LABELS, STATUS_ORDER } from '@/constants/categories';
import { DATABASE_PAGE } from '@/constants/testIds';

export default function Database() {
  const { feed, loading, error, refetch } = useFeed();
  const entries = useMemo(() => feed?.entries || [], [feed]);
  const navigate = useNavigate();

  const [search, setSearch] = useState('');
  const [selectedTypes, setSelectedTypes] = useState([]);
  const [selectedStatus, setSelectedStatus] = useState('all');
  const [selectedEcosystem, setSelectedEcosystem] = useState('all');
  const [selectedTags, setSelectedTags] = useState([]);
  const [sortField, setSortField] = useState('date_disclosed');

  const availableTypes = useMemo(
    () => CATEGORY_ORDER.filter((c) => entries.some((e) => e._category === c)),
    [entries]
  );
  const availableStatuses = useMemo(
    () => STATUS_ORDER.filter((s) => entries.some((e) => e.status === s)),
    [entries]
  );
  const availableEcosystems = useMemo(() => getUniqueValues(entries, 'ecosystem'), [entries]);
  const availableTags = useMemo(() => getUniqueValues(entries, 'tags'), [entries]);

  const toggle = (setter) => (value) =>
    setter((prev) => (prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]));

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    let result = entries.filter((e) => {
      if (selectedTypes.length && !selectedTypes.includes(e._category)) return false;
      if (selectedStatus !== 'all' && e.status !== selectedStatus) return false;
      if (selectedEcosystem !== 'all' && e.ecosystem !== selectedEcosystem) return false;
      if (selectedTags.length && !selectedTags.some((t) => (e.tags || []).includes(t))) return false;
      if (q) {
        const haystack = [
          e.title,
          e.description,
          ...(e.indicators || []),
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase();
        if (!haystack.includes(q)) return false;
      }
      return true;
    });
    return sortEntriesByDate(result, sortField);
  }, [entries, search, selectedTypes, selectedStatus, selectedEcosystem, selectedTags, sortField]);

  const hasActiveFilters =
    !!search || selectedTypes.length > 0 || selectedStatus !== 'all' || selectedEcosystem !== 'all' || selectedTags.length > 0;

  const clearFilters = () => {
    setSearch('');
    setSelectedTypes([]);
    setSelectedStatus('all');
    setSelectedEcosystem('all');
    setSelectedTags([]);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 py-10">
      <Seo
        title="Database"
        description="Browse every tracked threat in the AI agent supply chain: malicious skills, MCP threats, slopsquatted packages, platform vulnerabilities, incidents, and cited agent-tool CVEs."
      />

      <h1 className="font-heading text-3xl sm:text-4xl font-bold text-zinc-50 mb-2">Database</h1>
      <p className="text-sm text-zinc-500 mb-6 max-w-2xl">
        Every entry requires at least one public reference. Agent-tool CVEs
        are cited from Georgia Tech SSLab's Vibe Security Radar, not
        re-researched here.
      </p>

      <FilterBar
        search={search}
        onSearchChange={setSearch}
        types={availableTypes}
        selectedTypes={selectedTypes}
        onToggleType={toggle(setSelectedTypes)}
        statuses={availableStatuses}
        selectedStatus={selectedStatus}
        onStatusChange={setSelectedStatus}
        ecosystems={availableEcosystems}
        selectedEcosystem={selectedEcosystem}
        onEcosystemChange={setSelectedEcosystem}
        tags={availableTags}
        selectedTags={selectedTags}
        onToggleTag={toggle(setSelectedTags)}
        sortField={sortField}
        onToggleSort={() => setSortField((f) => (f === 'date_disclosed' ? 'last_updated' : 'date_disclosed'))}
        onClear={clearFilters}
        hasActiveFilters={hasActiveFilters}
      />

      <p
        data-testid={DATABASE_PAGE.resultsCount}
        className="font-mono text-xs text-zinc-500 mt-4 mb-3"
      >
        {loading ? 'Loading…' : `${filtered.length} of ${entries.length} entries`}
      </p>

      {error && <FeedErrorState onRetry={refetch} />}

      {!error && !loading && filtered.length === 0 && (
        <div data-testid={DATABASE_PAGE.emptyState} className="border border-white/10 rounded-sm p-10 text-center text-zinc-500">
          No entries match the current filters.
        </div>
      )}

      {!error && !loading && filtered.length > 0 && (
        <>
          <div className="hidden md:block border border-white/10 rounded-sm overflow-hidden">
            <Table>
              <TableHeader>
                <TableRow className="border-white/10 hover:bg-transparent">
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Title</TableHead>
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Category</TableHead>
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Status</TableHead>
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Ecosystem</TableHead>
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Disclosed</TableHead>
                  <TableHead className="text-zinc-500 font-mono text-[11px] uppercase tracking-wider">Source</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.map((entry) => (
                  <TableRow
                    key={entry.id}
                    data-testid={DATABASE_PAGE.entryRow(entry.id)}
                    className="border-white/5 hover:bg-white/[0.04] cursor-pointer"
                    onClick={() => navigate(`/database/${entry.id}`)}
                  >
                    <TableCell className="font-medium text-zinc-100 max-w-md">
                      <Link to={`/database/${entry.id}`} className="hover:underline">
                        {entry.title}
                      </Link>
                    </TableCell>
                    <TableCell><CategoryBadge label={CATEGORY_LABELS[entry._category] || entry._category} /></TableCell>
                    <TableCell><StatusBadge status={entry.status} /></TableCell>
                    <TableCell className="font-mono text-xs text-zinc-400">{entry.ecosystem || '—'}</TableCell>
                    <TableCell className="font-mono text-xs text-zinc-400 tabular-nums">{entry.date_disclosed || '—'}</TableCell>
                    <TableCell>
                      {entry.source_attribution ? (
                        <SourceAttributionBadge source={entry.source_attribution} />
                      ) : (
                        <span className="text-xs text-zinc-600">Original</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>

          <div className="md:hidden grid gap-3">
            {filtered.map((entry) => (
              <div key={entry.id} data-testid={DATABASE_PAGE.entryCard(entry.id)}>
                <Link
                  to={`/database/${entry.id}`}
                  className="block border border-white/10 bg-white/[0.03] rounded-sm p-4 hover:border-white/25 transition-colors"
                >
                  <div className="flex items-start gap-1.5 mb-2 flex-wrap">
                    <CategoryBadge label={CATEGORY_LABELS[entry._category] || entry._category} />
                    <StatusBadge status={entry.status} />
                  </div>
                  <h3 className="font-heading font-medium text-zinc-100 leading-snug">{entry.title}</h3>
                  <div className="flex items-center justify-between mt-3">
                    <span className="font-mono text-[11px] text-zinc-500 tabular-nums">{entry.date_disclosed || '—'}</span>
                    {entry.source_attribution && <SourceAttributionBadge source={entry.source_attribution} />}
                  </div>
                </Link>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
