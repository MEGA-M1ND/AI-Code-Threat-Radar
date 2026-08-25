import { Search, X, ArrowUpDown } from 'lucide-react';
import { Input } from '@/components/ui/input';
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuCheckboxItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
} from '@/components/ui/dropdown-menu';
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from '@/components/ui/select';
import { Button } from '@/components/ui/button';
import { DATABASE_PAGE } from '@/constants/testIds';
import { CATEGORY_LABELS } from '@/constants/categories';

function MultiSelectDropdown({ label, options, selected, onToggle, testId, renderLabel }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          data-testid={testId}
          className="rounded-sm border-white/15 bg-transparent text-zinc-300 hover:bg-white/5 hover:text-white font-mono text-xs h-9"
        >
          {label} {selected.length > 0 && `(${selected.length})`}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent className="bg-[#121214] border-white/10 text-zinc-200 rounded-sm max-h-72">
        <DropdownMenuLabel className="text-zinc-500 text-xs">{label}</DropdownMenuLabel>
        <DropdownMenuSeparator className="bg-white/10" />
        {options.map((opt) => (
          <DropdownMenuCheckboxItem
            key={opt}
            checked={selected.includes(opt)}
            onCheckedChange={() => onToggle(opt)}
            className="text-sm capitalize focus:bg-white/10"
          >
            {renderLabel ? renderLabel(opt) : opt}
          </DropdownMenuCheckboxItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export default function FilterBar({
  search,
  onSearchChange,
  types,
  selectedTypes,
  onToggleType,
  statuses,
  selectedStatus,
  onStatusChange,
  tools,
  selectedTool,
  onToolChange,
  severities,
  selectedSeverities,
  onToggleSeverity,
  sortField,
  onToggleSort,
  onClear,
  hasActiveFilters,
}) {
  return (
    <div className="flex flex-col gap-3">
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500" size={16} />
        <Input
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Search title, description, indicators..."
          data-testid={DATABASE_PAGE.searchInput}
          className="pl-9 rounded-sm border-white/15 bg-white/[0.03] focus-visible:ring-red-500/40 h-10"
        />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <MultiSelectDropdown
          label="Type"
          options={types}
          selected={selectedTypes}
          onToggle={onToggleType}
          testId={DATABASE_PAGE.typeFilter}
          renderLabel={(t) => CATEGORY_LABELS[t] || t}
        />

        <Select value={selectedStatus} onValueChange={onStatusChange}>
          <SelectTrigger
            data-testid={DATABASE_PAGE.statusFilter}
            className="w-auto min-w-[130px] rounded-sm border-white/15 bg-transparent text-zinc-300 font-mono text-xs h-9"
          >
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent className="bg-[#121214] border-white/10 text-zinc-200 rounded-sm">
            <SelectItem value="all">All statuses</SelectItem>
            {statuses.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={selectedTool} onValueChange={onToolChange}>
          <SelectTrigger
            data-testid={DATABASE_PAGE.ecosystemFilter}
            className="w-auto min-w-[140px] rounded-sm border-white/15 bg-transparent text-zinc-300 font-mono text-xs h-9"
          >
            <SelectValue placeholder="Tool" />
          </SelectTrigger>
          <SelectContent className="bg-[#121214] border-white/10 text-zinc-200 rounded-sm">
            <SelectItem value="all">All tools</SelectItem>
            {tools.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <MultiSelectDropdown
          label="Severity"
          options={severities}
          selected={selectedSeverities}
          onToggle={onToggleSeverity}
          testId={DATABASE_PAGE.tagsFilter}
        />

        <Button
          variant="outline"
          onClick={onToggleSort}
          data-testid={DATABASE_PAGE.sortToggle}
          className="rounded-sm border-white/15 bg-transparent text-zinc-300 hover:bg-white/5 hover:text-white font-mono text-xs h-9 gap-1.5"
        >
          <ArrowUpDown size={13} />
          {sortField === 'first_seen' ? 'Newest first' : 'Last updated'}
        </Button>

        {hasActiveFilters && (
          <Button
            variant="ghost"
            onClick={onClear}
            data-testid={DATABASE_PAGE.clearFilters}
            className="text-zinc-500 hover:text-zinc-200 h-9 gap-1 text-xs"
          >
            <X size={13} /> Clear
          </Button>
        )}
      </div>
    </div>
  );
}
