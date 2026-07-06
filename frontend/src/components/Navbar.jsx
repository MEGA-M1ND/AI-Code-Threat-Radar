import { useState } from 'react';
import { Link, NavLink } from 'react-router-dom';
import { Radar, Menu, X } from 'lucide-react';
import { NAV } from '@/constants/testIds';

const LINKS = [
  { to: '/', label: 'Home', testId: NAV.home },
  { to: '/database', label: 'Database', testId: NAV.database },
  { to: '/check', label: 'Exposure Checker', testId: NAV.checker },
  { to: '/methodology', label: 'Methodology', testId: NAV.methodology },
];

export default function Navbar() {
  const [open, setOpen] = useState(false);

  const linkClass = ({ isActive }) =>
    `px-3 py-2 text-sm font-mono uppercase tracking-wider transition-colors border-b-2 ${
      isActive
        ? 'text-zinc-50 border-red-500'
        : 'text-zinc-400 border-transparent hover:text-zinc-100 hover:border-white/20'
    }`;

  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-[#09090b]/95 backdrop-blur-sm">
      <nav className="max-w-7xl mx-auto flex items-center justify-between px-4 sm:px-6 h-16">
        <Link
          to="/"
          data-testid={NAV.logo}
          className="flex items-center gap-2 group"
        >
          <Radar className="text-red-500 group-hover:rotate-45 transition-transform duration-500" size={22} />
          <span className="font-heading font-bold text-lg tracking-tight text-zinc-50">
            AI Code Threat Radar
          </span>
        </Link>

        <div className="hidden md:flex items-center gap-1">
          {LINKS.map((l) => (
            <NavLink key={l.to} to={l.to} className={linkClass} data-testid={l.testId}>
              {l.label}
            </NavLink>
          ))}
        </div>

        <button
          className="md:hidden text-zinc-300"
          onClick={() => setOpen((o) => !o)}
          data-testid={NAV.mobileToggle}
          aria-label="Toggle navigation menu"
        >
          {open ? <X size={22} /> : <Menu size={22} />}
        </button>
      </nav>

      {open && (
        <div className="md:hidden border-t border-white/10 flex flex-col px-4 py-2">
          {LINKS.map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              onClick={() => setOpen(false)}
              className={({ isActive }) =>
                `py-3 text-sm font-mono uppercase tracking-wider border-b border-white/5 ${
                  isActive ? 'text-zinc-50' : 'text-zinc-400'
                }`
              }
              data-testid={`${l.testId}-mobile`}
            >
              {l.label}
            </NavLink>
          ))}
        </div>
      )}
    </header>
  );
}
