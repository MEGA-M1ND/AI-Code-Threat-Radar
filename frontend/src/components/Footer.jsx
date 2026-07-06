import { Link } from 'react-router-dom';
import { Github, ExternalLink } from 'lucide-react';
import { VIBE_RADAR, GITHUB_REPO_URL } from '@/constants/categories';
import { FOOTER } from '@/constants/testIds';

export default function Footer() {
  return (
    <footer className="border-t border-white/10 mt-24">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-10 grid gap-8 md:grid-cols-3">
        <div>
          <p className="font-heading font-bold text-zinc-100">AI Code Threat Radar</p>
          <p className="text-sm text-zinc-500 mt-2 leading-relaxed">
            Tracking threats in the AI agent supply chain — malicious skills,
            poisoned MCP servers, slopsquatted packages, and the platforms
            that ship them insecure by default.
          </p>
        </div>

        <div className="text-sm">
          <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-3">
            Navigate
          </p>
          <ul className="space-y-2 text-zinc-400">
            <li><Link to="/database" className="hover:text-zinc-100">Database</Link></li>
            <li><Link to="/check" className="hover:text-zinc-100">Exposure Checker</Link></li>
            <li><Link to="/methodology" className="hover:text-zinc-100">Methodology</Link></li>
            <li>
              <a
                href={GITHUB_REPO_URL}
                target="_blank"
                rel="noopener noreferrer"
                data-testid={FOOTER.githubLink}
                className="inline-flex items-center gap-1.5 hover:text-zinc-100"
              >
                <Github size={14} /> GitHub repo
              </a>
            </li>
          </ul>
        </div>

        <div className="text-sm" data-testid={FOOTER.relatedProjectsCompact}>
          <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500 mb-3">
            Related Project
          </p>
          <p className="text-zinc-500 leading-relaxed">
            We track the agent supply chain, not every AI-code CVE. For
            rigorous, academically-verified CVE tracking, see{' '}
            <a
              href={VIBE_RADAR.url}
              target="_blank"
              rel="noopener noreferrer"
              data-testid={FOOTER.vibeRadarLink}
              className="text-sky-400 hover:text-sky-300 inline-flex items-center gap-1"
            >
              Vibe Security Radar
              <ExternalLink size={11} />
            </a>{' '}
            (Georgia Tech SSLab).
          </p>
        </div>
      </div>
      <div className="border-t border-white/5 px-4 sm:px-6 py-4 text-center text-xs text-zinc-600 font-mono">
        Independent research project. No accounts, no tracking of pasted data, no backend database.
      </div>
    </footer>
  );
}
