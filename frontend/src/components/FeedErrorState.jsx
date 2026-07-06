import { AlertTriangle, Github } from 'lucide-react';
import { GITHUB_REPO_URL } from '@/constants/categories';
import { HOME_PAGE } from '@/constants/testIds';

export default function FeedErrorState({ onRetry }) {
  return (
    <div
      data-testid={HOME_PAGE.feedErrorBanner}
      className="border border-amber-500/30 bg-amber-500/[0.06] rounded-sm p-6 flex flex-col sm:flex-row items-start gap-4"
    >
      <AlertTriangle className="text-amber-500 shrink-0" size={22} />
      <div className="flex-1">
        <p className="font-heading font-semibold text-zinc-100">
          Feed temporarily unavailable
        </p>
        <p className="text-sm text-zinc-400 mt-1 leading-relaxed">
          We couldn't reach the live threat feed just now. This is usually
          transient — try again in a moment, or check the source data
          directly on GitHub.
        </p>
        <div className="flex gap-3 mt-3">
          {onRetry && (
            <button
              onClick={onRetry}
              className="px-3 py-1.5 border border-white/20 rounded-sm text-sm text-zinc-200 hover:border-white/40 transition-colors"
            >
              Retry
            </button>
          )}
          <a
            href={GITHUB_REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
            data-testid={HOME_PAGE.feedErrorGithubLink}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 border border-white/20 rounded-sm text-sm text-zinc-200 hover:border-white/40 transition-colors"
          >
            <Github size={14} /> View on GitHub
          </a>
        </div>
      </div>
    </div>
  );
}
