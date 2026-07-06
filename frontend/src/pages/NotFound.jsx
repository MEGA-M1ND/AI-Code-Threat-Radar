import { Link } from 'react-router-dom';
import { Radar } from 'lucide-react';
import Seo from '@/components/Seo';

export default function NotFound() {
  return (
    <div className="max-w-3xl mx-auto px-4 sm:px-6 py-24 text-center">
      <Seo title="Page not found" description="This page does not exist." />
      <Radar className="mx-auto text-zinc-600 mb-4" size={40} />
      <p className="font-heading text-3xl font-bold text-zinc-100 mb-2">404 — Off the radar</p>
      <p className="text-sm text-zinc-500 mb-6">The page you're looking for doesn't exist.</p>
      <Link to="/" className="text-sm text-red-400 hover:text-red-300">
        ← Back to home
      </Link>
    </div>
  );
}
