import { useEffect } from 'react';

const SITE_NAME = 'AI Code Threat Radar';

function setMeta(name, content, attr = 'name') {
  if (!content) return;
  let el = document.head.querySelector(`meta[${attr}="${name}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute(attr, name);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

/**
 * Lightweight per-page SEO manager. Avoids pulling in react-helmet as an
 * extra dependency — just imperatively updates document.title and the
 * relevant meta/OG tags on mount / when props change.
 */
export default function Seo({ title, description }) {
  useEffect(() => {
    const fullTitle = title ? `${title} | ${SITE_NAME}` : SITE_NAME;
    document.title = fullTitle;
    setMeta('description', description);
    setMeta('og:title', fullTitle, 'property');
    setMeta('og:description', description, 'property');
    setMeta('twitter:card', 'summary_large_image');
    setMeta('twitter:title', fullTitle);
    setMeta('twitter:description', description);
  }, [title, description]);

  return null;
}
