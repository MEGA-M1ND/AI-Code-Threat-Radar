// URL safety helper for rendering feed/user-derived links.
// Only http:// and https:// links are ever rendered as clickable anchors —
// everything else renders as inert plain text.

export function isSafeExternalUrl(url) {
  if (typeof url !== 'string') return false;
  return /^https?:\/\//i.test(url.trim());
}
