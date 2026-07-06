import { isSafeExternalUrl } from '@/lib/links';

/**
 * Renders feed/user-derived reference strings as real links ONLY when they
 * begin with http:// or https://. Anything else renders as inert plain
 * text so nothing untrusted can ever become a javascript:/data: link.
 */
export default function SafeLink({ href, children, className = '', testId, ...rest }) {
  if (!isSafeExternalUrl(href)) {
    return <span className={className}>{children}</span>;
  }
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className={className}
      data-testid={testId}
      {...rest}
    >
      {children}
    </a>
  );
}
