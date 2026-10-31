import { useId } from 'react';

const SHIELD = 'M16 2.4 27.4 6.6v8.6c0 6.4-4.7 11.6-11.4 14.4C9.3 26.8 4.6 21.6 4.6 15.2V6.6z';
const EYE = 'M7.6 15.4C10.2 11.5 13 10 16 10s5.8 1.5 8.4 5.4C21.8 19.3 19 20.8 16 20.8s-5.8-1.5-8.4-5.4z';

/**
 * The CyberSight mark: a geometric shield with a lens/eye cut out of it and a detection iris inside.
 * Same artwork as public/favicon.svg and public/brand/*.svg. Decorative by default (the wordmark next to it carries the name); pass `label` when it stands alone.
 */
export function LogoMark({ size = 28, label, mono }: { size?: number; label?: string; mono?: boolean }) {
  const uid = useId().replace(/:/g, '');
  const a11y = label ? { role: 'img' as const, 'aria-label': label } : { 'aria-hidden': true as const, focusable: 'false' as const };
  if (mono) {
    return (
      <svg viewBox="0 0 32 32" width={size} height={size} {...a11y}>
        <path fill="currentColor" fillRule="evenodd" d={`${SHIELD} ${EYE} M16 11.9a3.5 3.5 0 1 0 0 7a3.5 3.5 0 1 0 0-7zM16 14.05a1.35 1.35 0 1 1 0 2.7a1.35 1.35 0 1 1 0-2.7z`} />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 32 32" width={size} height={size} {...a11y}>
      <defs>
        <linearGradient id={`${uid}g`} x1="5" y1="3" x2="27" y2="30" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#38BDF8" /><stop offset="1" stopColor="#2563EB" /></linearGradient>
        <linearGradient id={`${uid}i`} x1="12" y1="12" x2="20" y2="19" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#7DD3FC" /><stop offset="1" stopColor="#38BDF8" /></linearGradient>
      </defs>
      <path fill={`url(#${uid}g)`} fillRule="evenodd" d={`${SHIELD} ${EYE}`} />
      <circle cx="16" cy="15.4" r="3.5" fill={`url(#${uid}i)`} />
      <circle cx="16" cy="15.4" r="1.35" fill="#04101F" />
      <circle cx="17.1" cy="14.3" r=".55" fill="#E8F0FC" />
    </svg>
  );
}

/** Mark + wordmark. The wordmark is live text in the theme's colours, so the logo reads on the dark and the light theme alike. */
export function Logo({ size = 28, subtitle }: { size?: number; subtitle?: string }) {
  return (
    <span className="logo">
      <LogoMark size={size} />
      <span className="logo-text">
        <span className="logo-word">Cyber<span className="logo-accent">Sight</span></span>
        {subtitle ? <small>{subtitle}</small> : null}
      </span>
    </span>
  );
}
