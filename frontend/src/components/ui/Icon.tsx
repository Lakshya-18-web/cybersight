import type { LucideIcon } from '../icons';

/** Decorative icon (hidden from assistive technology). An icon that carries meaning must sit next to text or inside a control with an accessible name. */
export function Icon({ icon: Glyph, size = 16, className, spin }: { icon: LucideIcon; size?: number; className?: string; spin?: boolean }) {
  const cls = [className, spin ? 'spin' : ''].filter(Boolean).join(' ');
  return <Glyph size={size} aria-hidden="true" focusable="false" {...(cls ? { className: cls } : {})} />;
}
