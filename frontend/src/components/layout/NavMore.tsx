import { useCallback, useEffect, useRef, useState } from 'react';
import { useDismiss } from '../../hooks/useDismiss';
import { Link } from '../../lib/router';
import { ChevronDown, type LucideIcon } from '../icons';
import { Icon } from '../ui/Icon';

interface Item { to: string; label: string; icon: LucideIcon; end?: boolean; also?: readonly string[] }

function belongs(item: Item, pathname: string): boolean {
  const hit = (base: string) => (item.end ? pathname === base : pathname === base || pathname.startsWith(`${base}/`));
  return hit(item.to) || (item.also ?? []).some((p) => pathname === p || pathname.startsWith(`${p}/`));
}

/** The desktop "More" menu: the destinations that do not fit in the bar next to the primary ones. A disclosure button (Escape, a click outside, or choosing a link closes it).
 *  It is hidden by CSS in the compact layout, where the same destinations are listed in the navigation panel. */
export function NavMore({ items, pathname }: { items: readonly Item[]; pathname: string }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const trigger = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setOpen(false), []);
  useDismiss(open, close, box, trigger);
  useEffect(() => { setOpen(false); }, [pathname]);
  const current = items.find((i) => belongs(i, pathname));
  return (
    <div className="popover-wrap nav-more" ref={box}>
      <button ref={trigger} type="button" className="nav-link nav-more-btn" aria-expanded={open} aria-controls={open ? 'nav-more-panel' : undefined}
        {...(current ? { 'data-active': 'true' } : {})} onClick={() => setOpen((v) => !v)}>
        <span>More</span>
        {current ? <span className="visually-hidden"> (current: {current.label})</span> : null}
        <Icon icon={ChevronDown} size={14} />
      </button>
      {open ? (
        <div className="popover popover-left" id="nav-more-panel" role="region" aria-label="More destinations">
          <ul role="list" className="popover-list">
            {items.map((item) => (
              <li key={item.to}>
                <Link to={item.to} className="popover-link" {...(belongs(item, pathname) ? { 'aria-current': 'page' as const } : {})}>
                  <Icon icon={item.icon} size={16} /><span>{item.label}</span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </div>
  );
}
