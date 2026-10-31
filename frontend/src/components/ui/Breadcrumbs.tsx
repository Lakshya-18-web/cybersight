import { Link } from '../../lib/router';

export interface Crumb { label: string; to?: string }

/** "Alerts / A-1042": every crumb but the last is a link; the last is the current page. */
export function Breadcrumbs({ items }: { items: readonly Crumb[] }) {
  return (
    <nav className="breadcrumbs" aria-label="Breadcrumb">
      <ol>
        {items.map((c, i) => (
          <li key={`${i}-${c.label}`}>{c.to && i < items.length - 1 ? <Link to={c.to}>{c.label}</Link> : <span {...(i === items.length - 1 ? { 'aria-current': 'page' as const } : {})}>{c.label}</span>}</li>
        ))}
      </ol>
    </nav>
  );
}
