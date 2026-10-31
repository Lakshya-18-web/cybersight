import { humanize } from '../../lib/format';
import { SEVERITY_ORDER } from '../../lib/severity';

/** Horizontal bars for a count per severity. Drawn as SVG so no inline style is needed (the site runs under a strict Content-Security-Policy). */
export function SeverityBars({ counts }: { counts: Record<string, number> }) {
  const keys = [...SEVERITY_ORDER, ...Object.keys(counts).filter((k) => !(SEVERITY_ORDER as readonly string[]).includes(k))];
  const max = Math.max(1, ...keys.map((k) => counts[k] ?? 0));
  return (
    <ul className="bars" role="list" aria-label="Cases by severity">
      {keys.map((k) => {
        const n = counts[k] ?? 0;
        const known = (SEVERITY_ORDER as readonly string[]).includes(k);
        return (
          <li key={k} className="bar-row">
            <span>{humanize(k)}</span>
            <svg viewBox="0 0 100 12" preserveAspectRatio="none" aria-hidden="true" focusable="false">
              <rect className="bar-track" x="0" y="0" width="100" height="12" rx="3" />
              {n > 0 ? <rect className="bar-fill" data-sev={known ? k : 'unknown'} x="0" y="0" width={Math.max(3, (n / max) * 100)} height="12" rx="3" /> : null}
            </svg>
            <span className="num">{n}</span>
          </li>
        );
      })}
    </ul>
  );
}
