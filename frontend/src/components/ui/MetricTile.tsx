import type { ReactNode } from 'react';
import { Link } from '../../lib/router';
import { Icon } from './Icon';
import type { LucideIcon } from '../icons';

type KpiTone = 'critical' | 'warning' | 'success' | 'accent' | 'ai';

/** One number with its label and the place it came from. `to` makes the whole card a link. The tone only colours the top edge and the number; the note always says in words what the number is. */
export function MetricTile({ label, value, note, tone, to, icon }: { label: string; value: ReactNode; note?: ReactNode; tone?: KpiTone; to?: string; icon?: LucideIcon }) {
  const inner = (
    <>
      <span className="metric-label">{icon ? <Icon icon={icon} size={14} /> : null}{label}</span>
      <span className="metric-value">{value}</span>
      {note ? <span className="metric-note">{note}</span> : null}
    </>
  );
  return to
    ? <Link to={to} className="card metric kpi" data-tone={tone}>{inner}</Link>
    : <div className="card metric kpi" data-tone={tone}>{inner}</div>;
}
