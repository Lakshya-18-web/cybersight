import type { SearchRow } from '../../api/types';
import { ArrowDown, ArrowUp, ArrowUpDown } from '../../components/icons';
import { CaseStatusBadge, RiskBadge, RoutingBadge, SeverityBadge, Badge } from '../../components/ui/Badge';
import { CopyButton } from '../../components/ui/CopyButton';
import { Icon } from '../../components/ui/Icon';
import { Time } from '../../components/ui/Time';
import type { SortKey, SortState } from '../../lib/caseSort';
import { Link } from '../../lib/router';

interface Props {
  items: readonly SearchRow[];
  caption: string;
  sort?: SortState;
  onSort?: (key: SortKey) => void;
  compact?: boolean;
  /** Adds the network endpoints, note count and latest feedback (only the search API returns them). */
  detailed?: boolean;
  /** Drops Risk, Pending actions and Notes so the table fits a half-width dashboard card. The full set is on the Alerts and Cases pages. */
  lean?: boolean;
  /** Adds a copy button for the alert id and an explicit Open action (the whole row is not clickable; the alert id is the link). */
  actions?: boolean;
}

function SortHeader({ label, k, sort, onSort }: { label: string; k: SortKey; sort: SortState | undefined; onSort: ((k: SortKey) => void) | undefined }) {
  if (!sort || !onSort) return <>{label}</>;
  const active = sort.key === k;
  return (
    <button type="button" className="sort-btn" onClick={() => onSort(k)}>
      {label}<Icon icon={!active ? ArrowUpDown : sort.dir === 'asc' ? ArrowUp : ArrowDown} size={12} />
    </button>
  );
}

export function CasesTable({ items, caption, sort, onSort, compact, detailed, lean, actions = true }: Props) {
  const aria = (k: SortKey) => (sort && sort.key === k ? (sort.dir === 'asc' ? 'ascending' : 'descending') : undefined);
  return (
    <div className="table-wrap">
      <table className="table" data-stack="true" data-density={compact ? 'compact' : undefined}>
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr>
            <th scope="col" aria-sort={aria('alert')}><SortHeader label="Alert" k="alert" sort={sort} onSort={onSort} /></th>
            {detailed ? <th scope="col">Source IP</th> : null}
            {detailed ? <th scope="col">Destination</th> : null}
            <th scope="col">Attack type</th>
            <th scope="col" aria-sort={aria('severity')}><SortHeader label="Severity" k="severity" sort={sort} onSort={onSort} /></th>
            <th scope="col">Routing</th>
            {lean ? null : <th scope="col">Risk</th>}
            <th scope="col">Status</th>
            {lean ? null : <th scope="col" className="num">Pending actions</th>}
            {detailed && !lean ? <th scope="col">Notes · feedback</th> : null}
            <th scope="col" aria-sort={aria('created')}><SortHeader label="Created" k="created" sort={sort} onSort={onSort} /></th>
            {actions ? <th scope="col"><span className="visually-hidden">Actions</span></th> : null}
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.case_id}>
              <td data-label="Alert"><span className="id-cell"><Link className="row-link mono-id" to={`/cases/${c.case_id}`}>{c.alert_id}</Link>{actions ? <CopyButton value={c.alert_id} label={`alert id ${c.alert_id}`} /> : null}</span></td>
              {detailed ? <td data-label="Source IP" className="mono">{c.src_ip ?? '—'}</td> : null}
              {detailed ? <td data-label="Destination" className="mono">{c.dst_ip ?? '—'}{c.dst_ip && c.dst_port ? `:${c.dst_port}` : ''}</td> : null}
              <td data-label="Attack type">{c.attack_type ?? <span className="muted">—</span>}{c.is_malicious === false && (c.attack_type ?? '').toUpperCase() !== 'BENIGN' ? <> <Badge>Not malicious</Badge></> : null}</td>
              <td data-label="Severity"><SeverityBadge severity={c.severity} /></td>
              <td data-label="Routing"><RoutingBadge decision={c.routing_decision} /></td>
              {lean ? null : <td data-label="Risk"><RiskBadge risk={c.risk_level} /></td>}
              <td data-label="Status"><CaseStatusBadge status={c.status} /></td>
              {lean ? null : <td data-label="Pending actions" className="num">{c.pending_actions > 0 ? <Badge tone="warning">{c.pending_actions}</Badge> : <span className="muted">0</span>}</td>}
              {detailed && !lean ? <td data-label="Notes · feedback">{c.notes_count ? <Badge>{c.notes_count} note{c.notes_count === 1 ? '' : 's'}</Badge> : <span className="muted">0 notes</span>}{c.latest_feedback ? <> <Badge tone={c.latest_feedback === 'correct' ? 'success' : c.latest_feedback === 'incorrect' ? 'critical' : 'neutral'}>{c.latest_feedback}</Badge></> : null}</td> : null}
              <td data-label="Created"><Time value={c.created_at} /></td>
              {actions ? <td data-label=""><Link to={`/cases/${c.case_id}`} className="btn" data-size="sm" aria-label={`Open ${c.alert_id}`}>Open</Link></td> : null}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
