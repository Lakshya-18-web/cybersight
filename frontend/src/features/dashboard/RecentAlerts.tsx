import { useState } from 'react';
import type { SearchRow } from '../../api/types';
import { Button } from '../../components/ui/Button';
import { Card, CardHeader } from '../../components/ui/Card';
import { SelectField, TextField } from '../../components/ui/Field';
import { EmptyState } from '../../components/ui/State';
import { ShieldAlert } from '../../components/icons';
import { CasesTable } from '../cases/CasesTable';
import { CASE_STATUSES, RISK_LEVELS, ROUTING_DECISIONS } from '../../api/types';
import { humanize } from '../../lib/format';
import { Link } from '../../lib/router';
import { SEVERITY_ORDER } from '../../lib/severity';

interface Filters { q: string; severity: string; risk: string; status: string; routing: string }
const NONE: Filters = { q: '', severity: '', risk: '', status: '', routing: '' };

export function matches(c: SearchRow, f: Filters): boolean {
  const q = f.q.trim().toLowerCase();
  if (f.severity && (c.severity ?? '').toLowerCase() !== f.severity) return false;
  if (f.risk && (c.risk_level ?? '').toLowerCase() !== f.risk) return false;
  if (f.status && c.status !== f.status) return false;
  if (f.routing && c.routing_decision !== f.routing) return false;
  if (!q) return true;
  return [c.alert_id, c.case_id, c.attack_type ?? '', c.src_ip ?? '', c.dst_ip ?? ''].some((v) => v.toLowerCase().includes(q));
}

/** The newest alerts already loaded for the dashboard. The filters here only look at those rows (said on the card); the Alerts page filters across all of them on the server. */
export function RecentAlerts({ items, total, shown = 10 }: { items: readonly SearchRow[]; total: number; shown?: number }) {
  const [f, setF] = useState<Filters>(NONE);
  const set = (k: keyof Filters) => (e: { target: { value: string } }) => setF((s) => ({ ...s, [k]: e.target.value }));
  const active = (Object.keys(f) as (keyof Filters)[]).filter((k) => f[k] !== '').length;
  const filtered = items.filter((c) => matches(c, f));
  const rows = filtered.slice(0, shown);
  return (
    <Card>
      <CardHeader title="Recent alerts" description={`Filters here look only at the ${items.length} newest alerts loaded on this page. The Alerts page searches all ${total}.`} actions={<Link to="/alerts">All alerts</Link>} />
      <form className="table-toolbar" role="search" aria-label="Filter the loaded recent alerts" onSubmit={(e) => e.preventDefault()}>
        <TextField label="Search loaded rows" type="search" value={f.q} onChange={set('q')} placeholder="ID, IP, attack…" autoComplete="off" />
        <SelectField label="Severity" value={f.severity} onChange={set('severity')}><option value="">Any</option>{SEVERITY_ORDER.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
        <SelectField label="Risk" value={f.risk} onChange={set('risk')}><option value="">Any</option>{RISK_LEVELS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
        <SelectField label="Status" value={f.status} onChange={set('status')}><option value="">Any</option>{CASE_STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
        <SelectField label="Routing" value={f.routing} onChange={set('routing')}><option value="">Any</option>{ROUTING_DECISIONS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
        {active ? <Button variant="ghost" onClick={() => setF(NONE)}>Clear filters</Button> : null}
      </form>
      {items.length === 0 ? <EmptyState icon={ShieldAlert} title="No alerts yet">Submitted alerts and sensor events appear here once a worker has triaged them.</EmptyState>
        : rows.length === 0 ? <EmptyState title="No loaded alert matches" action={<Button onClick={() => setF(NONE)}>Clear filters</Button>}>Try other filters, or search all alerts on the Alerts page.</EmptyState>
        : <CasesTable items={rows} detailed lean compact actions={false} caption="Most recent alerts" />}
      {filtered.length > rows.length ? <p className="table-foot" role="status">Showing {rows.length} of {filtered.length} loaded matches. <Link to="/alerts">Open the full list</Link></p> : null}
    </Card>
  );
}
