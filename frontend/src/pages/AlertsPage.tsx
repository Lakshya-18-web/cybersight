import { api } from '../api';
import { ALERT_SETS, CASE_STATUSES, RISK_LEVELS, ROUTING_DECISIONS, SEARCH_SORTS, VERDICT_STATUSES } from '../api/types';
import { usePermissions } from '../auth/AuthContext';
import { RefreshCw, Send, ShieldAlert } from '../components/icons';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { SelectField, TextField } from '../components/ui/Field';
import { PageHeader } from '../components/ui/PageHeader';
import { Pagination } from '../components/ui/Pagination';
import { Async, EmptyState } from '../components/ui/State';
import { CasesTable } from '../features/cases/CasesTable';
import { useResource } from '../hooks/useResource';
import { humanize } from '../lib/format';
import { Link, useSearchParams } from '../lib/router';
import { activeFilterCount, FILTER_PARAMS, PAGE_SIZES, Q_MAX, readFilters, toQuery } from '../lib/search';
import { SEVERITY_ORDER } from '../lib/severity';

const SORT_LABELS: Record<string, string> = {
  created_desc: 'Newest first', created_asc: 'Oldest first', updated_desc: 'Recently updated', severity_desc: 'Most severe first', risk_desc: 'Highest risk first',
};

/** The alert queue. Every filter, the search and the sort are applied by the server over ALL cases (not just the page on screen) and live in the address bar. */
export function AlertsPage() {
  const { submit } = usePermissions();
  const [params, setParams] = useSearchParams();
  const f = readFilters(params);
  const query = toQuery(f);
  const res = useResource((signal) => api.searchCases(query, { signal }), [JSON.stringify(query)]);
  const filters = activeFilterCount(f);
  const set = (name: string) => (e: { target: { value: string } }) => setParams({ [name]: e.target.value, offset: null });
  const reset = () => setParams(Object.fromEntries(FILTER_PARAMS.map((k) => [k, null])));

  return (
    <>
      <PageHeader title="Alerts" description="Every alert the pipeline has triaged. Search, filters and sorting run on the server across all of them."
        actions={<>
          <Button icon={RefreshCw} onClick={res.reload} loading={res.refreshing}>Refresh</Button>
          {submit ? <Link to="/alerts/new" className="btn" data-variant="primary"><Send size={16} aria-hidden="true" />Submit alert</Link> : null}
        </>} />
      <Card>
        <CardBody>
          <form className="filters" role="search" aria-label="Filter alerts" onSubmit={(e) => e.preventDefault()}>
            <TextField label="Search" type="search" value={f.q} onChange={(e) => setParams({ q: e.target.value, offset: null })} maxLength={Q_MAX} placeholder="Alert ID, address, attack type…" autoComplete="off" hint="Alert ID, case ID, source or destination address, attack type" />
            <SelectField label="Status" value={f.status} onChange={set('status')}>
              <option value="">All statuses</option>
              {CASE_STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Routing" value={f.routing_decision} onChange={set('routing_decision')}>
              <option value="">Any</option>
              {ROUTING_DECISIONS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Severity" value={f.severity} onChange={set('severity')}>
              <option value="">Any</option>
              {SEVERITY_ORDER.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Risk" value={f.risk_level} onChange={set('risk_level')}>
              <option value="">Any</option>
              {RISK_LEVELS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Source" value={f.alert_set} onChange={set('alert_set')}>
              <option value="">Any</option>
              {ALERT_SETS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Verdict" value={f.verdict_status} onChange={set('verdict_status')}>
              <option value="">Any</option>
              {VERDICT_STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Model says malicious" value={f.is_malicious} onChange={set('is_malicious')}>
              <option value="">Any</option><option value="true">Yes</option><option value="false">No</option>
            </SelectField>
            <SelectField label="Pending approvals" value={f.has_pending} onChange={set('has_pending')}>
              <option value="">Any</option><option value="true">Has pending</option><option value="false">None pending</option>
            </SelectField>
            <TextField label="Created from" type="date" value={f.created_from.slice(0, 10)} onChange={set('created_from')} />
            <TextField label="Created before" type="date" value={f.created_to.slice(0, 10)} onChange={set('created_to')} />
            <SelectField label="Sort" value={f.sort} onChange={set('sort')}>
              {SEARCH_SORTS.map((s) => <option key={s} value={s}>{SORT_LABELS[s]}</option>)}
            </SelectField>
            <SelectField label="Rows per page" value={String(f.limit)} onChange={set('limit')}>
              {PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
            </SelectField>
            {filters ? <Button variant="ghost" onClick={reset}>Clear {filters} filter{filters === 1 ? '' : 's'}</Button> : null}
          </form>
        </CardBody>
      </Card>
      <Card>
        <Async resource={res}>
          {(page) => (
            <>
              <p className="field-hint card-body" role="status">{page.total} alert{page.total === 1 ? '' : 's'}{filters ? ' match' : ''}{filters ? ' these filters' : ''}.</p>
              {page.total === 0 ? (
                <EmptyState icon={ShieldAlert} title={filters ? 'No alerts match these filters' : 'No alerts yet'}
                  action={filters ? <Button onClick={reset}>Clear filters</Button> : submit ? <Link to="/alerts/new" className="btn" data-variant="primary">Submit an alert</Link> : undefined}>
                  {filters ? 'Try removing a filter or widening the dates.' : 'Alerts appear here after a worker has triaged them. Sensor events arrive through the sensor ingestion endpoint.'}
                </EmptyState>
              ) : page.items.length === 0 ? (
                <EmptyState title="Nothing on this page">The list is shorter than the page you asked for. Go back to the first page.</EmptyState>
              ) : <CasesTable items={page.items} detailed caption="Triaged alerts" />}
              <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} busy={res.refreshing} onOffset={(o) => setParams({ offset: o === 0 ? null : String(o) }, { replace: false })} />
            </>
          )}
        </Async>
      </Card>
    </>
  );
}
