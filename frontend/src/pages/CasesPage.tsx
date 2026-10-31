import { api } from '../api';
import { CASE_STATUSES, RISK_LEVELS, ROUTING_DECISIONS, SEARCH_SORTS } from '../api/types';
import { Briefcase, RefreshCw } from '../components/icons';
import { Badge, CaseStatusBadge, RiskBadge, RoutingBadge, SeverityBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { CopyButton } from '../components/ui/CopyButton';
import { SelectField, TextField } from '../components/ui/Field';
import { PageHeader } from '../components/ui/PageHeader';
import { Pagination } from '../components/ui/Pagination';
import { Async, EmptyState } from '../components/ui/State';
import { Time } from '../components/ui/Time';
import { useResource } from '../hooks/useResource';
import { humanize, shortId } from '../lib/format';
import { Link, useSearchParams } from '../lib/router';
import { activeFilterCount, FILTER_PARAMS, PAGE_SIZES, Q_MAX, readFilters, toQuery } from '../lib/search';

const SORTS: Record<string, string> = { created_desc: 'Newest first', created_asc: 'Oldest first', updated_desc: 'Recently updated', severity_desc: 'Most severe first', risk_desc: 'Highest risk first' };

/** Case management list. Same server-side search as Alerts (every filter and the sort run over all cases), laid out per case: id, linked alert, verdict, status, created and updated. */
export function CasesPage() {
  const [params, setParams] = useSearchParams();
  const f = readFilters(params);
  const query = toQuery(f);
  const res = useResource((signal) => api.searchCases(query, { signal }), [JSON.stringify(query)]);
  const filters = activeFilterCount(f);
  const set = (name: string) => (e: { target: { value: string } }) => setParams({ [name]: e.target.value, offset: null });
  const reset = () => setParams(Object.fromEntries(FILTER_PARAMS.map((k) => [k, null])));
  return (
    <>
      <PageHeader title="Cases" description="One case per triaged alert: the model's verdict, the policy's routing, and where the case stands. Filters and sorting run on the server across all cases."
        actions={<Button icon={RefreshCw} onClick={res.reload} loading={res.refreshing}>Refresh</Button>} />
      <Card>
        <CardBody>
          <form className="filters" role="search" aria-label="Filter cases" onSubmit={(e) => e.preventDefault()}>
            <TextField label="Search" type="search" value={f.q} onChange={(e) => setParams({ q: e.target.value, offset: null })} maxLength={Q_MAX} placeholder="Case ID, alert ID, address…" autoComplete="off" />
            <SelectField label="Status" value={f.status} onChange={set('status')}><option value="">All statuses</option>{CASE_STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
            <SelectField label="Routing" value={f.routing_decision} onChange={set('routing_decision')}><option value="">Any</option>{ROUTING_DECISIONS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
            <SelectField label="Risk" value={f.risk_level} onChange={set('risk_level')}><option value="">Any</option>{RISK_LEVELS.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}</SelectField>
            <SelectField label="Model says malicious" value={f.is_malicious} onChange={set('is_malicious')}><option value="">Any</option><option value="true">Yes</option><option value="false">No</option></SelectField>
            <SelectField label="Sort" value={f.sort} onChange={set('sort')}>{SEARCH_SORTS.map((s) => <option key={s} value={s}>{SORTS[s]}</option>)}</SelectField>
            <SelectField label="Rows per page" value={String(f.limit)} onChange={set('limit')}>{PAGE_SIZES.map((n) => <option key={n} value={n}>{n}</option>)}</SelectField>
            {filters ? <Button variant="ghost" onClick={reset}>Clear {filters} filter{filters === 1 ? '' : 's'}</Button> : null}
          </form>
        </CardBody>
      </Card>
      <Card>
        <Async resource={res}>
          {(page) => (
            <>
              <p className="field-hint card-body" role="status">{page.total} case{page.total === 1 ? '' : 's'}{filters ? ' match these filters' : ''}.</p>
              {page.total === 0 ? <EmptyState icon={Briefcase} title={filters ? 'No cases match these filters' : 'No cases yet'} {...(filters ? { action: <Button onClick={reset}>Clear filters</Button> } : {})}>{filters ? 'Try removing a filter.' : 'A case is created when a worker finishes triaging an alert.'}</EmptyState>
                : page.items.length === 0 ? <EmptyState title="Nothing on this page">Go back to the first page.</EmptyState>
                : (
                  <div className="table-wrap">
                    <table className="table" data-stack="true" data-density="compact">
                      <caption className="visually-hidden">Cases</caption>
                      <thead><tr><th scope="col">Case</th><th scope="col">Alert</th><th scope="col">Verdict</th><th scope="col">Severity</th><th scope="col">Risk</th><th scope="col">Routing</th><th scope="col">Status</th><th scope="col">Created</th><th scope="col">Updated</th></tr></thead>
                      <tbody>
                        {page.items.map((c) => (
                          <tr key={c.case_id}>
                            <td data-label="Case"><span className="id-cell"><Link className="row-link mono-id" to={`/cases/${c.case_id}`}>{shortId(c.case_id)}</Link><CopyButton value={c.case_id} label="case id" /></span></td>
                            <td data-label="Alert" className="mono-id">{c.alert_id}</td>
                            <td data-label="Verdict">{c.verdict_status === 'ok' ? <>{c.is_malicious === true ? <Badge tone="critical">Malicious</Badge> : c.is_malicious === false ? <Badge tone="success">Benign</Badge> : <Badge>Unclassified</Badge>} <span className="muted">{c.attack_type ?? ''}</span></> : <Badge tone="warning">{humanize(c.verdict_status ?? 'missing')}</Badge>}</td>
                            <td data-label="Severity"><SeverityBadge severity={c.severity} /></td>
                            <td data-label="Risk"><RiskBadge risk={c.risk_level} /></td>
                            <td data-label="Routing"><RoutingBadge decision={c.routing_decision} /></td>
                            <td data-label="Status"><CaseStatusBadge status={c.status} /></td>
                            <td data-label="Created"><Time value={c.created_at} /></td>
                            <td data-label="Updated"><Time value={c.updated_at} /></td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} busy={res.refreshing} onOffset={(o) => setParams({ offset: o === 0 ? null : String(o) }, { replace: false })} />
            </>
          )}
        </Async>
      </Card>
    </>
  );
}
