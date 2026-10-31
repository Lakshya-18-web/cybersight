import { useState } from 'react';
import { api } from '../api';
import { Button } from '../components/ui/Button';
import { SeverityBadge, RiskBadge } from '../components/ui/Badge';
import { Card } from '../components/ui/Card';
import { PageHeader } from '../components/ui/PageHeader';
import { Pagination } from '../components/ui/Pagination';
import { Async, EmptyState } from '../components/ui/State';
import { Tabs, panelId, tabId } from '../components/ui/Tabs';
import { Time } from '../components/ui/Time';
import { RefreshCw, ShieldCheck } from '../components/icons';
import { CasesTable } from '../features/cases/CasesTable';
import { useResource } from '../hooks/useResource';
import { humanize } from '../lib/format';
import { Link, useSearchParams } from '../lib/router';
import { ActionStateBadge, Badge } from '../components/ui/Badge';
import { Banner } from '../components/ui/Banner';
import { SelectField } from '../components/ui/Field';
import { CardBody } from '../components/ui/Card';

const TABS = [
  { id: 'approvals', label: 'Awaiting approval' },
  { id: 'escalated', label: 'Escalated cases' },
  { id: 'review', label: 'Needs review' },
  { id: 'history', label: 'Decisions & simulated runs' },
] as const;
const LIMIT = 25;

export function Approvals() {
  const [offset, setOffset] = useState(0);
  const res = useResource((signal) => api.pendingApprovals({ limit: LIMIT, offset }, { signal }), [offset]);
  return (
    <Card>
      <Async resource={res}>
        {(page) => page.total === 0 ? (
          <EmptyState icon={ShieldCheck} title="Nothing is waiting for approval">Proposed actions appear here as soon as the agent makes them.</EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table" data-stack="true">
                <caption className="visually-hidden">Proposed actions awaiting a decision, oldest first</caption>
                <thead><tr><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Alert</th><th scope="col">Attack type</th><th scope="col">Severity</th><th scope="col">Risk</th><th scope="col">Proposed</th><th scope="col"><span className="visually-hidden">Review</span></th></tr></thead>
                <tbody>
                  {page.items.map((a) => (
                    <tr key={a.action_id}>
                      <td data-label="Action">{humanize(a.action_type)}</td>
                      <td data-label="Target" className="mono-id">{a.target ?? '—'}</td>
                      <td data-label="Alert" className="mono-id">{a.alert_id}</td>
                      <td data-label="Attack type">{a.attack_type ?? '—'}</td>
                      <td data-label="Severity"><SeverityBadge severity={a.severity} /></td>
                      <td data-label="Risk"><RiskBadge risk={a.risk_level} /></td>
                      <td data-label="Proposed"><Time value={a.created_at} /></td>
                      <td data-label=""><Link to={`/cases/${a.case_id}`} className="btn" data-size="sm" aria-label={`Review ${a.alert_id}`}>Review</Link></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} busy={res.refreshing} onOffset={setOffset} />
          </>
        )}
      </Async>
    </Card>
  );
}

function ByStatus({ status, empty }: { status: string; empty: string }) {
  const [offset, setOffset] = useState(0);
  const res = useResource((signal) => api.listCases({ status, limit: LIMIT, offset }, { signal }), [status, offset]);
  return (
    <Card>
      <Async resource={res}>
        {(page) => page.total === 0 ? <EmptyState title={empty} /> : (
          <>
            <CasesTable items={page.items} caption={`${humanize(status)} cases`} />
            <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} busy={res.refreshing} onOffset={setOffset} />
          </>
        )}
      </Async>
    </Card>
  );
}

/** Every decided proposal and, when one was recorded, its SIMULATED execution. A simulated execution is an audit record that the action would have been carried out; nothing was executed against any system. */
export function History() {
  const [state, setState] = useState('');
  const [executed, setExecuted] = useState('');
  const [offset, setOffset] = useState(0);
  const res = useResource((signal) => api.listActions({ state, executed, limit: LIMIT, offset }, { signal }), [state, executed, offset]);
  return (
    <div className="stack">
      <Banner tone="info" title="Simulation only">Approving records a person's decision. “Simulated” means an audit record was written that the action would have been carried out; no firewall, host or account was touched.</Banner>
      <Card>
        <CardBody>
          <form className="filters" aria-label="Filter decided actions" onSubmit={(e) => e.preventDefault()}>
            <SelectField label="State" value={state} onChange={(e) => { setState(e.target.value); setOffset(0); }}>
              <option value="">Any</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="rejected">Rejected</option>
            </SelectField>
            <SelectField label="Simulated execution" value={executed} onChange={(e) => { setExecuted(e.target.value); setOffset(0); }}>
              <option value="">Any</option><option value="true">Recorded</option><option value="false">Not recorded</option>
            </SelectField>
          </form>
        </CardBody>
      </Card>
      <Card>
        <Async resource={res}>
          {(page) => page.total === 0 ? <EmptyState title="Nothing matches">{state || executed ? 'Try other filters.' : 'No action has been proposed yet.'}</EmptyState> : (
            <>
              <div className="table-wrap">
                <table className="table" data-stack="true">
                  <caption className="visually-hidden">Proposed actions with their decision and simulated execution, newest activity first</caption>
                  <thead><tr><th scope="col">Action</th><th scope="col">Target</th><th scope="col">Alert</th><th scope="col">State</th><th scope="col">Decided by</th><th scope="col">Reason</th><th scope="col">Simulated run</th></tr></thead>
                  <tbody>
                    {page.items.map((a) => (
                      <tr key={a.action_id}>
                        <td data-label="Action">{humanize(a.action_type)}</td>
                        <td data-label="Target" className="mono-id">{a.target ?? '—'}</td>
                        <td data-label="Alert"><Link className="row-link mono-id" to={`/cases/${a.case_id}`}>{a.alert_id ?? a.case_id.slice(0, 8)}</Link></td>
                        <td data-label="State"><ActionStateBadge state={a.state} /></td>
                        <td data-label="Decided by">{a.decided_by ?? <span className="muted">—</span>}{a.decided_at ? <div className="muted"><Time value={a.decided_at} /></div> : null}</td>
                        <td data-label="Reason">{a.decision_reason ?? <span className="muted">—</span>}</td>
                        <td data-label="Simulated run">{a.executed ? <><Badge tone="accent">Simulated</Badge> <span className="muted">by {a.executed_by} <Time value={a.executed_at} /></span></> : <span className="muted">{a.state === 'approved' ? 'Not recorded yet' : '—'}</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} busy={res.refreshing} onOffset={setOffset} />
            </>
          )}
        </Async>
      </Card>
    </div>
  );
}

export function InvestigationsPage() {
  const [params] = useSearchParams();
  const [tab, setTab] = useState<string>(TABS.some((t) => t.id === params.get('tab')) ? (params.get('tab') as string) : 'approvals');
  const [epoch, setEpoch] = useState(0);
  return (
    <>
      <PageHeader title="Investigations" description="Work that needs a person: actions waiting for a decision, and cases the policy escalated or could not decide safely."
        actions={<Button icon={RefreshCw} onClick={() => setEpoch((n) => n + 1)}>Refresh</Button>} />
      <Tabs tabs={TABS} value={tab} onChange={setTab} prefix="inv" label="Investigation queues" />
      <div role="tabpanel" id={panelId('inv', tab)} aria-labelledby={tabId('inv', tab)}>
        {tab === 'approvals' ? <Approvals key={epoch} /> : null}
        {tab === 'escalated' ? <ByStatus key={`e${epoch}`} status="escalated" empty="No escalated cases" /> : null}
        {tab === 'history' ? <History key={`h${epoch}`} /> : null}
        {tab === 'review' ? <ByStatus key={`r${epoch}`} status="needs_review" empty="No cases need review" /> : null}
      </div>
    </>
  );
}
