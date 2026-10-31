import { api } from '../api';
import { toApiError, type ApiError } from '../api/errors';
import type { JobView, Overview, Page, PendingAction, ProviderHealth, SearchPage } from '../api/types';
import { Briefcase, Cpu, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert, Workflow } from '../components/icons';
import { Badge, SeverityBadge } from '../components/ui/Badge';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { BarList, ColumnChart, Donut, type ChartRow } from '../components/ui/Charts';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { MetricTile } from '../components/ui/MetricTile';
import { PageHeader } from '../components/ui/PageHeader';
import { Async, EmptyState } from '../components/ui/State';
import { Time } from '../components/ui/Time';
import { RecentActivity } from '../features/dashboard/RecentActivity';
import { RecentAlerts } from '../features/dashboard/RecentAlerts';
import { ServiceHealthCard } from '../features/health/ServiceHealthCard';
import { useHealth } from '../hooks/useHealth';
import { useResource } from '../hooks/useResource';
import { bucketByDay, countBy, rowsFromCounts, topRows } from '../lib/chartData';
import { formatNumber, humanize } from '../lib/format';
import { Link } from '../lib/router';

/** One section's result. A failed request leaves a gap that says so; it never takes the whole page down and is never filled with a guess. */
interface Part<T> { value?: T; error?: ApiError }
async function part<T>(promise: Promise<T>): Promise<Part<T>> {
  try { return { value: await promise }; } catch (e) {
    const err = toApiError(e);
    if (err.isAborted) throw err;
    return { error: err };
  }
}

const SAMPLE = 100;
async function loadDashboard(signal: AbortSignal) {
  const o = { signal };
  const [overview, recent, pending, jobs, providers] = await Promise.all([
    part(api.overview(o)),
    part(api.searchCases({ limit: SAMPLE }, o)),
    part(api.pendingApprovals({ limit: 5 }, o)),
    part(api.listJobs({ limit: 8 }, o)),
    part(api.providers(o)),
  ]);
  return { overview: overview as Part<Overview>, recent: recent as Part<SearchPage>, pending: pending as Part<Page<PendingAction>>, jobs: jobs as Part<Page<JobView>>, providers: providers as Part<ProviderHealth>, loadedAt: Date.now() };
}

const num = (n: number | undefined | null) => (n === undefined || n === null ? '—' : formatNumber(n));
const sum = (r: Record<string, number> | undefined, keys: string[]) => (r ? keys.reduce((a, k) => a + (r[k] ?? 0), 0) : undefined);
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'none', 'unavailable'] as const;
const sevRows = (counts: Record<string, number> | undefined): ChartRow[] =>
  rowsFromCounts(counts, SEV_ORDER, (k) => (k === 'unavailable' ? 'Unavailable (no verdict)' : humanize(k))).map((r) => ({ ...r, sev: r.key === 'unavailable' ? 'unknown' : r.key, ...(r.key === 'unavailable' ? {} : { to: `/alerts?severity=${encodeURIComponent(r.key)}` }) }));
const linked = (counts: Record<string, number> | undefined, param: string, order?: readonly string[]): ChartRow[] =>
  rowsFromCounts(counts, order, humanize).map((r) => ({ ...r, ...(r.key === 'unavailable' || r.key === 'unknown' ? {} : { to: `/alerts?${param}=${encodeURIComponent(r.key)}` }) }));

function Unavailable({ what }: { what: string }) { return <p className="muted">Unavailable: {what} could not be loaded.</p>; }

export function OverviewPage() {
  const res = useResource(loadDashboard, []);
  const health = useHealth();
  return (
    <>
      <PageHeader title="Security Operations Overview" description="What the pipeline has triaged and what needs a person. Every number is computed by the API from stored records; nothing is estimated, sampled for show or filled in."
        actions={<>
          <span className={`health-chip`} data-state={health.state} role="status">API: {health.state === 'ok' ? 'ready' : health.state === 'down' ? 'unreachable' : humanize(health.state)}</span>
          <Button icon={RefreshCw} onClick={() => { res.reload(); health.refresh(); }} loading={res.refreshing}>Refresh</Button>
        </>} />
      <Async resource={res}>
        {(d) => {
          const ov = d.overview.value;
          const unavailable = 'Unavailable: this count could not be loaded';
          const inFlight = sum(ov?.jobs, ['queued', 'running']);
          const failed = sum(ov?.jobs, ['failed', 'timed_out']);
          const open = sum(ov?.by_status, ['escalated', 'needs_review']);
          const verdicts = ov ? Object.values(ov.by_verdict_status).reduce((a, n) => a + n, 0) : undefined;
          const sample = d.recent.value;
          const loaded = sample?.items ?? [];
          const days = bucketByDay(loaded.map((c) => c.created_at));
          const attack = topRows(rowsFromCounts(countBy(loaded, (c) => c.attack_type)), 8);
          const degraded = d.overview.error || d.recent.error || d.providers.error;
          return (
            <>
              {degraded ? <Banner tone="warning" title="Some parts of the dashboard could not be loaded">The affected cards say so and show no number; the others are unaffected. Use Refresh to try again.</Banner> : null}
              <section className="grid grid-metrics" aria-label="Key counts">
                <MetricTile icon={ShieldAlert} label="Total alerts" value={num(ov?.cases_total)} to="/alerts" tone="accent" note={ov ? `${num(ov.cases_last_24h)} in the last 24 hours` : unavailable} />
                <MetricTile icon={Briefcase} label="Open cases" value={num(open)} to="/cases" {...(open ? { tone: 'warning' as const } : {})} note={ov ? 'Escalated or needing review' : unavailable} />
                <MetricTile icon={TriangleAlert} label="Escalated cases" value={num(ov?.by_status.escalated)} to="/alerts?status=escalated" {...(ov?.by_status.escalated ? { tone: 'critical' as const } : {})} note={ov ? 'Routed to a person' : unavailable} />
                <MetricTile icon={ShieldAlert} label="High-risk alerts" value={num(ov?.by_risk.high)} to="/alerts?risk_level=high" {...(ov?.by_risk.high ? { tone: 'critical' as const } : {})} note={ov ? 'Policy risk level: high' : unavailable} />
                <MetricTile icon={Cpu} label="Jobs in progress" value={num(inFlight)} to="/jobs" note={ov ? `${num(ov.jobs.queued ?? 0)} queued · ${num(ov.jobs.running ?? 0)} running` : unavailable} />
                <MetricTile icon={TriangleAlert} label="Failed jobs" value={num(failed)} to="/jobs?status=failed" {...(failed ? { tone: 'critical' as const } : {})} note={ov ? `${num(ov.jobs.failed ?? 0)} failed · ${num(ov.jobs.timed_out ?? 0)} timed out` : unavailable} />
                <MetricTile icon={ShieldCheck} label="AI analyses completed" value={num(ov?.by_verdict_status.ok)} to="/alerts?verdict_status=ok" tone="ai" note={ov ? `Usable model verdicts of ${num(verdicts)} cases` : unavailable} />
                <MetricTile icon={Workflow} label="Pending actions" value={num(ov?.pending_actions)} to="/playbooks" {...(ov?.pending_actions ? { tone: 'warning' as const } : {})} note={ov ? 'Proposed actions waiting for a person' : unavailable} />
              </section>

              <div className="grid grid-main">
                <Card>
                  <CardHeader title="Alert volume" description={sample ? `Alerts per day (UTC) among the newest ${loaded.length} of ${num(sample.total)}. Not the full history${sample.total > loaded.length ? '' : ': this is all of them'}.` : undefined} />
                  <CardBody>
                    {d.recent.error ? <Unavailable what="the alert list" /> : days.buckets.length === 0 ? <p className="muted">No alerts yet, so there is nothing to plot.</p> : <ColumnChart points={days.buckets.map((b) => ({ key: b.day, label: b.label, value: b.value }))} label="Alerts created per day" unit="alerts" />}
                    {days.skipped ? <p className="section-note">{days.skipped} alert(s) had no usable timestamp and are not plotted.</p> : null}
                  </CardBody>
                </Card>
                <Card>
                  <CardHeader title="Severity distribution" description="What the model said, across all cases. Exact totals." />
                  <CardBody>{ov ? <Donut rows={sevRows(ov.by_severity)} label="Cases by model severity" centre="cases" /> : <Unavailable what="the severity counts" />}</CardBody>
                </Card>
              </div>

              <div className="grid grid-3">
                <Card>
                  <CardHeader title="Case status" description="Exact totals." />
                  <CardBody>{ov ? <BarList rows={linked(ov.by_status, 'status', ['escalated', 'needs_review', 'resolved', 'auto_closed'])} label="Cases by status" /> : <Unavailable what="the status counts" />}</CardBody>
                </Card>
                <Card>
                  <CardHeader title="Routing decisions" description="The policy's decision after the evidence rules." />
                  <CardBody>{ov ? <Donut rows={linked(ov.by_routing, 'routing_decision', ['escalate', 'needs_review', 'auto_close'])} label="Cases by routing decision" centre="cases" /> : <Unavailable what="the routing counts" />}</CardBody>
                </Card>
                <Card>
                  <CardHeader title="Risk distribution" description="Policy risk level, exact totals." />
                  <CardBody>{ov ? <BarList rows={linked(ov.by_risk, 'risk_level', ['high', 'medium', 'low', 'unknown']).map((r) => ({ ...r, sev: r.key }))} label="Cases by risk level" /> : <Unavailable what="the risk counts" />}</CardBody>
                </Card>
              </div>

              <RecentAlerts items={loaded} total={sample?.total ?? 0} />

              <div className="grid grid-3">
                <div className="stack">
                  <ServiceHealthCard providers={d.providers.value} />
                </div>
                <div className="stack">
                  <Card>
                    <CardHeader title="Awaiting approval" description="Oldest first. A person decides; nothing runs by itself." actions={<Link to="/playbooks">Playbooks</Link>} />
                    {d.pending.error ? <CardBody><Unavailable what="the approval queue" /></CardBody>
                      : (d.pending.value?.items.length ?? 0) === 0 ? <EmptyState title="Nothing is waiting for approval">New proposals appear here as soon as the pipeline makes them.</EmptyState>
                      : (
                        <ul role="list" className="feed">
                          {d.pending.value?.items.map((a) => (
                            <li key={a.action_id}>
                              <SeverityBadge severity={a.severity} />
                              <span>{humanize(a.action_type)} <span className="muted">on {a.target ?? '—'} ·</span> <Link className="row-link mono-id" to={`/cases/${a.case_id}`}>{a.alert_id}</Link></span>
                              <Time value={a.created_at} />
                            </li>
                          ))}
                        </ul>
                      )}
                  </Card>
                  <Card>
                    <CardHeader title="Attack types" description={sample ? `Counted among the newest ${loaded.length} of ${num(sample.total)} alerts (the model's label; "Unavailable" means no usable verdict).` : undefined} />
                    <CardBody>{d.recent.error ? <Unavailable what="the alert list" /> : <BarList rows={attack.map((r) => ({ ...r, label: r.key === 'unavailable' ? 'Unavailable (no verdict)' : r.label }))} label="Attack types among loaded alerts" empty="No alerts yet." />}</CardBody>
                  </Card>
                </div>
                <div className="stack">
                  <RecentActivity jobs={d.jobs.error ? undefined : d.jobs.value?.items} />
                </div>
              </div>
              <p className="muted" role="status">Loaded <Time value={new Date(d.loadedAt).toISOString()} />. <Badge>Manual refresh</Badge></p>
            </>
          );
        }}
      </Async>
    </>
  );
}
