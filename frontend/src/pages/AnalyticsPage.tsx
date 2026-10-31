import { api } from '../api';
import { RefreshCw } from '../components/icons';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { BarList, ColumnChart, Donut, type ChartRow } from '../components/ui/Charts';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { SelectField } from '../components/ui/Field';
import { MetricTile } from '../components/ui/MetricTile';
import { PageHeader } from '../components/ui/PageHeader';
import { Async } from '../components/ui/State';
import { useResource } from '../hooks/useResource';
import { completionRate, jobLatency, tokenTotals } from '../lib/analytics';
import { bucketByDay, countBy, rowsFromCounts, topRows } from '../lib/chartData';
import { formatDuration, formatNumber, humanize } from '../lib/format';
import { useSearchParams } from '../lib/router';

const RANGES = { all: 'All time', '7': 'Last 7 days', '30': 'Last 30 days' } as const;
type RangeKey = keyof typeof RANGES;
const SAMPLE = 100;
const dayAgo = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);

/** Everything here is computed from API data. The summary counts (severity, risk, status, routing, jobs) are exact totals over ALL cases. The volume, attack-type and latency charts use the newest 100 rows
 *  (the API returns at most that many per request); the card says so, with the real total. The time range applies to those sampled rows through the API's created_from filter. */
export function AnalyticsPage() {
  const [params, setParams] = useSearchParams();
  const range: RangeKey = (params.get('range') as RangeKey) in RANGES ? (params.get('range') as RangeKey) : 'all';
  const res = useResource(async (signal) => {
    const o = { signal };
    const from = range === 'all' ? undefined : dayAgo(Number(range));
    const [overview, sample, jobs] = await Promise.all([
      api.overview(o).then((v) => ({ v }), (e: unknown) => ({ e })),
      api.searchCases({ limit: SAMPLE, ...(from ? { created_from: from } : {}) }, o).then((v) => ({ v }), (e: unknown) => ({ e })),
      api.listJobs({ limit: SAMPLE }, o).then((v) => ({ v }), (e: unknown) => ({ e })),
    ]);
    return { overview, sample, jobs };
  }, [range]);
  const num = (n: number | undefined) => (n === undefined ? '—' : formatNumber(n));
  return (
    <>
      <PageHeader title="Analytics" description="Distributions and processing statistics from stored records. Exact totals are marked exact; charts built from the newest rows say how many rows they used."
        actions={<>
          <SelectField label="Time range (sampled charts)" value={range} onChange={(e) => setParams({ range: e.target.value === 'all' ? null : e.target.value })}>
            {Object.entries(RANGES).map(([k, label]) => <option key={k} value={k}>{label}</option>)}
          </SelectField>
          <Button icon={RefreshCw} onClick={res.reload} loading={res.refreshing}>Refresh</Button>
        </>} />
      <Async resource={res}>
        {({ overview, sample, jobs }) => {
          const ov = 'v' in overview ? overview.v : undefined;
          const rows = 'v' in sample ? sample.v.items : undefined;
          const total = 'v' in sample ? sample.v.total : undefined;
          const js = 'v' in jobs ? jobs.v.items : undefined;
          const days = rows ? bucketByDay(rows.map((c) => c.created_at)) : undefined;
          const lat = js ? jobLatency(js) : undefined;
          const tok = js ? tokenTotals(js) : undefined;
          const done = completionRate(ov?.jobs);
          const sev = (r: Record<string, number> | undefined): ChartRow[] => rowsFromCounts(r, ['critical', 'high', 'medium', 'low', 'none', 'unavailable'], (k) => (k === 'unavailable' ? 'Unavailable (no verdict)' : humanize(k))).map((x) => ({ ...x, sev: x.key === 'unavailable' ? 'unknown' : x.key }));
          const fail = !ov || !rows || !js;
          return (
            <>
              {fail ? <Banner tone="warning" title="Some analytics could not be loaded">Cards that depend on the missing data say so. Nothing is estimated in their place.</Banner> : null}
              <section className="grid grid-metrics" aria-label="Processing summary">
                <MetricTile label="Cases (exact)" value={num(ov?.cases_total)} note={ov ? `${num(ov.cases_last_24h)} in the last 24 hours` : 'Unavailable'} tone="accent" />
                <MetricTile label="Job completion (exact)" value={done.rate === null ? '—' : `${Math.round(done.rate * 100)}%`} note={done.finished ? `${num(ov?.jobs.succeeded ?? 0)} of ${num(done.finished)} finished jobs succeeded` : 'No finished job yet'} {...(done.rate !== null && done.rate < 1 ? { tone: 'warning' as const } : {})} />
                <MetricTile label="Median job time" value={lat?.p50 == null ? '—' : formatDuration(lat.p50)} note={lat ? (lat.n ? `95th percentile ${formatDuration(lat.p95)} · max ${formatDuration(lat.max)} · ${lat.n} of the newest ${js?.length} jobs` : 'No job reported a processing time') : 'Unavailable'} />
                <MetricTile label="Model tokens" tone="ai" value={tok ? (tok.withTokens ? formatNumber(tok.total) : 'Not reported') : '—'} note={tok ? (tok.withTokens ? `${tok.withTokens} of the newest ${tok.jobs} jobs reported tokens` : `${tok.modelCalls} model call(s); the scripted model reports no token counts`) : 'Unavailable'} />
              </section>
              <div className="grid grid-main">
                <Card>
                  <CardHeader title="Alert volume over time" description={rows && total !== undefined ? `Alerts per UTC day among the newest ${rows.length} of ${formatNumber(total)} in this range (${RANGES[range].toLowerCase()}).` : undefined} />
                  <CardBody>{!days ? <p className="muted">Unavailable: the alert list could not be loaded.</p> : days.buckets.length === 0 ? <p className="muted">No alerts in this range.</p> : <ColumnChart points={days.buckets.map((b) => ({ key: b.day, label: b.label, value: b.value }))} label="Alerts per day" unit="alerts" />}</CardBody>
                </Card>
                <Card>
                  <CardHeader title="Severity (exact)" description="Model severity across all cases." />
                  <CardBody>{ov ? <Donut rows={sev(ov.by_severity)} label="Cases by severity" centre="cases" /> : <p className="muted">Unavailable.</p>}</CardBody>
                </Card>
              </div>
              <div className="grid grid-3">
                <Card><CardHeader title="Risk (exact)" /><CardBody>{ov ? <BarList rows={sev(ov.by_risk)} label="Cases by risk" /> : <p className="muted">Unavailable.</p>}</CardBody></Card>
                <Card><CardHeader title="Case status (exact)" /><CardBody>{ov ? <BarList rows={rowsFromCounts(ov.by_status, ['escalated', 'needs_review', 'resolved', 'auto_closed'], humanize)} label="Cases by status" /> : <p className="muted">Unavailable.</p>}</CardBody></Card>
                <Card><CardHeader title="Routing (exact)" /><CardBody>{ov ? <Donut rows={rowsFromCounts(ov.by_routing, ['escalate', 'needs_review', 'auto_close'], humanize)} label="Cases by routing" centre="cases" /> : <p className="muted">Unavailable.</p>}</CardBody></Card>
              </div>
              <div className="grid grid-3">
                <Card>
                  <CardHeader title="Attack types" description={rows ? `Among the newest ${rows.length} cases in this range.` : undefined} />
                  <CardBody>{rows ? <BarList rows={topRows(rowsFromCounts(countBy(rows, (c) => c.attack_type)), 8).map((r) => ({ ...r, label: r.key === 'unavailable' ? 'Unavailable (no verdict)' : r.label }))} label="Attack types" empty="No cases in this range." /> : <p className="muted">Unavailable.</p>}</CardBody>
                </Card>
                <Card><CardHeader title="Jobs (exact)" description="By current status." /><CardBody>{ov ? <BarList rows={rowsFromCounts(ov.jobs, ['succeeded', 'running', 'queued', 'failed', 'timed_out'], humanize)} label="Jobs by status" empty="No jobs yet." /> : <p className="muted">Unavailable.</p>}</CardBody></Card>
                <Card><CardHeader title="Verdict health (exact)" description="Whether the model's answer could be used." /><CardBody>{ov ? <BarList rows={rowsFromCounts(ov.by_verdict_status, ['ok', 'parse_failed', 'model_error', 'missing'], humanize)} label="Verdict health" /> : <p className="muted">Unavailable.</p>}</CardBody></Card>
              </div>
              <Card>
                <CardHeader title="What this page does not show" />
                <CardBody>
                  <ul className="bullets">
                    <li>No detection accuracy, no improvement over a baseline and no time saved: those need labelled data and a measured baseline, which live in the Reports page's evaluation documents, not in live traffic.</li>
                    <li>No trend arrows or period-over-period change: the API stores no history of these counts, so none is invented.</li>
                    <li>Processing time covers the newest {SAMPLE} jobs at most; token counts appear only when a real model reported them.</li>
                  </ul>
                </CardBody>
              </Card>
            </>
          );
        }}
      </Async>
    </>
  );
}
