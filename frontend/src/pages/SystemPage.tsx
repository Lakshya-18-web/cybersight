import { useState, type ReactNode } from 'react';
import { api } from '../api';
import type { Diagnostics, ProviderHealth, SensorStats } from '../api/types';
import { RefreshCw } from '../components/icons';
import { Badge } from '../components/ui/Badge';
import { ErrorBanner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { KeyValue } from '../components/ui/KeyValue';
import { PageHeader } from '../components/ui/PageHeader';
import { Async } from '../components/ui/State';
import { Tabs, panelId, tabId } from '../components/ui/Tabs';
import { Time } from '../components/ui/Time';
import { useResource } from '../hooks/useResource';
import { formatDuration, formatNumber, humanize } from '../lib/format';

const TABS = [{ id: 'providers', label: 'Providers & queue' }, { id: 'diagnostics', label: 'Diagnostics' }] as const;

function Dot({ state, children }: { state: 'ok' | 'warn' | 'down' | 'unknown'; children: ReactNode }) {
  return <span><span className="status-dot" data-state={state} aria-hidden="true" />{children}</span>;
}

function counts(c: Record<string, number> | undefined): string {
  const e = Object.entries(c ?? {});
  return e.length ? e.map(([k, n]) => `${humanize(k)} ${formatNumber(n)}`).join(' · ') : 'none';
}

function Providers({ p, sensors }: { p: ProviderHealth; sensors: SensorStats | undefined }) {
  const ti = p.threat_intel;
  const tis = ti.status;
  const known = typeof tis.configured === 'boolean';
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Language model" description="Verdicts are hypotheses; the model can never approve or execute anything." />
          <CardBody>
            <KeyValue items={[
              ['Mode', <Dot key="m" state={p.model.mode === 'live' ? 'ok' : 'warn'}>{humanize(p.model.mode)}{p.model.mode === 'fake' ? ' (no model is called)' : ''}</Dot>],
              ['Live calls allowed', p.model.live_calls_allowed ? 'Yes' : 'No'],
              ['Configured model', p.model.configured_model ?? 'Not applicable'],
              ['Live check', <Dot key="s" state="unknown">Not checked: {p.model.status_note ?? 'the API does not call the model to test it'}</Dot>],
              ['Verdicts stored', counts(p.model.verdicts_by_status)],
              ['Model errors stored', formatNumber(p.model.model_errors_total)],
            ]} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Threat intelligence" description="Optional enrichment. It can raise caution; it can never lower it." />
          <CardBody>
            <KeyValue items={[
              ['Provider', tis.provider ?? 'AbuseIPDB'],
              ['Configured', <Dot key="c" state={tis.configured === true ? 'ok' : 'unknown'}>{known ? (tis.configured ? 'Yes' : 'No: lookups are off, cases are analysed without it') : 'Not known to the API process'}</Dot>],
              ...(!known && tis.note ? [['Why', tis.note] as const] : []),
              ['Enabled for', ti.enabled_for ? ti.enabled_for.map(humanize).join(', ') : null],
              ['Daily budget', known && tis.daily_budget !== undefined ? `${formatNumber(tis.used_last_24h ?? 0)} of ${formatNumber(tis.daily_budget)} used in the last 24 hours` : null],
              ['Timeout', tis.timeout_seconds === undefined ? null : `${tis.timeout_seconds} s`],
              ['Cache', tis.cache_entries === undefined ? null : `${formatNumber(tis.cache_entries)} entries, kept ${formatDuration(tis.cache_ttl_seconds ?? null)}`],
              [`Lookups in cases, last ${ti.lookups_last_24h.hours} h`, counts(ti.lookups_last_24h.by_status)],
              ['Last successful lookup', ti.lookups_last_24h.last_lookup_at ? <Time key="l" value={ti.lookups_last_24h.last_lookup_at} absolute /> : 'None recorded'],
            ]} />
          </CardBody>
        </Card>
      </div>
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Queue and database" />
          <CardBody>
            <KeyValue items={[
              ['Queue backend', p.queue.backend],
              ['Broker', <Dot key="b" state={p.queue.broker_ready ? 'ok' : 'down'}>{p.queue.broker_ready ? 'Ready' : `Not ready${p.queue.detail ? `: ${p.queue.detail}` : ''}`}</Dot>],
              ['Database', <Dot key="d" state={p.database.reachable ? 'ok' : 'down'}>{p.database.reachable ? 'Reachable' : 'Not reachable'}</Dot>],
              ['Workers', <Dot key="w" state="unknown">Unavailable: {p.workers.reason ?? 'the API cannot see worker heartbeats'}</Dot>],
            ]} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Jobs" description="Counts by status, with the age of the oldest job in each." />
          <CardBody>
            {Object.keys(p.jobs).length === 0 ? <p className="muted">No jobs yet.</p> : (
              <ul role="list" className="stack-sm">
                {Object.entries(p.jobs).map(([k, v]) => (
                  <li key={k} className="row-between"><span>{humanize(k)}</span><span className="num">{formatNumber(v.count)}{v.oldest_age_seconds !== null ? <span className="muted"> · oldest {formatDuration(v.oldest_age_seconds)}</span> : null}</span></li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Sensor ingestion" description="Suricata EVE events received through the authenticated ingestion endpoint." />
        <CardBody>
          {sensors === undefined ? <p className="muted">Unavailable: the sensor counts could not be loaded.</p> : (
            <KeyValue items={[
              ['Sensors that have sent events', formatNumber(sensors.sensors)],
              ['Stored events', `${formatNumber(sensors.events)} (${formatNumber(sensors.alerts)} alerts, ${formatNumber(sensors.flows)} flows)`],
              ['Last event received', sensors.last_received_at ? <Time key="t" value={sensors.last_received_at} absolute /> : 'None yet'],
            ]} />
          )}
        </CardBody>
      </Card>
    </div>
  );
}

function Diag({ d }: { d: Diagnostics }) {
  const chain = d.audit_chain;
  const chainState = chain.ok === true ? 'ok' : chain.ok === false ? 'down' : 'unknown';
  const mig = d.migrations;
  return (
    <div className="stack">
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Versions and policies" />
          <CardBody>
            <KeyValue items={[
              ...Object.entries(d.versions).map(([k, v]) => [humanize(k), v] as const),
              ['Risk policy', d.policies.risk_policy ? <span key="r">{d.policies.risk_policy.version} <span className="hash">{d.policies.risk_policy.sha256}</span></span> : (d.policies.error ?? null)],
              ['Evidence policy', d.policies.evidence_policy ? <span key="e">{d.policies.evidence_policy.version} <span className="hash">{d.policies.evidence_policy.sha256}</span></span> : null],
              ['Authentication', humanize(d.auth_mode)],
            ]} />
          </CardBody>
        </Card>
        <Card>
          <CardHeader title="Integrity" />
          <CardBody>
            <KeyValue items={[
              ['Audit hash chain', <Dot key="a" state={chainState}>{chain.ok === true ? 'Verified: no break found' : chain.ok === false ? `Broken at event ${String(chain.first_bad_event_id ?? '?')}` : `Not checked${chain.reason ? `: ${chain.reason}` : ''}`}</Dot>],
              ['Migrations', mig.status === 'unavailable' ? `Unavailable: ${mig.reason ?? ''}` : `${mig.week4?.length ?? 0} base, ${mig.week5?.length ?? 0} extension`],
            ]} />
            {mig.week5 && mig.week5.length ? <ul className="bullets">{mig.week5.map((m) => <li key={String(m[0])}>{String(m[0])} {String(m[1] ?? '')}</li>)}</ul> : null}
          </CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Settings" description="Non-secret settings only. Keys, tokens and passwords are never returned by the API." />
        <CardBody>
          <KeyValue items={Object.entries(d.settings).map(([k, v]) => [humanize(k), <code key={k}>{typeof v === 'object' ? JSON.stringify(v) : String(v)}</code>] as const)} />
        </CardBody>
      </Card>
    </div>
  );
}

export function SystemPage() {
  const [tab, setTab] = useState<string>('providers');
  const providers = useResource((s) => api.providers({ signal: s }), []);
  const sensors = useResource((s) => api.sensors({ signal: s }), []);
  const diag = useResource((s) => api.diagnostics({ signal: s }), []);
  const reload = () => { providers.reload(); sensors.reload(); diag.reload(); };
  return (
    <>
      <PageHeader title="System" description="Health of the services the pipeline depends on, and the versions and checks behind it. Read from the API; nothing here is simulated."
        actions={<Button icon={RefreshCw} onClick={reload} loading={providers.refreshing || diag.refreshing}>Refresh</Button>} />
      <Tabs tabs={TABS} value={tab} onChange={setTab} prefix="sys" label="System sections" />
      <div role="tabpanel" id={panelId('sys', 'providers')} aria-labelledby={tabId('sys', 'providers')} hidden={tab !== 'providers'}>
        <Async resource={providers}>{(p) => <Providers p={p} sensors={sensors.data} />}</Async>
        {providers.data && sensors.error ? <ErrorBanner error={sensors.error} onRetry={sensors.reload} /> : null}
        {providers.data ? <Badge>Not a live probe of the model or threat-intelligence provider</Badge> : null}
      </div>
      <div role="tabpanel" id={panelId('sys', 'diagnostics')} aria-labelledby={tabId('sys', 'diagnostics')} hidden={tab !== 'diagnostics'}>
        <Async resource={diag}>{(d) => <Diag d={d} />}</Async>
      </div>
    </>
  );
}
