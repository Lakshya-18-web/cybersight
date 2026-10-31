import { api } from '../api';
import type { ThreatIntelRecord } from '../api/types';
import { Radar, RefreshCw } from '../components/icons';
import { Badge } from '../components/ui/Badge';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { BarList } from '../components/ui/Charts';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { KeyValue } from '../components/ui/KeyValue';
import { PageHeader } from '../components/ui/PageHeader';
import { Async, EmptyState } from '../components/ui/State';
import { Time } from '../components/ui/Time';
import { CasePicker } from '../features/cases/CasePicker';
import { useResource } from '../hooks/useResource';
import { rowsFromCounts } from '../lib/chartData';
import { formatNumber, humanize } from '../lib/format';
import { UUID_RE } from '../lib/ids';
import { Link, useSearchParams } from '../lib/router';
import { describeRecord } from '../lib/threatIntel';

function Records({ records }: { records: readonly ThreatIntelRecord[] }) {
  return (
    <div className="table-wrap">
      <table className="table" data-stack="true" data-density="compact">
        <caption className="visually-hidden">Reputation lookups for this case</caption>
        <thead><tr><th scope="col">Indicator</th><th scope="col">Role</th><th scope="col">Result</th><th scope="col">Source</th><th scope="col">Checked</th></tr></thead>
        <tbody>
          {records.map((r, i) => {
            const v = describeRecord(r);
            return (
              <tr key={`${r.ip}-${i}`}>
                <td data-label="Indicator" className="mono">{r.ip}</td>
                <td data-label="Role">{humanize(r.role ?? '')}</td>
                <td data-label="Result"><Badge tone={v.tone}>{v.headline}</Badge>{v.detail ? <div className="muted">{v.detail}</div> : null}
                  {v.hasScore && r.reputation?.country_code ? <div className="muted">{r.reputation.country_code}{r.reputation.usage_type ? ` · ${r.reputation.usage_type}` : ''}</div> : null}</td>
                <td data-label="Source">{r.provider ?? r.source ?? <span className="muted">—</span>}</td>
                <td data-label="Checked"><Time value={r.checked_at} absolute /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function CaseIntel({ caseId }: { caseId: string }) {
  const res = useResource((s) => api.caseAnalysis(caseId, { signal: s }), [caseId]);
  return (
    <Async resource={res}>
      {(a) => {
        const ti = a.evidence_classes.external_enrichment.threat_intel;
        const m = a.mitre;
        return (
          <div className="stack">
            <Card>
              <CardHeader title="Reputation lookups" description={<>Case <Link to={`/cases/${caseId}`}>{a.case.alert_id}</Link> · lookup status: {humanize(ti.status)}</>} />
              {ti.records.length === 0 ? <EmptyState icon={Radar} title="No lookup was recorded for this case">{ti.reason ?? 'The enrichment provider is not configured, or the addresses were private or not eligible.'} A missing result is not a clean result.</EmptyState> : <Records records={ti.records} />}
            </Card>
            <Card>
              <CardHeader title="MITRE ATT&CK mapping" description="The model's technique (a hypothesis) next to the reference text the agents looked up." />
              <CardBody>
                <KeyValue items={[['Model technique', m.model_technique ?? 'None given'], ['Where it came from', humanize(m.from)], ['Reference entries', m.reference.length ? m.reference.map((f) => f.statement ?? '').filter(Boolean).join(' · ') : 'None']]} />
                {m.note ? <p className="muted">{m.note}</p> : null}
              </CardBody>
            </Card>
          </div>
        );
      }}
    </Async>
  );
}

/** Threat intelligence as the pipeline records it. Provider status and 24-hour lookup outcomes come from GET /providers; indicators and MITRE mappings are per case. There is no feed, geolocation or score here that the pipeline did not store. */
export function ThreatIntelPage() {
  const [params, setParams] = useSearchParams();
  const caseId = params.get('case') ?? '';
  const prov = useResource((s) => api.providers({ signal: s }), []);
  return (
    <>
      <PageHeader title="Threat Intelligence" description="External enrichment recorded in cases: provider status, lookup outcomes and per-case indicators. A private, reserved-range or unavailable result is shown as exactly that, never as a clean or confirmed-malicious verdict."
        actions={<Button icon={RefreshCw} onClick={prov.reload} loading={prov.refreshing}>Refresh</Button>} />
      <Async resource={prov}>
        {(p) => {
          const s = p.threat_intel.status;
          const known = typeof s.configured === 'boolean';
          const by = p.threat_intel.lookups_last_24h;
          return (
            <div className="grid grid-2">
              <Card>
                <CardHeader title="Provider" description="Optional: enrichment can raise caution, never lower it." />
                <CardBody>
                  {!known ? <Banner tone="info" title="Integration not known to the API process">{s.note ?? 'The worker holds the threat-intelligence settings.'}</Banner>
                    : s.configured === false ? <Banner tone="info" title="Integration not configured">No lookups are made; cases are analysed without it.</Banner> : null}
                  <KeyValue items={[
                    ['Provider', s.provider ?? '—'],
                    ['Enabled for', p.threat_intel.enabled_for ? p.threat_intel.enabled_for.map(humanize).join(', ') : null],
                    ['Daily budget', known && s.daily_budget !== undefined ? `${formatNumber(s.used_last_24h ?? 0)} of ${formatNumber(s.daily_budget)} used in the last 24 h` : null],
                    ['Last successful lookup', by.last_lookup_at ? <Time key="t" value={by.last_lookup_at} absolute /> : 'None recorded'],
                  ]} />
                </CardBody>
              </Card>
              <Card>
                <CardHeader title={`Lookup outcomes, last ${by.hours} h`} description="From stored cases." />
                <CardBody><BarList rows={rowsFromCounts(by.by_status, undefined, humanize)} label="Lookup outcomes" empty="No lookups were recorded in this period." /></CardBody>
              </Card>
            </div>
          );
        }}
      </Async>
      <Card><CardBody><p className="section-note">Indicators are read per case: choose one below. The API has no list of all indicators, so none is shown here.</p></CardBody></Card>
      <CasePicker caseId={caseId} onPick={(id) => setParams({ case: id || null }, { replace: false })} submitLabel="Show intelligence" />
      {UUID_RE.test(caseId) ? <CaseIntel key={caseId} caseId={caseId} /> : <Card><EmptyState icon={Radar} title="Choose a case">Pick a recent case to see its indicators and MITRE mapping.</EmptyState></Card>}
    </>
  );
}
