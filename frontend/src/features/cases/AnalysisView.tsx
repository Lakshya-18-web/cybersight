import type { ReactNode } from 'react';
import type { CaseAnalysis, Finding, FlowToolCall, SpecialistFindings, ThreatIntelRecord } from '../../api/types';
import { Badge, RiskBadge, RoutingBadge, SeverityBadge } from '../../components/ui/Badge';
import { Banner } from '../../components/ui/Banner';
import { Card, CardBody, CardHeader } from '../../components/ui/Card';
import { JsonView } from '../../components/ui/JsonView';
import { KeyValue } from '../../components/ui/KeyValue';
import { Time } from '../../components/ui/Time';
import { formatNumber, humanize, shortId } from '../../lib/format';
import { Link } from '../../lib/router';
import { describeRecord } from '../../lib/threatIntel';
import { ActionCard } from './ActionCard';

type EvidenceClass = 'observed' | 'enrichment' | 'hypothesis' | 'policy';

/** One of the four kinds of information, always labelled in words as well as by the coloured edge. */
export function ClassCard({ kind, tag, title, description, children }: { kind: EvidenceClass; tag: string; title: string; description?: string | undefined; children: ReactNode }) {
  return (
    <Card className={`evidence-class evidence-${kind}`}>
      <CardHeader title={<><span className="class-tag">{tag}</span> {title}</>} {...(description ? { description } : {})} />
      <CardBody>{children}</CardBody>
    </Card>
  );
}

export function EvidenceLegend() {
  return (
    <p className="legend" aria-label="The four kinds of information on this page">
      <span><strong>Observed</strong>: what the sensor reported and the flow records show.</span>
      <span><strong>External enrichment</strong>: reference tables and threat intelligence; context only.</span>
      <span><strong>Model hypothesis</strong>: a language model's reading; not evidence.</span>
      <span><strong>Policy decision</strong>: fixed rules and the proposals they led to.</span>
    </p>
  );
}

function Statements({ findings }: { findings: readonly Finding[] | undefined }) {
  const list = (findings ?? []).filter((f) => typeof f.statement === 'string');
  if (list.length === 0) return null;
  return <ul className="bullets">{list.map((f, i) => <li key={i}>{f.statement}</li>)}</ul>;
}

function Specialist({ title, s }: { title: string; s: SpecialistFindings | null | undefined }) {
  if (!s) return <div><div className="field-label">{title}</div><p className="muted">Unavailable: this analyst did not run or its result was not stored.</p></div>;
  return (
    <div className="stack-sm">
      <div className="row"><div className="field-label">{title}</div>{s.status ? <Badge tone={s.status === 'ok' ? 'neutral' : 'warning'}>{humanize(s.status)}</Badge> : null}
        {typeof s.beacon_candidate === 'boolean' ? <Badge tone={s.beacon_candidate ? 'warning' : 'neutral'}>{s.beacon_candidate ? 'Beacon candidate' : 'Not a beacon candidate'}</Badge> : null}</div>
      <Statements findings={s.findings} />
      {s.limits?.length ? <details className="details"><summary>Limits of this analysis</summary><ul className="bullets">{s.limits.map((l, i) => <li key={i}>{l}</li>)}</ul></details> : null}
    </div>
  );
}

function FlowCalls({ calls }: { calls: readonly FlowToolCall[] }) {
  if (calls.length === 0) return <p className="muted">No flow queries were recorded for this case.</p>;
  return (
    <div className="table-wrap">
      <table className="table" data-stack="true" data-density="compact">
        <caption className="visually-hidden">Flow queries made by the analysis agents</caption>
        <thead><tr><th scope="col">Query</th><th scope="col">Result</th><th scope="col" className="num">Flows</th><th scope="col">Arguments</th></tr></thead>
        <tbody>
          {calls.map((c, i) => (
            <tr key={i}>
              <td data-label="Query" className="mono">{c.tool}</td>
              <td data-label="Result">{c.ok ? <Badge tone="success">Answered</Badge> : <Badge tone="warning">{c.error_code ? humanize(c.error_code) : 'Failed'}</Badge>}</td>
              <td data-label="Flows" className="num">{c.n_flows === null || c.n_flows === undefined ? '—' : formatNumber(c.n_flows)}</td>
              <td data-label="Arguments" className="mono">{c.arguments ? Object.entries(c.arguments).map(([k, v]) => `${k}=${String(v)}`).join(' ') : '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Observed({ a }: { a: CaseAnalysis }) {
  const o = a.evidence_classes.observed;
  const s = o.sensor;
  const alert = o.alert;
  const missing = o.unavailable_fields ?? [];
  return (
    <ClassCard kind="observed" tag="Observed" title="What the sensor and the flow records show" description={o.description}>
      <div className="stack">
        {s ? (
          <KeyValue items={[
            ['Sensor', s.sensor ?? null],
            ['Rule', s.display?.signature ? `${s.display.signature} (sid ${s.signature_id ?? '?'} rev ${s.rev ?? '?'})` : s.signature_id !== undefined ? `sid ${s.signature_id}` : null],
            ['Category', s.display?.category ?? s.category ?? null],
            ['Sensor severity', s.severity === undefined ? null : `${s.severity} (1 is the most severe)`],
            ['Action taken by the sensor', s.action ?? null],
            ['Application protocol', s.app_proto ?? null],
            ['Event time', <Time key="et" value={s.event_time} absolute />],
            ['Received', <Time key="rt" value={s.received_at} absolute />],
            ['Linked flow', s.flow_linked ? `Yes (${s.flow_source ?? 'flow event'}, ${formatNumber(s.flows_in_window ?? 0)} flows in the window)` : 'No flow record was linked to this alert'],
            ['Adapter', s.adapter_version ?? null],
          ]} />
        ) : <p className="muted">This case did not come from a sensor event, so there is no sensor record. The fields below are what was submitted.</p>}
        <KeyValue items={[
          ['Source', `${String(alert.src_ip ?? '—')}:${String(alert.src_port ?? '—')}`],
          ['Destination', `${String(alert.dst_ip ?? '—')}:${String(alert.dst_port ?? '—')}`],
          ['Protocol', alert.protocol === null || alert.protocol === undefined ? null : String(alert.protocol)],
          ['Timestamp', alert.timestamp === null || alert.timestamp === undefined ? null : String(alert.timestamp)],
          ['Detector score', alert.detector_score === null || alert.detector_score === undefined ? 'Unavailable: no detector scored this alert' : String(alert.detector_score)],
        ]} />
        {missing.length ? (
          <Banner tone="info" title="Fields the source did not provide">
            <div className="chip-row">{missing.map((m) => <Badge key={m}>{m}</Badge>)}</div>
            <p>These were not estimated or filled in; they are shown as unavailable.</p>
          </Banner>
        ) : null}
        <Specialist title="Traffic analyst" s={o.specialist_findings.traffic_analyst} />
        <Specialist title="Command-and-control timing analyst" s={o.specialist_findings.c2_beacon_analyst} />
        <div><div className="field-label">Flow queries behind those findings</div><FlowCalls calls={o.flow_tool_calls} /></div>
        <JsonView value={alert} label="All alert fields (raw)" />
      </div>
    </ClassCard>
  );
}

function IntelRow({ r }: { r: ThreatIntelRecord }) {
  const v = describeRecord(r);
  return (
    <tr>
      <td data-label="Address" className="mono">{r.ip}</td>
      <td data-label="Role">{r.role === 'src' ? 'Source' : r.role === 'dst' ? 'Destination' : r.role ?? '—'}</td>
      <td data-label="Answer"><Badge tone={v.tone}>{v.headline}</Badge>{v.detail ? <div className="muted">{v.detail}</div> : null}</td>
      <td data-label="Details">{r.reputation ? <span>{r.reputation.country_code ?? '—'}{r.reputation.usage_type ? ` · ${r.reputation.usage_type}` : ''}{r.reputation.last_reported_at ? ` · last reported ${r.reputation.last_reported_at.slice(0, 10)}` : ''}</span> : <span className="muted">—</span>}</td>
      <td data-label="Checked"><Time value={r.checked_at} absolute /></td>
    </tr>
  );
}

export function Enrichment({ a }: { a: CaseAnalysis }) {
  const e = a.evidence_classes.external_enrichment;
  const ti = e.threat_intel;
  const ref = e.reference_context;
  const refFindings = (ref?.findings ?? []).filter((f) => f.kind !== 'mitre_search_hit' && f.kind !== 'mitre_reference');
  return (
    <ClassCard kind="enrichment" tag="External enrichment" title="Reference tables and threat intelligence" description={e.description}>
      <div className="stack">
        <div>
          <div className="field-label">Threat intelligence{ti.records[0]?.provider ? ` (${ti.records[0].provider})` : ''}</div>
          {ti.records.length === 0 ? (
            <p className="muted">{ti.status === 'not_enabled' ? 'Not used for this case. ' : 'Nothing recorded. '}{ti.reason ?? ''}</p>
          ) : (
            <div className="table-wrap">
              <table className="table" data-stack="true" data-density="compact">
                <caption className="visually-hidden">Reputation lookups for the addresses in this alert</caption>
                <thead><tr><th scope="col">Address</th><th scope="col">Role</th><th scope="col">Answer</th><th scope="col">Details</th><th scope="col">Checked</th></tr></thead>
                <tbody>{ti.records.map((r, i) => <IntelRow key={`${r.ip}-${i}`} r={r} />)}</tbody>
              </table>
            </div>
          )}
          <p className="muted">Scores come from a third party and can be wrong or out of date. They are never shown to the model; the policy treats a missing, failed or zero answer as neutral, so it can never lower caution.</p>
        </div>
        <div>
          <div className="field-label">Reference context (offline tables)</div>
          {ref === null ? <p className="muted">Unavailable: the enrichment step did not run or its result was not stored.</p> : refFindings.length === 0 ? <p className="muted">The reference tables had nothing to add.</p> : <Statements findings={refFindings} />}
        </div>
      </div>
    </ClassCard>
  );
}

export function Hypothesis({ a }: { a: CaseAnalysis }) {
  const m = a.evidence_classes.model_hypothesis;
  const v = m.verdict;
  return (
    <ClassCard kind="hypothesis" tag="Model hypothesis" title="What the language model concluded" description={m.description}>
      <div className="stack">
        {m.fake_model ? <Banner tone="warning" title="Produced by the offline fake model">The text below is canned plumbing output, not an analysis.</Banner> : null}
        {v ? (
          <>
            <KeyValue items={[
              ['Attack type', v.attack_type],
              ['Malicious', v.is_malicious === null ? null : v.is_malicious ? 'Yes' : 'No'],
              ['Severity', <SeverityBadge key="s" severity={v.severity} />],
              ['MITRE technique', v.mitre_technique],
              ['Verdict status', humanize(v.status)],
              ...(v.error_code ? [['Error code', v.error_code] as const] : []),
              ['Model', m.model ?? v.model],
              ['Prompt', m.prompt_version ?? v.prompt_version],
            ]} />
            {v.evidence_text ? <div><div className="field-label">Model rationale (untrusted text)</div><blockquote className="codeblock">{v.evidence_text}</blockquote></div> : null}
          </>
        ) : <p className="muted">No verdict was recorded for this case.</p>}
      </div>
    </ClassCard>
  );
}

export function Policy({ a, reload }: { a: CaseAnalysis; reload: () => void }) {
  const p = a.evidence_classes.policy_decision;
  const r = p.routing;
  const ep = p.evidence_policy;
  return (
    <ClassCard kind="policy" tag="Policy decision" title="Rules applied after the model, and what they led to" description={p.description}>
      <div className="stack">
        {r ? (
          <KeyValue items={[
            ['Decision', <RoutingBadge key="d" decision={r.decision} />],
            ['Risk level', <RiskBadge key="r" risk={r.risk_level} />],
            ['Policy', r.policy_version],
            ['Decided', <Time key="t" value={r.decided_at} absolute />],
          ]} />
        ) : <p className="muted">No routing decision was recorded.</p>}
        {r?.reasons.length ? <div><div className="field-label">Reasons</div><ul className="bullets">{r.reasons.map((x, i) => <li key={i}>{x}</li>)}</ul></div> : null}
        {ep ? (
          <div className="stack-sm">
            <div className="field-label">Evidence policy {ep.version ?? ''}</div>
            <p>{ep.raised ? <>Raised caution from <strong>{humanize(ep.decision_before)}</strong> to <strong>{humanize(ep.decision_after)}</strong>.</> : 'Did not change the decision.'} Rules checked: {(ep.rules_checked ?? []).join(', ') || '—'}.</p>
            {ep.fired?.length ? <ul className="bullets">{ep.fired.map((f) => <li key={f.rule}><strong>{f.rule} {humanize(f.name)}</strong> ({humanize(f.source)}): {f.detail}</li>)}</ul> : <p className="muted">No evidence rule applied.</p>}
            <p className="muted">These rules can only raise caution, never lower it. A threat-intelligence score alone can never close a case.</p>
          </div>
        ) : <p className="muted">No evidence-policy record was stored for this case.</p>}
        {p.guard_signals.length ? (
          <Banner tone="warning" title="Safety signals raised while handling this alert"><JsonView value={p.guard_signals} label="Signals" /></Banner>
        ) : <p className="muted">No safety signals were raised (for example, instruction-like text in an alert field).</p>}
        <div>
          <div className="field-label">Proposed actions</div>
          {p.actions.length === 0 ? <p className="muted">The policy did not propose a containment or monitoring step. The model never proposes or executes actions.</p>
            : <div>{p.actions.map((x) => <ActionCard key={x.action_id} action={x} onChanged={reload} />)}</div>}
        </div>
      </div>
    </ClassCard>
  );
}

export function Mitre({ a }: { a: CaseAnalysis }) {
  const m = a.mitre;
  // One row per technique: the keyword search and the reference lookup often return the same entry.
  const byTechnique = new Map<string, { metrics: Record<string, unknown>; how: Set<string> }>();
  for (const h of m.reference ?? []) {
    const mt = h.metrics ?? {};
    const key = String(mt.technique_id ?? `unknown-${byTechnique.size}`);
    const row = byTechnique.get(key) ?? { metrics: mt, how: new Set<string>() };
    row.how.add(h.kind === 'mitre_search_hit' ? 'Keyword search hit' : 'Reference entry');
    byTechnique.set(key, row);
  }
  const hits = [...byTechnique.values()];
  return (
    <Card>
      <CardHeader title="MITRE ATT&CK" description={m.note ?? 'Reference material found by a keyword search; not a determination.'} />
      <CardBody>
        <div className="stack">
          <KeyValue items={[['Technique named by the model (hypothesis)', m.model_technique && m.model_technique !== 'NONE' ? m.model_technique : 'None named']]} />
          {hits.length === 0 ? <p className="muted">No ATT&CK reference entries were retrieved for this case.</p> : (
            <div className="table-wrap">
              <table className="table" data-stack="true" data-density="compact">
                <caption className="visually-hidden">ATT&CK reference entries retrieved for this alert</caption>
                <thead><tr><th scope="col">Technique</th><th scope="col">Name</th><th scope="col">Tactics</th><th scope="col">How it was found</th></tr></thead>
                <tbody>
                  {hits.map((h, i) => {
                    const mt = h.metrics;
                    return (
                      <tr key={i}>
                        <td data-label="Technique" className="mono">{String(mt.technique_id ?? '—')}</td>
                        <td data-label="Name">{String(mt.name ?? '—')}</td>
                        <td data-label="Tactics">{Array.isArray(mt.tactics) ? mt.tactics.join(', ') : '—'}</td>
                        <td data-label="How it was found">{[...h.how].join(' · ')}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </CardBody>
    </Card>
  );
}

export function Provenance({ a }: { a: CaseAnalysis }) {
  const p = a.provenance;
  const job = a.job;
  return (
    <Card>
      <CardHeader title="Provenance" description="What produced this result." />
      <CardBody>
        <KeyValue items={[
          ['Case', <span key="c" className="mono-id">{a.case.case_id}</span>],
          ['Source', humanize(a.case.alert_set)],
          ['Run', <span key="r" className="mono-id">{a.case.run_name}</span>],
          ['Graph', p.graph_version ?? a.case.graph_version],
          ['Risk policy', p.risk_policy ? `${p.risk_policy.version ?? '—'} (${shortId(p.risk_policy.sha256, 12)}…)` : null],
          ['Evidence policy', p.evidence_policy?.version ? `${p.evidence_policy.version} (${shortId(p.evidence_policy.sha256, 12)}…)` : null],
          ['Memory', humanize(a.case.memory_mode)],
          ['Job', job ? <Link key="j" to={`/jobs/${job.job_id}`}>{shortId(job.job_id)} · {humanize(job.status)} · {job.attempts} attempt{job.attempts === 1 ? '' : 's'}</Link> : null],
          ['Created', <Time key="cr" value={a.case.created_at} absolute />],
        ]} />
      </CardBody>
    </Card>
  );
}
