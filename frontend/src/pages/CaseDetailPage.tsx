import { useState, type ReactNode } from 'react';
import { api } from '../api';
import { ArrowLeft, RefreshCw } from '../components/icons';
import { Badge, CaseStatusBadge, RiskBadge, RoutingBadge, SeverityBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CopyButton } from '../components/ui/CopyButton';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { Icon } from '../components/ui/Icon';
import { PageHeader } from '../components/ui/PageHeader';
import { Async, EmptyState, LoadingRows } from '../components/ui/State';
import { Tabs, panelId, tabId } from '../components/ui/Tabs';
import { Time } from '../components/ui/Time';
import { Enrichment, EvidenceLegend, Hypothesis, Mitre, Observed, Policy, Provenance } from '../features/cases/AnalysisView';
import { CaseManagement } from '../features/cases/CaseManagement';
import { EvidenceView, HistoryTimeline, MemoryTable } from '../features/cases/EvidenceView';
import { CaseTimeline } from '../features/cases/Timeline';
import { useResource } from '../hooks/useResource';
import { humanize } from '../lib/format';
import { Link, useParams } from '../lib/router';

type TabId = 'analysis' | 'mitre' | 'timeline' | 'notes' | 'raw' | 'memory';

function Lazy<T>({ load, deps, active, children }: { load: (s: AbortSignal) => Promise<T>; deps: readonly unknown[]; active: boolean; children: (d: T) => ReactNode }) {
  // Loaded the first time its tab is opened, then kept.
  const res = useResource(load, deps, active);
  return <Async resource={res} skeleton={<LoadingRows rows={4} />}>{children}</Async>;
}

export function CaseDetailPage() {
  const { id = '' } = useParams();
  const res = useResource((signal) => api.caseAnalysis(id, { signal }), [id]);
  const [tab, setTab] = useState<TabId>('analysis');
  const [visited, setVisited] = useState<Set<TabId>>(new Set(['analysis']));
  const open = (t: string) => { const next = t as TabId; setTab(next); setVisited((s) => new Set(s).add(next)); };
  const a = res.data;
  const verdict = a?.evidence_classes.model_hypothesis.verdict ?? null;
  const routing = a?.evidence_classes.policy_decision.routing ?? null;
  const tabs = [
    { id: 'analysis', label: 'Summary' },
    { id: 'mitre', label: 'MITRE' },
    { id: 'timeline', label: 'History', count: a ? a.timeline.length : null },
    { id: 'notes', label: 'Notes & feedback', count: a ? a.notes.length + a.feedback.length : null },
    { id: 'raw', label: 'Evidence' },
    { id: 'memory', label: 'Memory' },
  ] as const;

  return (
    <>
      <PageHeader crumbs={[{ label: 'Cases', to: '/cases' }, { label: a ? a.case.alert_id : 'Case' }]} title={a ? a.case.alert_id : 'Case'}
        description={a ? <span className="row"><CaseStatusBadge status={a.case.status} /><SeverityBadge severity={verdict?.severity ?? null} /><RoutingBadge decision={routing?.decision} /><Badge>{humanize(a.case.alert_set)} alert</Badge>
          <Badge>{humanize(a.case.memory_mode)} memory</Badge><span className="muted">Created <Time value={a.case.created_at} /></span></span> : undefined}
        actions={<>
          <Link to="/cases" className="btn" data-variant="ghost"><Icon icon={ArrowLeft} size={16} />Cases</Link>
          <Button icon={RefreshCw} onClick={res.reload} loading={res.refreshing}>Refresh</Button>
        </>} />
      <Async resource={res}>
        {(c) => (
          <>
            <section aria-label="Case summary" className="stack-sm">
              <dl className="summary-strip">
                <div><dt><span className="tag-ai">AI verdict</span></dt><dd>{verdict ? (verdict.status === 'ok' ? (verdict.is_malicious === true ? 'Malicious' : verdict.is_malicious === false ? 'Benign' : 'Unclassified') : humanize(verdict.status)) : 'No verdict'}</dd></div>
                <div><dt>Attack type</dt><dd>{verdict?.attack_type ?? '—'}</dd></div>
                <div><dt>Detector score</dt><dd className="num">{typeof c.evidence_classes.observed.alert.detector_score === 'number' ? c.evidence_classes.observed.alert.detector_score : 'Not provided'}</dd></div>
                <div><dt>Severity (model)</dt><dd><SeverityBadge severity={verdict?.severity ?? null} /></dd></div>
                <div><dt>MITRE technique</dt><dd>{verdict?.mitre_technique ?? 'None given'}</dd></div>
                <div><dt>Policy routing</dt><dd><RoutingBadge decision={routing?.decision} /></dd></div>
                <div><dt>Policy risk</dt><dd><RiskBadge risk={routing?.risk_level} /></dd></div>
                <div><dt>Ids</dt><dd className="mono-id">alert {c.case.alert_id} <CopyButton value={c.case.alert_id} label="alert id" /><br />case {c.case.case_id.slice(0, 8)} <CopyButton value={c.case.case_id} label="case id" />{c.job ? <><br />job <Link to={`/jobs/${c.job.job_id}`}>{c.job.job_id.slice(0, 8)}</Link></> : null}</dd></div>
              </dl>
              <p className="section-note">The AI verdict is a hypothesis from the model. The routing and risk are decided separately by the deterministic policy, which can only raise caution, never lower it.</p>
            </section>
            <Tabs tabs={tabs} value={tab} onChange={open} prefix="case" label="Case sections" />
            <div role="tabpanel" id={panelId('case', 'analysis')} aria-labelledby={tabId('case', 'analysis')} hidden={tab !== 'analysis'}>
              <div className="stack">
                <EvidenceLegend />
                <Observed a={c} />
                <Enrichment a={c} />
                <Hypothesis a={c} />
                <Policy a={c} reload={res.reload} />
                <Provenance a={c} />
              </div>
            </div>
            <div role="tabpanel" id={panelId('case', 'mitre')} aria-labelledby={tabId('case', 'mitre')} hidden={tab !== 'mitre'}>
              <Mitre a={c} />
            </div>
            <div role="tabpanel" id={panelId('case', 'timeline')} aria-labelledby={tabId('case', 'timeline')} hidden={tab !== 'timeline'}>
              <div className="stack">
                <Card>
                  <CardHeader title="Timeline" description="What happened to this case, oldest first." />
                  <CardBody>{c.timeline.length ? <CaseTimeline events={c.timeline} /> : <EmptyState title="No events yet" />}</CardBody>
                </Card>
                <Card>
                  <CardHeader title="Audit trail" description="The tamper-evident record behind the timeline. The hash chain spans the whole log, so only the server can verify it." />
                  <CardBody>
                    <Lazy load={(s) => api.caseHistory(id, { signal: s })} deps={[id, c.case.updated_at, c.timeline.length]} active={visited.has('timeline')}>
                      {(d) => d.events.length ? <HistoryTimeline events={d.events} /> : <EmptyState title="No events yet" />}
                    </Lazy>
                  </CardBody>
                </Card>
              </div>
            </div>
            <div role="tabpanel" id={panelId('case', 'notes')} aria-labelledby={tabId('case', 'notes')} hidden={tab !== 'notes'}>
              <CaseManagement analysis={c} onChanged={res.reload} />
            </div>
            <div role="tabpanel" id={panelId('case', 'raw')} aria-labelledby={tabId('case', 'raw')} hidden={tab !== 'raw'}>
              <Card>
                <CardHeader title="Raw evidence" description="Each step the agents took and what they found, in order, with the stored payloads." />
                <CardBody>
                  <Lazy load={(s) => api.caseEvidence(id, { signal: s })} deps={[id]} active={visited.has('raw')}>
                    {(d) => d.items.length ? <EvidenceView items={d.items} /> : <EmptyState title="No evidence recorded" />}
                  </Lazy>
                </CardBody>
              </Card>
            </div>
            <div role="tabpanel" id={panelId('case', 'memory')} aria-labelledby={tabId('case', 'memory')} hidden={tab !== 'memory'}>
              <Card>
                <CardHeader title="Memory" description="Similar past cases the agent compared this one with." />
                <Lazy load={(s) => api.caseMemory(id, { signal: s })} deps={[id]} active={visited.has('memory')}>
                  {(d) => d.hits.length ? <MemoryTable hits={d.hits} /> : <EmptyState title={d.memory_mode === 'on' ? 'No similar cases were retrieved' : 'Memory was off for this case'}>{d.memory_mode === 'on' ? 'The memory search returned nothing for this alert.' : 'The agent did not look at past cases.'}</EmptyState>}
                </Lazy>
              </Card>
            </div>
          </>
        )}
      </Async>
    </>
  );
}
