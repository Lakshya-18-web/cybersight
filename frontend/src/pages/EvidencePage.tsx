import { api } from '../api';
import { Banner } from '../components/ui/Banner';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { PageHeader } from '../components/ui/PageHeader';
import { Async, EmptyState } from '../components/ui/State';
import { FileSearch } from '../components/icons';
import { Enrichment, EvidenceLegend, Hypothesis, Observed, Policy } from '../features/cases/AnalysisView';
import { CasePicker } from '../features/cases/CasePicker';
import { EvidenceView } from '../features/cases/EvidenceView';
import { useResource } from '../hooks/useResource';
import { UUID_RE } from '../lib/ids';
import { Link, useSearchParams } from '../lib/router';

function CaseEvidence({ caseId }: { caseId: string }) {
  const analysis = useResource((s) => api.caseAnalysis(caseId, { signal: s }), [caseId]);
  const raw = useResource((s) => api.caseEvidence(caseId, { signal: s }), [caseId]);
  return (
    <div className="stack">
      <Async resource={analysis}>
        {(c) => (
          <>
            <p>Case <Link to={`/cases/${caseId}`}>{c.case.alert_id}</Link>: the four kinds of evidence, kept apart.</p>
            <EvidenceLegend />
            <Observed a={c} />
            <Enrichment a={c} />
            <Hypothesis a={c} />
            <Policy a={c} reload={analysis.reload} />
          </>
        )}
      </Async>
      <Card>
        <CardHeader title="Investigation steps" description="Each step the agents took and what they found, in order, with the stored payloads." />
        <CardBody>
          <Async resource={raw}>{(d) => d.items.length ? <EvidenceView items={d.items} /> : <EmptyState title="No evidence recorded">The agents stored no evidence steps for this case.</EmptyState>}</Async>
        </CardBody>
      </Card>
    </div>
  );
}

/** Evidence is stored per case. This page opens it for the case you choose; it never lists evidence across cases because the API has no such feed. */
export function EvidencePage() {
  const [params, setParams] = useSearchParams();
  const caseId = params.get('case') ?? '';
  return (
    <>
      <PageHeader title="Evidence" description="Observed telemetry, enrichment, the model's interpretation and the policy decision for one case, with the raw investigation steps." />
      <Banner tone="info" title="Evidence is read one case at a time">The API stores evidence per case and has no feed across cases, so choose a case below. Where no flow or enrichment record exists, the page says so instead of showing a placeholder.</Banner>
      <CasePicker caseId={caseId} onPick={(id) => setParams({ case: id || null }, { replace: false })} submitLabel="Show evidence" />
      {UUID_RE.test(caseId) ? <CaseEvidence key={caseId} caseId={caseId} /> : <Card><EmptyState icon={FileSearch} title="Choose a case">Pick a recent case or paste its id.</EmptyState></Card>}
    </>
  );
}
