import { api } from '../api';
import { Banner } from '../components/ui/Banner';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { CopyButton } from '../components/ui/CopyButton';
import { PageHeader } from '../components/ui/PageHeader';
import { Async, EmptyState } from '../components/ui/State';
import { CasePicker } from '../features/cases/CasePicker';
import { HistoryTimeline } from '../features/cases/EvidenceView';
import { useResource } from '../hooks/useResource';
import { UUID_RE } from '../lib/ids';
import { Link, useSearchParams } from '../lib/router';
import { ScrollText } from '../components/icons';

function CaseAudit({ caseId }: { caseId: string }) {
  const res = useResource((signal) => api.caseHistory(caseId, { signal }), [caseId]);
  return (
    <Card>
      <CardHeader title="Audit trail" description={<>Case <span className="mono-id">{caseId}</span> <CopyButton value={caseId} label="case id" /> · <Link to={`/cases/${caseId}`}>Open the case</Link></>} />
      <CardBody>
        <Async resource={res}>
          {(d) => d.events.length ? <HistoryTimeline events={d.events} /> : <EmptyState icon={ScrollText} title="No events recorded for this case" />}
        </Async>
      </CardBody>
    </Card>
  );
}

export function AuditPage() {
  const [params, setParams] = useSearchParams();
  const caseId = params.get('case') ?? '';
  return (
    <>
      <PageHeader title="Audit Log" description="The tamper-evident event log, one case at a time: who did what, when, with the hash that links each event to the one before it." />
      <Banner tone="info" title="Why one case at a time, and what 'verified' means here">
        The API exposes the audit log per case (and per action); there is no endpoint that lists events across all cases, so this page does not pretend to show a global feed.
        Hashes are shown as recorded. Only the server can verify the whole chain: see <Link to="/system">System status</Link> for its own result. This page never marks a chain as verified by itself.
      </Banner>
      <CasePicker caseId={caseId} onPick={(id) => setParams({ case: id || null }, { replace: false })} submitLabel="Show audit trail" />
      {UUID_RE.test(caseId) ? <CaseAudit key={caseId} caseId={caseId} /> : <Card><EmptyState icon={ScrollText} title="Choose a case">Pick a recent case or paste its id to see who did what and when.</EmptyState></Card>}
    </>
  );
}
