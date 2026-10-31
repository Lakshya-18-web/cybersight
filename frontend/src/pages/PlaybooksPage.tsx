import { useState } from 'react';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { PageHeader } from '../components/ui/PageHeader';
import { Tabs, panelId, tabId } from '../components/ui/Tabs';
import { RefreshCw } from '../components/icons';
import { usePermissions } from '../auth/AuthContext';
import { Approvals, History } from './InvestigationsPage';
import { useSearchParams } from '../lib/router';

const TABS = [{ id: 'approvals', label: 'Awaiting approval' }, { id: 'history', label: 'Decisions & simulated runs' }, { id: 'about', label: 'About playbooks' }] as const;

/** Response actions as the backend models them: the pipeline PROPOSES an action on a case, a person approves or rejects it on the case page, and an approved action can be recorded as a SIMULATED execution. There is no playbook library
 *  and nothing is ever executed against a real system; this page says so and lists the real proposals. */
export function PlaybooksPage() {
  const [params] = useSearchParams();
  const { decide } = usePermissions();
  const [tab, setTab] = useState<string>(TABS.some((t) => t.id === params.get('tab')) ? (params.get('tab') as string) : 'approvals');
  const [epoch, setEpoch] = useState(0);
  return (
    <>
      <PageHeader title="Playbooks" description="Proposed response actions, who must approve them, and what was decided. Execution is simulation only."
        actions={<Button icon={RefreshCw} onClick={() => setEpoch((n) => n + 1)}>Refresh</Button>} />
      <Banner tone="info" title="Nothing here can change a real system">Approving records a person's decision; “Simulated” means an audit record was written. No firewall, host or account is touched, and no button on this site contains, isolates, blocks or deletes anything.
        {decide ? ' You can decide proposals from the case page, with a reason that is written to the audit log.' : ' Your role can read these but not decide them.'}</Banner>
      <Tabs tabs={TABS} value={tab} onChange={setTab} prefix="pb" label="Playbook sections" />
      <div role="tabpanel" id={panelId('pb', tab)} aria-labelledby={tabId('pb', tab)}>
        {tab === 'approvals' ? <Approvals key={epoch} /> : null}
        {tab === 'history' ? <History key={`h${epoch}`} /> : null}
        {tab === 'about' ? (
          <Card>
            <CardHeader title="How response actions work here" />
            <CardBody>
              <ul className="bullets">
                <li><strong>Available playbooks:</strong> none are defined. The backend has no playbook catalogue; each action is proposed for one case by the pipeline (for example, block an address or isolate a host) with a rationale.</li>
                <li><strong>Eligibility:</strong> decided by the deterministic policy. An action needing approval stays pending until a person with the decide permission approves or rejects it; a language model can never approve or execute anything.</li>
                <li><strong>Execution:</strong> an approved action can be recorded as a simulated execution (an audit entry). Real execution is not implemented.</li>
                <li><strong>Audit:</strong> every decision and simulated run is an event in the case's audit trail (Audit Log page).</li>
              </ul>
            </CardBody>
          </Card>
        ) : null}
      </div>
    </>
  );
}
