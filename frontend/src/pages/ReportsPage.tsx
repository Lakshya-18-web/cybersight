import { useState } from 'react';
import { api } from '../api';
import { Download, FileText } from '../components/icons';
import { Banner } from '../components/ui/Banner';
import { Button } from '../components/ui/Button';
import { Card, CardBody, CardHeader } from '../components/ui/Card';
import { PageHeader } from '../components/ui/PageHeader';
import { toApiError } from '../api/errors';
import { toCsv, downloadText } from '../lib/csv';
import { Link } from '../lib/router';

const SAMPLE = 100;
const COLUMNS = [
  { key: 'alert_id', label: 'Alert ID' }, { key: 'case_id', label: 'Case ID' }, { key: 'created_at', label: 'Created' }, { key: 'attack_type', label: 'Attack type' }, { key: 'src_ip', label: 'Source IP' },
  { key: 'dst_ip', label: 'Destination IP' }, { key: 'severity', label: 'Severity' }, { key: 'risk_level', label: 'Risk' }, { key: 'routing_decision', label: 'Routing' }, { key: 'status', label: 'Case status' }, { key: 'verdict_status', label: 'Verdict status' },
] as const;

type State = { kind: 'idle' } | { kind: 'busy' } | { kind: 'done'; text: string } | { kind: 'error'; text: string };

/** Exports built in the browser from data the API returned; nothing is generated server-side and nothing is uploaded. The files say how many rows they hold and how many exist. */
export function ReportsPage() {
  const [alerts, setAlerts] = useState<State>({ kind: 'idle' });
  const [summary, setSummary] = useState<State>({ kind: 'idle' });
  const stamp = () => new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);

  const exportAlerts = async () => {
    setAlerts({ kind: 'busy' });
    try {
      const page = await api.searchCases({ limit: SAMPLE });
      downloadText(`cybersight-alerts-${stamp()}.csv`, toCsv(COLUMNS, page.items as unknown as Record<string, unknown>[]), 'text/csv');
      setAlerts({ kind: 'done', text: `Saved ${page.items.length} of ${page.total} alerts (the newest ${SAMPLE} at most).` });
    } catch (e) { setAlerts({ kind: 'error', text: toApiError(e).message }); }
  };
  const exportSummary = async () => {
    setSummary({ kind: 'busy' });
    try {
      const [overview, jobs] = await Promise.all([api.overview(), api.listJobs({ limit: SAMPLE })]);
      const doc = { generated_at: new Date().toISOString(), source: 'CyberSight console, from GET /overview and GET /jobs', overview, jobs_sample: { returned: jobs.items.length, total: jobs.total } };
      downloadText(`cybersight-summary-${stamp()}.json`, JSON.stringify(doc, null, 2), 'application/json');
      setSummary({ kind: 'done', text: 'Saved the API’s own summary counts as they were a moment ago.' });
    } catch (e) { setSummary({ kind: 'error', text: toApiError(e).message }); }
  };
  const note = (s: State) => s.kind === 'done' ? <p role="status" className="muted">{s.text}</p> : s.kind === 'error' ? <Banner tone="critical" title="The export failed">{s.text}</Banner> : null;

  return (
    <>
      <PageHeader title="Reports" description="Exports of what the API holds, and the evaluation reports its commands wrote. Nothing is generated that the data does not support." />
      <div className="grid grid-2">
        <Card>
          <CardHeader title="Alert summary (CSV)" description="The newest alerts with severity, risk, routing and status. Cells that could run as spreadsheet formulas are neutralised." />
          <CardBody><div className="stack-sm"><div><Button icon={Download} variant="primary" onClick={exportAlerts} loading={alerts.kind === 'busy'}>Download CSV</Button></div>{note(alerts)}</div></CardBody>
        </Card>
        <Card>
          <CardHeader title="Case and processing summary (JSON)" description="The exact counts behind the dashboard: cases by status, severity, risk and routing, plus job counts." />
          <CardBody><div className="stack-sm"><div><Button icon={Download} variant="primary" onClick={exportSummary} loading={summary.kind === 'busy'}>Download JSON</Button></div>{note(summary)}</div></CardBody>
        </Card>
      </div>
      <Card>
        <CardHeader title="Evaluation reports" description="Written by the evaluation commands, read from the server's report folder." actions={<Link to="/evaluation">Open evaluation reports</Link>} />
        <CardBody><p className="muted">Detection quality, injection results and safety invariants are documented there, with the limits of each report. <FileText size={14} aria-hidden="true" className="inline-icon" /></p></CardBody>
      </Card>
      <Banner tone="info" title="Not available">Risk-distribution and investigation-history reports are on the Analytics and Audit Log pages. A combined PDF report, scheduled reports and a cross-case investigation history are not supported by the API, so no button pretends to make them.</Banner>
    </>
  );
}
