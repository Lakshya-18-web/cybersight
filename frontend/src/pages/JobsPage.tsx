import { api } from '../api';
import { JOB_STATUSES, TERMINAL_JOB_STATUSES } from '../api/types';
import { JobStatusBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { Card, CardBody } from '../components/ui/Card';
import { SelectField } from '../components/ui/Field';
import { PageHeader } from '../components/ui/PageHeader';
import { Pagination } from '../components/ui/Pagination';
import { ErrorBanner } from '../components/ui/Banner';
import { EmptyState, ErrorState, LoadingRows } from '../components/ui/State';
import { Time } from '../components/ui/Time';
import { Cpu, RefreshCw } from '../components/icons';
import { config } from '../config';
import { usePolling } from '../hooks/usePolling';
import { formatDuration, humanize, secondsBetween } from '../lib/format';
import { Link, useSearchParams } from '../lib/router';

const SIZES = [25, 50, 100] as const;
const intOr = (v: string | null, d: number, min: number) => { const n = Number(v); return Number.isInteger(n) && n >= min ? n : d; };

export function JobsPage() {
  const [params, setParams] = useSearchParams();
  const status = (JOB_STATUSES as readonly string[]).includes(params.get('status') ?? '') ? (params.get('status') as string) : '';
  const limit = (SIZES as readonly number[]).includes(intOr(params.get('limit'), 25, 1)) ? intOr(params.get('limit'), 25, 1) : 25;
  const offset = intOr(params.get('offset'), 0, 0);

  // The list refreshes by itself only while something on this page is still queued or running; once everything is finished the polling stops.
  const res = usePolling(
    {
      fetch: (signal) => api.listJobs({ status, limit, offset }, { signal }),
      isDone: (page) => page.items.every((j) => TERMINAL_JOB_STATUSES.includes(j.status)),
      intervalMs: Math.max(config.jobPollMs, 3000),
    },
    [status, limit, offset],
  );
  const page = res.data;

  return (
    <>
      <PageHeader title="Jobs" description="Alert submissions and what the workers did with them, newest first."
        actions={<Button icon={RefreshCw} onClick={res.refresh}>Refresh</Button>} />
      <Card>
        <CardBody>
          <form className="filters" role="search" aria-label="Filter jobs" onSubmit={(e) => e.preventDefault()}>
            <SelectField label="Status" value={status} onChange={(e) => setParams({ status: e.target.value, offset: null })}>
              <option value="">All statuses</option>
              {JOB_STATUSES.map((s) => <option key={s} value={s}>{humanize(s)}</option>)}
            </SelectField>
            <SelectField label="Rows per page" value={String(limit)} onChange={(e) => setParams({ limit: e.target.value, offset: null })}>
              {SIZES.map((n) => <option key={n} value={n}>{n}</option>)}
            </SelectField>
            {status ? <Button variant="ghost" onClick={() => setParams({ status: null, offset: null })}>Clear filter</Button> : null}
          </form>
          <p className="field-hint" role="status">{res.polling ? 'Updating automatically while jobs on this page are in progress.' : page ? 'Everything on this page has finished. Refresh to look again.' : ''}</p>
        </CardBody>
      </Card>
      <Card>
        {!page && res.error ? <ErrorState error={res.error} onRetry={res.refresh} />
          : !page ? <LoadingRows label="Loading jobs" />
          : (
            <>
              {res.error ? <div className="card-body"><ErrorBanner error={res.error} onRetry={res.refresh} /></div> : null}
              {page.total === 0 ? <EmptyState icon={Cpu} title={status ? 'No jobs with this status' : 'No jobs yet'}>{status ? 'Clear the filter to see all jobs.' : 'Submitted alerts show up here.'}</EmptyState> : (
                <div className="table-wrap">
                  <table className="table" data-stack="true">
                    <caption className="visually-hidden">Jobs</caption>
                    <thead><tr><th scope="col">Job</th><th scope="col">Status</th><th scope="col">Alert</th><th scope="col">Submitted by</th><th scope="col" className="num">Attempts</th><th scope="col">Duration</th><th scope="col">Enqueued</th><th scope="col">Case</th></tr></thead>
                    <tbody>
                      {page.items.map((j) => (
                        <tr key={j.job_id}>
                          <td data-label="Job"><Link className="row-link mono-id" to={`/jobs/${j.job_id}`}>{j.job_id.slice(0, 8)}</Link></td>
                          <td data-label="Status"><JobStatusBadge status={j.status} /></td>
                          <td data-label="Alert" className="mono-id">{j.alert_id}</td>
                          <td data-label="Submitted by">{j.submitted_by}</td>
                          <td data-label="Attempts" className="num">{j.attempts}/{j.max_attempts}</td>
                          <td data-label="Duration">{formatDuration(secondsBetween(j.started_at, j.finished_at))}</td>
                          <td data-label="Enqueued"><Time value={j.enqueued_at} /></td>
                          <td data-label="Case">{j.case_id ? <Link to={`/cases/${j.case_id}`}>Open</Link> : <span className="muted">—</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              <Pagination total={page.total} limit={page.limit} offset={page.offset} count={page.items.length} onOffset={(o) => setParams({ offset: o === 0 ? null : String(o) }, { replace: false })} />
            </>
          )}
      </Card>
    </>
  );
}
