import { ArrowLeft, RefreshCw } from '../components/icons';
import { Banner, ErrorBanner } from '../components/ui/Banner';
import { JobStatusBadge } from '../components/ui/Badge';
import { Button } from '../components/ui/Button';
import { CopyButton } from '../components/ui/CopyButton';
import { Icon } from '../components/ui/Icon';
import { PageHeader } from '../components/ui/PageHeader';
import { ErrorState, LoadingRows } from '../components/ui/State';
import { JobSummary } from '../features/jobs/JobPanels';
import { useJob } from '../features/jobs/useJob';
import { Link, useParams } from '../lib/router';

export function JobDetailPage() {
  const { id = '' } = useParams();
  const job = useJob(id);
  return (
    <>
      <PageHeader crumbs={[{ label: 'Jobs', to: '/jobs' }, { label: job.data ? job.data.job_id.slice(0, 8) : 'Job' }]} title={job.data ? `Job ${job.data.job_id.slice(0, 8)}` : 'Job'}
        description={job.data ? <span className="row"><JobStatusBadge status={job.data.status} /><CopyButton value={job.data.job_id} label="job id" /></span> : undefined}
        actions={<>
          <Link to="/jobs" className="btn" data-variant="ghost"><Icon icon={ArrowLeft} size={16} />Jobs</Link>
          <Button icon={RefreshCw} onClick={job.refresh}>Refresh</Button>
          {job.data?.case_id ? <Link to={`/cases/${job.data.case_id}`} className="btn" data-variant="primary">Open the case</Link> : null}
        </>} />
      {!job.data && job.error ? <ErrorState error={job.error} onRetry={job.refresh} /> : !job.data ? <LoadingRows label="Loading job" /> : (
        <>
          {job.error ? <ErrorBanner error={job.error} onRetry={job.refresh} /> : null}
          <p className="muted" role="status" aria-live="polite">
            {job.polling ? 'Checking for updates every few seconds. This stops when the job finishes.'
              : job.stopReason === 'done' ? 'The job has finished; no further updates are expected.'
              : job.stopReason === 'timeout' ? 'Stopped checking after 10 minutes. Refresh to check again.'
              : job.stopReason === 'errors' ? 'Stopped checking after repeated errors. Refresh to try again.' : ''}
          </p>
          {job.data.status === 'queued' && job.stopReason === 'timeout' ? <Banner tone="warning" title="Still queued">No worker has picked this job up. Check the worker and sweeper services.</Banner> : null}
          <JobSummary job={job.data} />
        </>
      )}
    </>
  );
}
