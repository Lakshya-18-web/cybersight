import type { JobView } from '../../api/types';
import { JobStatusBadge } from '../../components/ui/Badge';
import { Card, CardHeader } from '../../components/ui/Card';
import { EmptyState } from '../../components/ui/State';
import { Time } from '../../components/ui/Time';
import { formatDuration, secondsBetween, shortId } from '../../lib/format';
import { Link } from '../../lib/router';

/** The newest jobs from GET /jobs: what a worker did with each submitted alert. Nothing here is generated. */
export function RecentActivity({ jobs }: { jobs: readonly JobView[] | undefined }) {
  return (
    <Card>
      <CardHeader title="Recent activity" description="The six newest jobs: alert intake and what the workers did with it." actions={<Link to="/jobs">All jobs</Link>} />
      {jobs === undefined ? <p className="card-body muted">Unavailable: the job list could not be loaded.</p>
        : jobs.length === 0 ? <EmptyState title="No jobs yet">Submit an alert or send sensor events to start one.</EmptyState>
        : (
          <ul role="list" className="feed">
            {jobs.slice(0, 6).map((j) => {
              const dur = secondsBetween(j.started_at, j.finished_at);
              return (
                <li key={j.job_id}>
                  <JobStatusBadge status={j.status} />
                  <span><Link className="row-link mono-id" to={`/jobs/${j.job_id}`}>{shortId(j.job_id)}</Link> <span className="muted">· alert <span className="mono-id">{j.alert_id}</span>{dur !== null ? ` · ${formatDuration(dur)}` : ''}</span></span>
                  <Time value={j.finished_at ?? j.started_at ?? j.enqueued_at} />
                </li>
              );
            })}
          </ul>
        )}
    </Card>
  );
}
