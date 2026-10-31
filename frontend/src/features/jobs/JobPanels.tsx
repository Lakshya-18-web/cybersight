import { formatDateTime, formatDuration, humanize, secondsBetween } from '../../lib/format';
import { Banner } from '../../components/ui/Banner';
import { Card, CardBody, CardHeader } from '../../components/ui/Card';
import { KeyValue } from '../../components/ui/KeyValue';
import { Link } from '../../lib/router';
import { JobStatusBadge, Badge } from '../../components/ui/Badge';
import type { JobView } from '../../api/types';
import { jobTone } from '../../lib/severity';

/** What happened to a job, step by step, using only the timestamps the API returned. */
export function JobTimeline({ job }: { job: JobView }) {
  const steps: { label: string; at: string | null; tone: 'neutral' | 'accent' | 'success' | 'critical' | 'warning' }[] = [
    { label: 'Queued', at: job.enqueued_at, tone: 'neutral' },
    { label: job.attempts > 1 ? `Started (attempt ${job.attempts} of ${job.max_attempts})` : 'Started', at: job.started_at, tone: 'accent' },
  ];
  if (job.finished_at || ['succeeded', 'failed', 'timed_out'].includes(job.status)) {
    steps.push({ label: humanize(job.status), at: job.finished_at, tone: job.status === 'succeeded' ? 'success' : jobTone(job.status) === 'critical' ? 'critical' : 'warning' });
  }
  return (
    <ol className="timeline" aria-label="Job progress">
      {steps.map((s) => (
        <li key={s.label} data-tone={s.at ? s.tone : undefined}>
          <div className="timeline-head"><strong>{s.label}</strong><span className="timeline-time">{s.at ? formatDateTime(s.at) : 'not yet'}</span></div>
        </li>
      ))}
    </ol>
  );
}

export function JobSummary({ job }: { job: JobView }) {
  const result = job.result;
  const total = secondsBetween(job.enqueued_at, job.finished_at);
  return (
    <div className="stack">
      <Card>
        <CardHeader title="Status" actions={<JobStatusBadge status={job.status} />} />
        <CardBody>
          <div className="grid grid-2">
            <JobTimeline job={job} />
            <KeyValue items={[
              ['Job', <span className="mono-id" key="j">{job.job_id}</span>],
              ['Alert ID', job.alert_id],
              ['Alert set', job.alert_set],
              ['Memory', humanize(job.memory_mode)],
              ['Submitted by', job.submitted_by],
              ['Attempts', `${job.attempts} of ${job.max_attempts}`],
              ['Started', job.started_at ? formatDateTime(job.started_at) : 'not yet'],
              ['Completed', job.finished_at ? formatDateTime(job.finished_at) : 'not yet'],
              ['Time in system', total === null ? null : formatDuration(total)],
              ['Case', job.case_id ? <Link key="c" to={`/cases/${job.case_id}`}>Open the case</Link> : null],
            ]} />
          </div>
        </CardBody>
      </Card>

      {job.status === 'failed' || job.status === 'timed_out' ? (
        <Banner tone="critical" title={job.status === 'timed_out' ? 'The job ran out of time' : 'The job failed'}>
          <p>{job.error_code ? <>Reason code: <code>{job.error_code}</code>. </> : null}{job.error_detail ?? ''}</p>
        </Banner>
      ) : null}

      {result ? (
        <Card>
          <CardHeader title="Result" description="What the worker reported when it finished." />
          <CardBody>
            <KeyValue items={[
              ['Graph status', humanize(result.graph_status)],
              ['Verdict status', humanize(result.verdict_status)],
              ['Routing decision', humanize(result.routing_decision)],
              ['Risk level', humanize(result.risk_level)],
              ['Proposed actions', result.proposed_actions === undefined ? null : String(result.proposed_actions)],
              ['Ingest', humanize(result.ingest)],
              ['Model', result.fake_model === undefined ? null : result.fake_model ? <Badge tone="warning" key="m">Offline fake model</Badge> : 'Live model'],
              ['Guard signals', Array.isArray(result.guard_signals) ? (result.guard_signals.length === 0 ? 'None raised' : `${result.guard_signals.length} raised`) : null],
            ]} />
          </CardBody>
        </Card>
      ) : null}

      {job.timings || job.usage ? (
        <div className="grid grid-2">
          {job.timings ? (
            <Card>
              <CardHeader title="Timing" />
              <CardBody>
                <KeyValue items={[
                  ['Wall time', formatDuration(job.timings.wall_seconds)],
                  ['Graph', formatDuration(job.timings.graph_seconds)],
                  ['Model', formatDuration(job.timings.model_seconds)],
                ]} />
                {job.timings.nodes && Object.keys(job.timings.nodes).length ? (
                  <div className="table-wrap">
                    <table className="table" data-density="compact">
                      <thead><tr><th scope="col">Step</th><th scope="col" className="num">Calls</th><th scope="col" className="num">Time</th></tr></thead>
                      <tbody>
                        {Object.entries(job.timings.nodes).map(([name, n]) => (
                          <tr key={name}><td>{humanize(name)}</td><td className="num">{n.calls}</td><td className="num">{formatDuration(n.seconds)}</td></tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </CardBody>
            </Card>
          ) : null}
          {job.usage ? (
            <Card>
              <CardHeader title="Model usage" />
              <CardBody>
                <KeyValue items={[
                  ['Model calls', job.usage.model_calls === undefined ? null : String(job.usage.model_calls)],
                  ['Prompt tokens', job.usage.prompt_tokens === null ? 'not reported' : String(job.usage.prompt_tokens)],
                  ['Output tokens', job.usage.output_tokens === null ? 'not reported' : String(job.usage.output_tokens)],
                  ['Thinking tokens', job.usage.thinking_tokens === null ? 'not reported' : String(job.usage.thinking_tokens)],
                  ['Total tokens', job.usage.total_tokens === null ? 'not reported' : String(job.usage.total_tokens)],
                ]} />
                {job.usage.tokens_note ? <p className="muted">{job.usage.tokens_note}</p> : null}
              </CardBody>
            </Card>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
